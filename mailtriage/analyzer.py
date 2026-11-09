"""Offline, explainable signals for RFC 5322 email messages."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import PurePath
from typing import Any
from urllib.parse import urlsplit

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
RISKY_EXTENSIONS = {
    ".apk", ".bat", ".cmd", ".com", ".dll", ".exe", ".hta", ".htm", ".html", ".iso", ".jar", ".js", ".jse", ".lnk",
    ".msi", ".ps1", ".py", ".reg", ".scr", ".sh", ".url", ".vbe", ".vbs", ".wsf", ".wsh", ".xll",
    ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm",
}
URGENT_TERMS = ("urgent", "action required", "verify your account", "password expires",
                "account suspended", "immediate action", "payment overdue")

RULES = {
    "MAIL-001": ("high", "Sender and reply address use different domains"),
    "MAIL-002": ("medium", "Email authentication reports a failure"),
    "MAIL-003": ("medium", "Message contains a link with a risky URL pattern"),
    "MAIL-004": ("high", "Message includes a potentially risky attachment type"),
    "MAIL-005": ("low", "Urgent language appears alongside a link"),
    "MAIL-006": ("medium", "Visible link text and destination host differ"),
}


class LinkParser(HTMLParser):
    """Collect HTML links and visible text without loading or executing anything."""
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._current: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = dict(attrs).get("href") or ""
            self._current = {"url": href.strip(), "text": ""}
            self.links.append(self._current)

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current["text"] += data

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a":
            self._current = None


def _addresses(value: str | None) -> list[str]:
    return [address.strip() for _, address in getaddresses([value or ""]) if address and "@" in address]


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(".")


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _url_host(raw_url: str) -> tuple[str | None, list[str]]:
    cleaned = raw_url.strip().rstrip(".,;:!?)]")
    try:
        parsed = urlsplit(cleaned)
        host = parsed.hostname
        if not host:
            return None, []
        host = host.lower().rstrip(".")
        reasons = []
        try:
            ipaddress.ip_address(host)
            reasons.append("URL uses a literal IP address")
        except ValueError:
            pass
        if "xn--" in host:
            reasons.append("URL contains an IDN punycode label")
        if parsed.username is not None or parsed.password is not None:
            reasons.append("URL contains user-info before the host")
        try:
            if parsed.port is not None and parsed.port not in {80, 443}:
                reasons.append(f"URL uses a non-standard port ({parsed.port})")
        except ValueError:
            reasons.append("URL has a malformed port")
        if parsed.scheme.lower() == "http":
            reasons.append("URL does not use HTTPS")
        return host, reasons
    except ValueError:
        return None, ["URL could not be parsed safely"]


def analyze_message(raw: bytes, *, include_sensitive: bool = False) -> dict[str, Any]:
    """Parse and triage one email. No URLs are opened and no attachment is extracted."""
    message = BytesParser(policy=policy.default).parsebytes(raw)
    sender_addresses = _addresses(str(message.get("From", "")))
    reply_addresses = _addresses(str(message.get("Reply-To", "")))
    sender_domain = _domain(sender_addresses[0]) if sender_addresses else None
    reply_domain = _domain(reply_addresses[0]) if reply_addresses else None

    text_bodies: list[str] = []
    html_links: list[dict[str, str]] = []
    attachments: list[dict[str, Any]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            suffixes = [suffix.lower() for suffix in PurePath(filename or "").suffixes]
            extension = suffixes[-1] if suffixes else ""
            attachments.append({
                "filename": filename or f"attachment-{len(attachments) + 1}",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "extension": extension,
                "risky_type": extension in RISKY_EXTENSIONS,
                "double_extension": len(suffixes) > 1 and suffixes[-1] in RISKY_EXTENSIONS,
            })
            continue
        content_type = part.get_content_type().lower()
        if content_type == "text/plain":
            text_bodies.append(_decode_part(part))
        elif content_type == "text/html":
            html = _decode_part(part)
            parser = LinkParser()
            try:
                parser.feed(html)
            except Exception:
                pass
            html_links.extend(parser.links)
            text_bodies.append(html)

    body = "\n".join(text_bodies)
    urls = set(match.group(0).rstrip(".,;:!?)]") for match in URL_PATTERN.finditer(body))
    for link in html_links:
        if link["url"].lower().startswith(("http://", "https://")):
            urls.add(link["url"].strip().rstrip(".,;:!?)]"))

    findings: list[dict[str, Any]] = []
    def add(rule_id: str, evidence: list[str], triage: list[str]) -> None:
        severity, title = RULES[rule_id]
        findings.append({"rule_id": rule_id, "severity": severity, "title": title,
                         "evidence": evidence, "recommended_triage": triage})

    if sender_domain and reply_domain and sender_domain != reply_domain:
        add("MAIL-001", [f"From domain: {sender_domain}", f"Reply-To domain: {reply_domain}"],
            ["Confirm the reply address against a trusted contact directory.",
             "Review the message's business context before replying or forwarding."])

    auth_headers = " ".join(str(value) for value in message.get_all("Authentication-Results", []))
    spf_headers = " ".join(str(value) for value in message.get_all("Received-SPF", []))
    failed_auth = [name for name in ("spf", "dkim", "dmarc")
                   if re.search(rf"\b{name}\s*=\s*(?:fail|softfail|permerror)\b", auth_headers.lower())]
    if re.search(r"^\s*(?:fail|softfail|permerror)\b", spf_headers, flags=re.IGNORECASE | re.MULTILINE) and "spf" not in failed_auth:
        failed_auth.insert(0, "spf")
    if failed_auth:
        add("MAIL-002", ["Reported failure: " + ", ".join(failed_auth)],
            ["Check results added by the trusted receiving mail gateway; sender-supplied headers may be forged.",
             "Correlate with gateway verdicts and the sender domain's authentication policy."])

    risky_urls: list[str] = []
    hosts: set[str] = set()
    for url in sorted(urls):
        host, reasons = _url_host(url)
        if host:
            hosts.add(host)
        if reasons:
            risky_urls.append(f"{host or 'unparsed URL'}: " + "; ".join(reasons))
    if risky_urls:
        add("MAIL-003", risky_urls[:12],
            ["Do not open the link from the message; inspect it only in an approved analysis environment.",
             "Compare the destination with the expected service domain and gateway reputation results."])

    risky_attachments = [item for item in attachments if item["risky_type"]]
    if risky_attachments:
        evidence = []
        for index, item in enumerate(risky_attachments, start=1):
            name = item["filename"] if include_sensitive else f"attachment-{index}"
            evidence.append(f"{name}: {item['extension']} ({item['size_bytes']} bytes, SHA-256 {item['sha256']})")
        add("MAIL-004", evidence,
            ["Do not open or execute the attachment.",
             "Submit the hash to approved internal tooling; follow organizational malware-handling procedures."])

    subject = str(message.get("Subject", ""))
    urgent_hits = [term for term in URGENT_TERMS if term in subject.lower()]
    if urgent_hits and urls:
        add("MAIL-005", ["Urgency terms in subject: " + ", ".join(urgent_hits),
                          f"Message contains {len(urls)} URL(s)."],
            ["Verify the request using a known-good contact path, not the message's links or reply address."])

    mismatches = []
    for link in html_links:
        visible_host, _ = _url_host(link["text"].strip()) if URL_PATTERN.fullmatch(link["text"].strip()) else (None, [])
        target_host, _ = _url_host(link["url"])
        if visible_host and target_host and visible_host != target_host:
            mismatches.append(f"Visible host {visible_host} points to {target_host}")
    if mismatches:
        add("MAIL-006", mismatches[:12],
            ["Treat the displayed text as untrusted; verify the actual destination without opening it."])

    report: dict[str, Any] = {
        "tool": "Offline Phishing Email Analyzer",
        "message": {"from_domain": sender_domain, "reply_to_domain": reply_domain,
                    "url_count": len(urls), "url_hosts": sorted(hosts),
                    "attachment_count": len(attachments),
                    "attachments": [{"name": item["filename"] if include_sensitive else f"attachment-{i + 1}",
                                     "content_type": item["content_type"], "size_bytes": item["size_bytes"],
                                     "sha256": item["sha256"], "risky_type": item["risky_type"],
                                     "double_extension": item["double_extension"]}
                                    for i, item in enumerate(attachments)]},
        "findings_count": len(findings), "findings": findings,
        "disclaimer": "Signals are triage leads, not proof of phishing. Validate with trusted mail-gateway and organizational context.",
    }
    if include_sensitive:
        report["message"].update({"from": sender_addresses, "reply_to": reply_addresses,
                                  "subject": subject, "urls": sorted(urls)})
    return report

