# Detection rules and limits

The analyzer produces independent signals. It does not calculate a composite risk score; analysts should weigh evidence using trusted gateway telemetry and organizational context.

| ID | Logic | Common benign explanations |
|---|---|---|
| `MAIL-001` | First parsed From domain differs from first Reply-To domain. | Mailing lists, ticketing platforms, legitimate reply management. |
| `MAIL-002` | Authentication-Results includes `spf`, `dkim`, or `dmarc` failure/softfail/permerror; Received-SPF failure is also recognized. | Forwarding, DNS changes, third-party senders, misconfiguration. |
| `MAIL-003` | At least one HTTP(S) URL has an IP-literal host, an `xn--` label, embedded user-info, a non-standard port, or uses HTTP. | Internal lab links, test systems, legacy services. |
| `MAIL-004` | Attachment extension is in the explicit script/executable/shortcut/macro list. | Legitimate administrative or business files with risky formats. |
| `MAIL-005` | Subject contains a configured urgency phrase and the message contains a URL. | Real deadlines and legitimate account alerts. |
| `MAIL-006` | An HTML anchor's visible text is a URL whose host differs from the href host. | URL shorteners, tracking redirects, benign marketing links. |

## Parsing details

- URL hosts are extracted locally with Python's URL parser. No link is requested and no domain is resolved.
- Attachment payload bytes are read in memory only to calculate size and SHA-256. The analyzer does not extract files to disk.
- Full addresses, subject, URL strings, and attachment names are excluded by default. `--include-sensitive` adds them to the report.
- HTML is parsed only to inspect anchor text and href values. Scripts and remote content are never rendered.

## Limitations

- No external reputation, sandbox, DNS, WHOIS, or threat-intelligence lookups.
- Authentication headers are not cryptographically validated. Trust them only when the receiving gateway inserted them.
- Does not handle `.msg`, mailbox archives, password-protected archives, or provider-specific telemetry.
- Attachment suffix checks can be bypassed and can produce false positives; they are not malware detection.
- URL parsing is a triage aid and not a full browser-equivalence or homograph analysis.
- Input size is capped at 25 MiB by default to keep this starter predictable.
- Findings are not automatically sent to a SIEM or response system.
