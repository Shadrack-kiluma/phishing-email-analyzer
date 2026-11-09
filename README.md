# Offline Phishing Email Analyzer

A defensive, offline command-line tool for triaging local RFC 5322 `.eml` files. It inspects sender/reply domains, mail-authentication result headers, URL structure, and attachment metadata/hashes, then returns explainable findings with analyst next steps.

**Safe by default:** the analyzer never opens links, performs DNS or reputation lookups, extracts attachments to disk, or executes message content. Reports omit full addresses, subjects, URLs, and attachment names unless `--include-sensitive` is explicitly selected. Synthetic examples use reserved `.example` domains and documentation-only IP addresses.

## Quick start

Requires Python 3.10 or newer. No runtime dependencies.

```console
python -m mailtriage.cli examples/synthetic-suspicious.eml
```

Machine-readable report:

```console
python -m mailtriage.cli examples/synthetic-suspicious.eml --format json
```

Save a report locally:

```console
python -m mailtriage.cli examples/synthetic-suspicious.eml --format json --output report.json
```

Include sensitive message fields only when you need them for authorized local triage:

```console
python -m mailtriage.cli examples/synthetic-suspicious.eml --format json --include-sensitive
```

Install the command:

```console
python -m pip install -e .
mailtriage examples/synthetic-suspicious.eml
```

## Detection signals

| ID | Signal |
|---|---|
| `MAIL-001` | `From` and `Reply-To` use different domains. |
| `MAIL-002` | Authentication-Results or Received-SPF reports SPF, DKIM, or DMARC failure. |
| `MAIL-003` | URL uses a literal IP, HTTP, IDN punycode, user-info, or non-standard port. |
| `MAIL-004` | Attachment has a potentially risky executable, script, shortcut, or macro-enabled extension. |
| `MAIL-005` | Urgency language in the subject appears with a link. |
| `MAIL-006` | An HTML link's visible URL host differs from its destination host. |

Signals are explainable heuristics, not verdicts. A failed authentication header may be forged unless it was added by a trusted receiving gateway; a risky extension alone does not prove an attachment is malicious. See [`docs/rules.md`](docs/rules.md) and [`docs/safe-handling.md`](docs/safe-handling.md).

## Project structure

- `mailtriage/analyzer.py` — parsing, metadata extraction, SHA-256 hashes, rules, and triage guidance
- `mailtriage/cli.py` — local CLI, text/JSON output, privacy controls
- `examples/` — synthetic suspicious and benign `.eml` fixtures
- `docs/` — signal logic and safe handling guidance

## Responsible use

Analyze messages you are authorized to handle. Email can contain private, regulated, or credential-bearing information. Keep real messages and generated reports out of public repositories. Use the `--include-sensitive` option only when needed, and store resulting reports according to your organization's data-handling policy.

## License

MIT. See [`LICENSE`](LICENSE).

