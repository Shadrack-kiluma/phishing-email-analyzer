# Safe handling and triage

## Before analysis

- Confirm you are authorized to handle the message.
- Work on an approved copy and retain the original according to evidence procedures.
- Use an isolated analyst environment where appropriate. This tool is read-only, but the message itself may contain sensitive data.

## Review findings

1. Record the message source, acquisition method, hash, and case reference in your approved system.
2. Check `From`, `Reply-To`, `Return-Path`, and relevant Received headers in context.
3. Trust SPF/DKIM/DMARC results only when added by a known receiving gateway; sender-supplied copies are forgeable.
4. Inspect URL destinations and attachment hashes only with approved internal tooling. Do not open message links or attachments as part of initial triage.
5. Correlate with mail-gateway verdicts, endpoint telemetry, identity logs, and user reports.
6. Escalate or contain through your organization's incident response process. This tool takes no response action.

## Protect report data

Reports can expose personal addresses, subjects, attachment names, link destinations, and file hashes. Keep them in approved case storage. The `--include-sensitive` flag intentionally adds raw addresses, subject text, URL strings, and attachment names; do not use it for public demos or public repositories.

## Training data

The included `.eml` files are synthetic. They use `example` domains and a documentation-only IP address. They contain no live links or executable payloads.
