# DataGuard Intelligent Assistant

The initial assistant implementation follows **Mode A: local rule-based prototype** from the module specification. It runs offline and uses only the Python standard library. It does not require an API key or network access. A provider-backed LLM adapter can be added later, behind the same response contract, after this deterministic path is validated.

## Integration

- The Qt Assistant page starts app/main.py as a short-lived Python subprocess.
- Request/response traffic is one JSON object over stdin/stdout.
- The C++ UI passes the current screen, selected removable-device metadata, current scan summary, selected-file summary, most recent operation record, and selected certificate metadata when available.
- Raw file contents, credentials, authentication tokens, physical device paths, and serial numbers are not included in assistant context.
- The service is guidance-only. Its response schema only includes text, caveats, and navigation destination IDs. The Qt UI has an independent navigation allowlist and does not route assistant output to wipe or recovery functions.
- Each request has an eight-second process timeout. Missing Python, a missing script, timeout, or invalid JSON produces a built-in safe fallback. Storage operations do not depend on the assistant process.
- Conversation messages are held only in the visible UI session. The assistant does not persist them.

## Run the service manually

From the repository root, run:

    python assistant/app/main.py

Send one JSON object on stdin, for example:

    {"request_id":"manual-1","question":"What does this scan mean?","context":{"screen":"scan_results","scan_summary":{"existing_entries":4,"potentially_deleted_entries":2,"scan_status":"completed"}}}

The service emits a single JSON response on stdout.

## Test

From the repository root:

    python -m unittest discover -s assistant/tests -v

The tests use fixture data and do not need a physical storage device.

## Limits

This initial version is deterministic and does not call an LLM. It can only explain fields the Qt application supplies or approved local knowledge. Missing values remain unknown. ML outputs are repeated from the application record; the assistant never calculates missing scores or treats an estimate as proof of recoverability/irrecoverability. Navigation suggestions cannot initiate operations.
