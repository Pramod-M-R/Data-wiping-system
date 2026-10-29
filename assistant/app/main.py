"""JSON-over-stdin/stdout entry point for the local assistant subprocess."""
from __future__ import annotations

import json
import sys

try:
    from .controller import MAX_REQUEST_BYTES, RequestError, error_response, handle_request
except ImportError:  # direct script invocation
    from controller import MAX_REQUEST_BYTES, RequestError, error_response, handle_request


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        response = error_response("The request is too large. Please shorten the question.")
    else:
        try:
            request = json.loads(raw.decode("utf-8"))
            response = handle_request(request)
        except UnicodeDecodeError:
            response = error_response("The request was not valid UTF-8.")
        except json.JSONDecodeError:
            response = error_response("The assistant request was not valid JSON.")
        except RequestError as exc:
            response = error_response(str(exc))
        except Exception:
            # Never print a traceback or conversation content into the UI/protocol.
            response = error_response(
                "The local assistant encountered an internal error. Storage operations are unaffected."
            )

    sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
