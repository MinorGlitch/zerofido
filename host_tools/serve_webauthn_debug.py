from __future__ import annotations

import http.server
import json
import pathlib
import socketserver
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from host_tools.conformance_suite import ConformanceSuiteService
HOST = "localhost"
PORT = 8765
SERVICE = ConformanceSuiteService(host=HOST, port=PORT)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ZeroFidoSuite/1.0"

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        data = self.rfile.read(length)
        if not data:
            return {}
        return json.loads(data.decode("utf-8"))

    def _serve_file(self, path: pathlib.Path, content_type: str) -> None:
        if not path.exists():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/", "/webauthn_debug.html"}:
            self._serve_file(ROOT / "webauthn_debug.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/api/status":
            self._send_json(200, SERVICE.get_status())
            return
        if parsed.path == "/api/report/latest":
            report = SERVICE.get_latest_report()
            if report is None:
                self._send_json(404, {"error": "no report available"})
                return
            self._send_json(200, report)
            return
        if parsed.path == "/api/events":
            subscriber = SERVICE.subscribe()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                self.wfile.write(b"retry: 1000\n\n")
                self.wfile.flush()
                while True:
                    event = subscriber.get()
                    body = json.dumps(event["data"])
                    frame = f"event: {event['event']}\ndata: {body}\n\n".encode("utf-8")
                    self.wfile.write(frame)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                SERVICE.unsubscribe(subscriber)
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/run":
            trigger = self._read_json_body().get("trigger", "manual")
            self._send_json(200, SERVICE.start_run(trigger))
            return
        if parsed.path.startswith("/api/manual-checkpoint/"):
            checkpoint_id = parsed.path.rsplit("/", 1)[-1]
            self._send_json(200, SERVICE.resume_manual_checkpoint(checkpoint_id))
            return
        if parsed.path.startswith("/api/browser-scenario/"):
            scenario_id = parsed.path.rsplit("/", 1)[-1]
            payload = self._read_json_body()
            self._send_json(200, SERVICE.run_browser_scenario_api(scenario_id, payload))
            return
        self.send_error(404)


def main() -> None:
    SERVICE.start()
    try:
        with ThreadingHTTPServer((HOST, PORT), Handler) as httpd:
            print(f"serving http://{HOST}:{PORT}/webauthn_debug.html")
            httpd.serve_forever()
    finally:
        SERVICE.stop()


if __name__ == "__main__":
    main()
