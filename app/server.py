"""HTTP 服务：审计页面、健康路径与审计 API。

仅依赖 Python 标准库。路由：
  GET  /           审计操作页面
  GET  /health     健康路径
  POST /api/audit  规则审计（请求体 {"variables": [...], "rules": [...]}）
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import audit as audit_mod

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 1 << 20  # 1 MiB


class Handler(BaseHTTPRequestHandler):
    server_version = "PostureAudit/1.0"
    protocol_version = "HTTP/1.1"

    # -------------------------------------------------------------- 响应辅助
    def _send(self, body: bytes, status: int, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj, status: int = 200):
        self._send(
            json.dumps(obj, ensure_ascii=False).encode("utf-8"),
            status,
            "application/json; charset=utf-8",
        )

    def _not_found(self):
        self._send_json({"ok": False, "errors": [{"kind": "not_found", "message": "路径不存在"}]}, 404)

    # ------------------------------------------------------------------ 路由
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send_json({"status": "ok"})
        elif path == "/":
            body = (STATIC_DIR / "index.html").read_bytes()
            self._send(body, 200, "text/html; charset=utf-8")
        else:
            self._not_found()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/audit":
            self._not_found()
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._send_json(
                {"ok": False, "errors": [{"kind": "invalid_payload", "message": "请求体缺失或超过 1 MiB"}]},
                400,
            )
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(
                {"ok": False, "errors": [{"kind": "invalid_payload", "message": "请求体不是合法 JSON"}]},
                400,
            )
            return
        if not isinstance(payload, dict):
            self._send_json(
                {"ok": False, "errors": [{"kind": "invalid_payload", "message": "请求体须为 JSON 对象"}]},
                400,
            )
            return
        result = audit_mod.audit(
            payload.get("variables", []),
            payload.get("rules", []),
            payload.get("danger"),
            payload.get("levels"),
        )
        self._send_json(result, 200 if result.get("ok") else 422)

    def log_message(self, fmt, *args):  # 保持容器日志简洁
        pass


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"posture-audit listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
