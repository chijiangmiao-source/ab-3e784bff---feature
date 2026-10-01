import json
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.server import Handler


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path):
        return urllib.request.urlopen(self.base + path, timeout=5)

    def post(self, path, payload):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_health(self):
        with self.get("/health") as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read().decode("utf-8")), {"status": "ok"})

    def test_page_served(self):
        with self.get("/") as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("姿态保护控制器", body)
            self.assertIn("/api/audit", body)

    def test_audit_roundtrip(self):
        status, data = self.post(
            "/api/audit",
            {
                "variables": ["safe"],
                "rules": [
                    {"id": "R1", "action": "hold", "condition": "safe"},
                    {"id": "R2", "action": "alarm", "condition": "!safe"},
                ],
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["verdict"], "PASS")

    def test_audit_validation_failure_is_422(self):
        status, data = self.post(
            "/api/audit",
            {"variables": ["a"], "rules": [{"id": "R1", "action": "x", "condition": "b"}]},
        )
        self.assertEqual(status, 422)
        self.assertFalse(data["ok"])
        self.assertEqual(data["errors"][0]["kind"], "unknown_variable")

    def test_bad_json_is_400(self):
        req = urllib.request.Request(
            self.base + "/api/audit", data=b"{not json", method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)

    def test_unknown_path_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get("/nope")
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
