import hashlib
import http.client
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProtocolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        env = os.environ.copy()
        env.update(LOCALSEND_DIR=cls.tmp.name, LOCALSEND_PORT=str(cls.port))
        cls.process = subprocess.Popen(
            [str(ROOT / "ps5-localsend.elf")], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        for _ in range(100):
            try:
                status, _ = cls.request("GET", "/api/localsend/v2/info")
                if status == 200:
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError(f"server did not start: {cls.process.stderr.read()!r}")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.process.stderr.close()
        cls.tmp.cleanup()

    @classmethod
    def request(cls, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=20)
        conn.request(method, path, body=body)
        response = conn.getresponse()
        result = response.status, response.read()
        conn.close()
        return result

    def prepare(self, name, content, sha=None):
        request = {
            "info": {"alias": "Test", "version": "2.0", "fingerprint": "other", "port": 53317, "protocol": "http"},
            "files": {"id 1": {"id": "id 1", "fileName": name, "size": len(content), "fileType": "application/octet-stream", "sha256": sha}},
        }
        status, body = self.request("POST", "/api/localsend/v2/prepare-upload", json.dumps(request).encode())
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        return f"/api/localsend/v2/upload?sessionId={data['sessionId']}&fileId=id%201&token={data['files']['id 1']}"

    def test_info_and_register(self):
        for method, path in [("GET", "/api/localsend/v2/info"), ("POST", "/api/localsend/v2/register")]:
            status, body = self.request(method, path)
            self.assertEqual(status, 200)
            info = json.loads(body)
            self.assertEqual(info["protocol"], "http")
            self.assertEqual(info["deviceModel"], "PlayStation 5")

    def test_upload_unicode_name_and_hash(self):
        content = b"ps5-localsend integration test\x00" * 1000
        path = self.prepare("../caf\u00e9.bin", content, hashlib.sha256(content).hexdigest())
        status, _ = self.request("POST", path, content)
        self.assertEqual(status, 200)
        found = list(pathlib.Path(self.tmp.name).glob("*-caf\u00e9.bin"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].read_bytes(), content)

    def test_hash_mismatch_rejected(self):
        path = self.prepare("mismatch.bin", b"bad", "0" * 64)
        status, _ = self.request("POST", path, b"bad")
        self.assertEqual(status, 422)
        self.assertFalse(list(pathlib.Path(self.tmp.name).glob("*-mismatch.bin")))
        sid = path.split("sessionId=")[1].split("&")[0]
        self.request("POST", f"/api/localsend/v2/cancel?sessionId={sid}")

    def test_wrong_token_rejected(self):
        path = self.prepare("secret.bin", b"abc")
        status, _ = self.request("POST", path.split("&token=")[0] + "&token=wrong", b"abc")
        self.assertEqual(status, 403)
        sid = path.split("sessionId=")[1].split("&")[0]
        self.request("POST", f"/api/localsend/v2/cancel?sessionId={sid}")


if __name__ == "__main__":
    unittest.main()
