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
import urllib.parse


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProtocolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        env = os.environ.copy()
        env.update(LOCALSEND_DIR=cls.tmp.name, LOCALSEND_PORT=str(cls.port), LOCALSEND_PIN="123456")
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

    def test_command_line_send_to_peer(self):
        source = pathlib.Path(self.tmp.name) / "outgoing.txt"
        source.write_bytes(b"from PS5 to peer" * 100)
        result = subprocess.run(
            [str(ROOT / "ps5-localsend.elf"), "--send", str(source), "127.0.0.1", str(self.port)],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        found = list(pathlib.Path(self.tmp.name).glob("*-outgoing.txt"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].read_bytes(), source.read_bytes())

    def test_browser_send_to_peer(self):
        source = pathlib.Path(self.tmp.name) / "browser-source.txt"
        source.write_bytes(b"browser controlled send" * 100)
        status, body = self.request("POST", "/api/localsend/v2/prepare-download?pin=123456")
        self.assertEqual(status, 200)
        listing = json.loads(body)
        file_id = next(key for key, value in listing["files"].items() if value["fileName"] == source.name)
        with tempfile.TemporaryDirectory() as destination:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                remote_port = sock.getsockname()[1]
            env = os.environ.copy()
            env.update(LOCALSEND_DIR=destination, LOCALSEND_PORT=str(remote_port), LOCALSEND_PIN="654321")
            receiver = subprocess.Popen(
                [str(ROOT / "ps5-localsend.elf")], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            try:
                for _ in range(100):
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", remote_port, timeout=1)
                        conn.request("GET", "/api/localsend/v2/info")
                        conn.getresponse().read()
                        conn.close()
                        break
                    except OSError:
                        time.sleep(0.05)
                else:
                    self.fail("second receiver did not start")
                form = urllib.parse.urlencode({"peer": "127.0.0.1", "port": remote_port}).encode()
                status, _ = self.request(
                    "POST", f"/send?sessionId={listing['sessionId']}&fileId={file_id}", form
                )
                self.assertEqual(status, 200)
                found = list(pathlib.Path(destination).glob("*-browser-source.txt"))
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].read_bytes(), source.read_bytes())
            finally:
                receiver.terminate()
                receiver.wait(timeout=5)
                receiver.stderr.close()

    def test_pin_protected_download(self):
        status, _ = self.request("POST", "/api/localsend/v2/prepare-download?pin=000000")
        self.assertEqual(status, 401)
        status, body = self.request("POST", "/api/localsend/v2/prepare-download?pin=123456")
        self.assertEqual(status, 200)
        listing = json.loads(body)
        self.assertTrue(listing["info"]["download"])
        self.assertTrue(listing["files"])
        file_id, metadata = next(iter(listing["files"].items()))
        status, payload = self.request(
            "GET", f"/api/localsend/v2/download?sessionId={listing['sessionId']}&fileId={file_id}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(payload), metadata["size"])
        self.assertEqual(payload, (pathlib.Path(self.tmp.name) / metadata["fileName"]).read_bytes())
        status, page = self.request("GET", "/?pin=123456")
        self.assertEqual(status, 200)
        self.assertIn(b"Files available for download", page)

    def test_wrong_token_rejected(self):
        path = self.prepare("secret.bin", b"abc")
        status, _ = self.request("POST", path.split("&token=")[0] + "&token=wrong", b"abc")
        self.assertEqual(status, 403)
        sid = path.split("sessionId=")[1].split("&")[0]
        self.request("POST", f"/api/localsend/v2/cancel?sessionId={sid}")


if __name__ == "__main__":
    unittest.main()
