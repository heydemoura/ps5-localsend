# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 heydemoura
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
    def request(cls, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=20)
        conn.request(method, path, body=body, headers=headers or {})
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
            self.assertEqual(info["alias"], socket.gethostname())

    def test_chunked_upload(self):
        content = b"official client chunked upload\x00" * 1500
        path = self.prepare("chunked.bin", content, hashlib.sha256(content).hexdigest())
        with socket.create_connection(("127.0.0.1", self.port), timeout=20) as sock:
            sock.sendall(
                f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n".encode()
            )
            for offset in range(0, len(content), 997):
                chunk = content[offset:offset + 997]
                sock.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            sock.sendall(b"0\r\n\r\n")
            response = sock.makefile("rb")
            self.assertIn(b" 200 ", response.readline())
        found = list(pathlib.Path(self.tmp.name).glob("*-chunked.bin"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].read_bytes(), content)

    def test_malformed_chunked_upload_rejected(self):
        path = self.prepare("malformed.bin", b"abc")
        with socket.create_connection(("127.0.0.1", self.port), timeout=20) as sock:
            sock.sendall(
                f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n".encode()
                + b"3\r\nabcXX0\r\n\r\n"
            )
            self.assertIn(b" 400 ", sock.makefile("rb").readline())
        self.assertFalse(list(pathlib.Path(self.tmp.name).glob("*-malformed.bin")))
        sid = path.split("sessionId=")[1].split("&")[0]
        self.request("POST", f"/api/localsend/v2/cancel?sessionId={sid}")

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
            env={**os.environ, "LOCALSEND_DIR": self.tmp.name, "LOCALSEND_PIN": "123456"},
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
                announcement = json.dumps({
                    "alias": "Peer B", "version": "2.0", "fingerprint": "peer-b",
                    "port": remote_port, "protocol": "http", "announce": False,
                }).encode()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(announcement, ("127.0.0.1", self.port))
                for _ in range(50):
                    _, page = self.request("POST", "/api/ui/list", b"pin=123456")
                    if b"Peer B" in page:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("discovered peer did not appear in browser")
                status, body = self.request("POST", "/api/localsend/v2/prepare-download?pin=123456")
                self.assertEqual(status, 200)
                listing = json.loads(body)
                file_id = next(key for key, value in listing["files"].items() if value["fileName"] == source.name)
                form = urllib.parse.urlencode({"target": "peer-b"}).encode()
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
        status, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Set a PIN to enable transfers", page)
        self.assertIn(b"GPL-3.0-only; no warranty", page)
        status, listing = self.request("POST", "/api/ui/list", b"pin=123456")
        self.assertEqual(status, 200)
        self.assertIn(b"files", listing)

    def test_first_run_pin_setup_blocks_transfers_and_persists(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            env = os.environ.copy()
            env.pop("LOCALSEND_PIN", None)
            env.update(LOCALSEND_DIR=directory, LOCALSEND_PORT=str(port))

            def request(method, path, body=None, headers=None):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request(method, path, body=body, headers=headers or {})
                response = conn.getresponse()
                result = response.status, response.read()
                conn.close()
                return result

            def start():
                process = subprocess.Popen([str(ROOT / "ps5-localsend.elf")], env=env,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                for _ in range(100):
                    try:
                        if request("GET", "/api/ui/status")[0] == 200:
                            return process
                    except OSError:
                        time.sleep(0.05)
                self.fail("first-run server did not start")

            process = start()
            try:
                self.assertFalse(json.loads(request("GET", "/api/ui/status")[1])["pinSet"])
                self.assertFalse(json.loads(request("GET", "/api/localsend/v2/info")[1])["download"])
                self.assertEqual(request("GET", "/")[0], 200)
                outbound = subprocess.run(
                    [str(ROOT / "ps5-localsend.elf"), "--send", "missing.txt", "127.0.0.1"],
                    env=env, capture_output=True, text=True, timeout=5,
                )
                self.assertNotEqual(outbound.returncode, 0)
                self.assertIn("Set a LocalSend PIN", outbound.stderr)
                for method, path, body in [
                    ("POST", "/api/localsend/v2/prepare-upload", b"{}"),
                    ("POST", "/api/localsend/v2/upload", b""),
                    ("POST", "/api/localsend/v2/prepare-download?pin=123456", b""),
                    ("GET", "/api/localsend/v2/download", None),
                    ("POST", "/send", b""),
                ]:
                    self.assertEqual(request(method, path, body)[0], 403)
                self.assertEqual(request("POST", "/api/ui/pin", b"pin=123456")[0], 403)
                headers = {"x-ps5-localsend": "1"}
                self.assertEqual(request("POST", "/api/ui/pin", b"pin=12345", headers)[0], 400)
                self.assertEqual(request("POST", "/api/ui/pin", b"pin=123456", headers)[0], 200)
                self.assertTrue(json.loads(request("GET", "/api/ui/status")[1])["pinSet"])
                self.assertEqual(request("POST", "/api/ui/pin", b"pin=111111", headers)[0], 409)
                pin_file = pathlib.Path(directory) / ".pin"
                self.assertEqual(pin_file.read_text(), "123456")
                self.assertEqual(pin_file.stat().st_mode & 0o777, 0o600)
            finally:
                process.terminate()
                process.wait(timeout=5)
                process.stderr.close()
            process = start()
            try:
                self.assertTrue(json.loads(request("GET", "/api/ui/status")[1])["pinSet"])
                self.assertEqual(request("POST", "/api/ui/list", b"pin=123456")[0], 200)
                self.assertEqual(request("POST", "/api/ui/list", b"pin=654321")[0], 401)
            finally:
                process.terminate()
                process.wait(timeout=5)
                process.stderr.close()

    def test_wrong_token_rejected(self):
        path = self.prepare("secret.bin", b"abc")
        status, _ = self.request("POST", path.split("&token=")[0] + "&token=wrong", b"abc")
        self.assertEqual(status, 403)
        sid = path.split("sessionId=")[1].split("&")[0]
        self.request("POST", f"/api/localsend/v2/cancel?sessionId={sid}")


if __name__ == "__main__":
    unittest.main()
