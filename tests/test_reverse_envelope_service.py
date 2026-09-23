from __future__ import annotations

import hashlib
import json
import pathlib
import socket
import sys
import tempfile
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from remote_envelope import build_envelope  # noqa: E402
from reverse_envelope_service import BridgeService, LoopbackBridgeServer  # noqa: E402


class ReverseEnvelopeServiceTests(unittest.TestCase):
    def _envelope(self, request_id: str) -> dict:
        return build_envelope(
            request_id=request_id,
            source_id="central",
            target_id="EDGE_WORKER",
            operation="execute.prepared",
            packet_digest=hashlib.sha256(b"packet").hexdigest(),
            payload_summary={
                "job_id": "job-" + request_id,
                "packet_id": "packet-" + request_id,
                "attempt_id": "attempt-" + request_id,
                "model": "provider-free-fixture",
                "variant": "fixture-v1",
                "provider": "fixture",
                "pool_id": "fixture",
            },
        )

    def test_receive_is_idempotent_and_persists_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            envelope = self._envelope("request-reverse-1")
            service = BridgeService(pathlib.Path(tmp))
            request = {
                "schema_version": 1,
                "request_id": "rpc-reverse-1",
                "operation": "envelope-receive",
                "envelope": envelope,
            }
            first = service.handle_request(request)
            second = service.handle_request(request)
            self.assertEqual("ok", first["status"])
            self.assertEqual("accepted", first["result"]["status"])
            self.assertFalse(first["result"]["duplicate"])
            self.assertTrue(second["result"]["duplicate"])
            status = service.handle_request(
                {
                    "schema_version": 1,
                    "request_id": "rpc-reverse-status-1",
                    "operation": "envelope-status",
                    "target_request_id": "request-reverse-1",
                }
            )
            self.assertEqual("accepted", status["result"]["status"])

    def test_loopback_socket_round_trip_uses_fixed_json_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = LoopbackBridgeServer("127.0.0.1", 0, BridgeService(tmp))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                request = {
                    "schema_version": 1,
                    "request_id": "rpc-socket-1",
                    "operation": "envelope-receive",
                    "envelope": self._envelope("request-socket-1"),
                }
                with socket.create_connection(server.server_address, timeout=2) as conn:
                    conn.sendall((json.dumps(request) + "\n").encode("utf-8"))
                    response = json.loads(conn.makefile("rb").readline().decode("utf-8"))
                self.assertEqual("ok", response["status"])
                self.assertEqual("accepted", response["result"]["status"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_service_rejects_provider_or_shell_fields_and_non_loopback_bind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            service = BridgeService(tmp)
            response = service.handle_request(
                {
                    "schema_version": 1,
                    "request_id": "rpc-secret-1",
                    "operation": "envelope-pending",
                    "prompt": "must-not-cross",
                }
            )
            self.assertEqual("error", response["status"])
            self.assertEqual("BridgeError", response["error"])
            with self.assertRaises(ValueError):
                LoopbackBridgeServer("0.0.0.0", 0, service)


if __name__ == "__main__":
    unittest.main()
