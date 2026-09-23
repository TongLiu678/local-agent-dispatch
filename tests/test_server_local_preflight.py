from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dispatch_preflight_scan as preflight  # noqa: E402


def local_models(smoke: dict, *, fresh: bool = True) -> dict:
    smoke = dict(smoke)
    if fresh:
        smoke.setdefault("completed_at_utc", preflight.now())
    return {
        "hosts": {
            "remote_a": {
                "host_id": "remote_a",
                "transport": "ssh",
                "apis": [
                    {
                        "runtime": "openai_compatible",
                        "base_url": "http://127.0.0.1:8000/v1",
                        "models": ["qwen2.5-coder-14b-awq"],
                        "health": "ready",
                    }
                ],
                "agentic_smoke": smoke,
            }
        }
    }


def build(smoke: dict, *, fresh: bool = True) -> dict:
    return preflight.build_pools(
        codex_usage={},
        cursor_status={},
        cursor_catalog=[],
        antigravity_usage={},
        antigravity_catalog=[],
        opencode_go={},
        local_models=local_models(smoke, fresh=fresh),
        blocked_rows=[],
    )["server_local.remote_a"]


class ServerLocalPreflightTests(unittest.TestCase):
    def test_matching_smoke_and_live_api_are_ready(self):
        pool = build(
            {
                "status": "passed",
                "host_id": "remote_a",
                "model": "qwen2.5-coder-14b-awq",
                "endpoint": "http://127.0.0.1:8000/v1/",
            }
        )
        self.assertEqual("ready", pool["health"])
        self.assertEqual("qwen2.5-coder-14b-awq", pool["default_model"])
        self.assertIsNone(pool["blocked_reason"])

    def test_mismatched_smoke_identity_blocks_server_pool(self):
        cases = (
            (
                {"host_id": "other-host"},
                "agentic smoke host_id does not match live host",
            ),
            (
                {"model": "stale-model"},
                "agentic smoke model does not match live API model",
            ),
            (
                {"endpoint": "http://127.0.0.1:9000/v1"},
                "agentic smoke endpoint does not match live API endpoint",
            ),
        )
        for identity, reason in cases:
            with self.subTest(identity=identity):
                smoke = {"status": "passed", **identity}
                pool = build(smoke)
                self.assertEqual("blocked", pool["health"])
                self.assertEqual(reason, pool["blocked_reason"])

    def test_status_only_smoke_without_freshness_is_blocked(self):
        pool = build({"status": "passed"}, fresh=False)
        self.assertEqual("blocked", pool["health"])
        self.assertEqual("agentic smoke freshness timestamp is missing", pool["blocked_reason"])

    def test_smoke_endpoint_is_not_accepted_when_live_endpoint_is_unknown(self):
        matched, reason = preflight.server_local_smoke_match(
            {
                "status": "passed",
                "endpoint": "http://127.0.0.1:8000/v1",
                "completed_at_utc": preflight.now(),
            },
            "remote_a",
            {"models": ["qwen2.5-coder-14b-awq"]},
        )
        self.assertFalse(matched)
        self.assertEqual(
            "agentic smoke endpoint cannot be verified against live API", reason
        )

    def test_matching_api_can_be_selected_when_another_listener_is_first(self):
        smoke = {
            "status": "passed",
            "host_id": "remote_a",
            "model": "qwen2.5-coder-14b-awq",
            "endpoint": "http://127.0.0.1:8000/v1",
        }
        hosts = local_models(smoke)
        hosts["hosts"]["remote_a"]["apis"].insert(
            0,
            {
                "runtime": "openai_compatible",
                "base_url": "http://127.0.0.1:9000/v1",
                "models": ["unrelated-model"],
                "health": "ready",
            },
        )
        pool = preflight.build_pools(
            {}, {}, [], {}, [], {}, hosts, []
        )["server_local.remote_a"]
        self.assertEqual("ready", pool["health"])
        self.assertEqual("http://127.0.0.1:8000/v1", pool["base_url"])

    def test_stale_smoke_is_blocked_even_when_identity_matches(self):
        pool = build(
            {
                "status": "passed",
                "host_id": "remote_a",
                "model": "qwen2.5-coder-14b-awq",
                "endpoint": "http://127.0.0.1:8000/v1",
                "completed_at_utc": "2020-01-01T00:00:00Z",
            }
        )
        self.assertEqual("blocked", pool["health"])
        self.assertEqual("agentic smoke evidence is stale", pool["blocked_reason"])


if __name__ == "__main__":
    unittest.main()
