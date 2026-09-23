from __future__ import annotations

import contextlib
import io
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import continuity_controller  # noqa: E402
import remote_cli_placement as placement  # noqa: E402


NOW = "2026-08-15T08:00:00+00:00"


def _wrapper(name: str = "remote-cli-wrapper") -> dict[str, str]:
    return {
        "name": name,
        "version": "0.1.0",
        "sha256": "a" * 64,
        "mode": "dry-run",
    }


def _inputs(*, gemini: bool = False, sol: bool = False):
    if gemini and sol:
        raise ValueError("gemini and sol fixtures are mutually exclusive")
    if gemini:
        assignment = {
            "job_id": "gemini-job",
            "attempt_id": "gemini-attempt",
            "pool_id": "antigravity.gemini",
            "provider": "antigravity",
            "model": "gemini-3.6-flash-high",
            "variant": None,
            "execution_host": "westd",
            "execution_transport": "ssh",
            "workload_host": "westd",
            "workload_transport": "ssh",
            "remote_workspace": "/srv/lad/gemini-job",
            "write_scope": "src/gemini",
            "remote_cli_wrapper": _wrapper("agy-remote-cli-wrapper"),
            "receipt_path": "/srv/lad/gemini-job/.lad/receipts/gemini-attempt.json",
        }
        cli = {
            "name": "agy",
            "path": "/opt/antigravity/bin/agy",
            "version": "1.1.13",
            "install_state": "installed",
            "auth": {
                "state": "authenticated",
                "scope": "remote_host",
                "host_id": "westd",
                "observed_at_utc": NOW,
                "ttl_seconds": 600,
                "source": "agy models",
            },
        }
    elif sol:
        assignment = {
            "job_id": "sol-job",
            "attempt_id": "sol-attempt",
            "pool_id": "codex.luna",
            "provider": "codex",
            "model": "gpt-5.6-sol",
            "variant": "max",
            "execution_host": "westd",
            "execution_transport": "ssh",
            "workload_host": "westd",
            "workload_transport": "ssh",
            "remote_workspace": "/srv/lad/sol-job",
            "write_scope": "src/sol",
            "remote_cli_wrapper": _wrapper("codex-sol-remote-cli-wrapper"),
            "receipt_path": "/srv/lad/sol-job/.lad/receipts/sol-attempt.json",
        }
        cli = {
            "name": "codex",
            "path": "/usr/local/bin/codex",
            "version": "0.147.0",
            "install_state": "installed",
            "auth": {
                "state": "authenticated",
                "scope": "remote_host",
                "host_id": "westd",
                "observed_at_utc": NOW,
                "ttl_seconds": 600,
                "source": "codex login status",
            },
        }
    else:
        assignment = {
            "job_id": "spark-job",
            "attempt_id": "spark-attempt",
            "pool_id": "codex.spark",
            "provider": "codex",
            "model": "gpt-5.3-codex-spark",
            "variant": "xhigh",
            "execution_host": "westd",
            "execution_transport": "ssh",
            "workload_host": "westd",
            "workload_transport": "ssh",
            "remote_workspace": "/srv/lad/spark-job",
            "write_scope": "src/spark",
            "remote_cli_wrapper": _wrapper("codex-remote-cli-wrapper"),
            "receipt_path": "/srv/lad/spark-job/.lad/receipts/spark-attempt.json",
        }
        cli = {
            "name": "codex",
            "path": "/usr/local/bin/codex",
            "version": "0.147.0",
            "install_state": "installed",
            "auth": {
                "state": "authenticated",
                "scope": "remote_host",
                "host_id": "westd",
                "observed_at_utc": NOW,
                "ttl_seconds": 600,
                "source": "codex login status",
            },
        }
    host = {
        "host_id": "westd",
        "transport": "ssh",
        "hostname": "synthetic.westd.invalid",
        "port": 443,
        "project_path": "/srv/lad",
        "remote_cli": cli,
    }
    route = {
        "provider": "racknerd",
        "kind": "execution",
        "status": "verified",
        "verified": True,
        "target_host_id": "westd",
        "egress_ip": "192.0.2.44",
        "observed_at_utc": NOW,
        "ttl_seconds": 300,
        "source": "codex-racknerd-route verify",
        "project_path": "/srv/lad",
    }
    return assignment, host, route


class RemoteCliPlacementTests(unittest.TestCase):
    def test_codex_sol_contract_is_exact_current_route(self):
        assignment, host, route = _inputs(sol=True)
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertTrue(report["valid"], report)
        contract = report["contract"]
        self.assertEqual("codex.luna", contract["pool_id"])
        self.assertEqual("gpt-5.6-sol", contract["model"])
        self.assertEqual("max", contract["variant"])
        self.assertFalse(report["provider_execution"])

    def test_codex_spark_contract_is_exact_and_provider_free(self):
        assignment, host, route = _inputs()
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertTrue(report["valid"], report)
        self.assertEqual("admit", report["decision"])
        self.assertTrue(report["dry_run"])
        self.assertFalse(report["provider_execution"])
        self.assertFalse(report["model_prompts_sent"])
        contract = report["contract"]
        self.assertEqual("gpt-5.3-codex-spark", contract["model"])
        self.assertEqual("xhigh", contract["variant"])
        self.assertEqual("ssh", contract["execution_transport"])
        self.assertEqual("/srv/lad", contract["project_path"])
        self.assertEqual("src/spark", contract["write_scope"])
        self.assertEqual(
            "/srv/lad/spark-job/.lad/receipts/spark-attempt.json",
            contract["receipt"]["path"],
        )
        self.assertEqual("required_pending", contract["receipt"]["status"])

    def test_antigravity_agy_contract_requires_explicit_null_variant(self):
        assignment, host, route = _inputs(gemini=True)
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertTrue(report["valid"], report)
        contract = report["contract"]
        self.assertEqual("agy", contract["cli"]["name"])
        self.assertEqual("gemini-3.6-flash-high", contract["model"])
        self.assertIsNone(contract["variant"])
        self.assertEqual("remote_host", contract["cli"]["auth"]["scope"])

        assignment.pop("variant")
        missing = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(missing["valid"])
        self.assertIn("assignment.variant is required", missing["reasons"][0])

    def test_local_desktop_auth_is_never_accepted_for_remote_host(self):
        assignment, host, route = _inputs()
        host["remote_cli"]["auth"]["scope"] = "local_desktop"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("remote_host", report["reasons"][0])

    def test_route_must_be_verified_racknerd_and_target_exact_host(self):
        assignment, host, route = _inputs()
        route["provider"] = "mac-proxy"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("provider=racknerd", report["reasons"][0])

        route["provider"] = "racknerd"
        route["target_host_id"] = "bjb2"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("target_host_id", report["reasons"][0])

    def test_stale_auth_and_unsafe_receipt_fail_closed(self):
        assignment, host, route = _inputs()
        host["remote_cli"]["auth"]["observed_at_utc"] = "2026-08-14T00:00:00+00:00"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("stale", report["reasons"][0])

        assignment, host, route = _inputs()
        assignment["receipt_path"] = "/srv/other/.lad/receipts/attempt.json"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("escapes project_path", report["reasons"][0])

    def test_exact_model_wrapper_and_receipt_are_required(self):
        assignment, host, route = _inputs()
        assignment["model"] = "gpt-5.6-luna"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("exact approved model", report["reasons"][0])

        assignment, host, route = _inputs()
        assignment["remote_cli_wrapper"]["mode"] = "execute"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("mode must be dry-run", report["reasons"][0])

        assignment, host, route = _inputs()
        assignment["receipt_path"] = "/srv/lad/spark-job/result.json"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn(".lad/receipts", report["reasons"][0])

    def test_split_workload_requires_a_second_wrapper(self):
        assignment, host, route = _inputs()
        assignment["workload_host"] = "bjb2"
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertFalse(report["valid"])
        self.assertIn("workload_wrapper", report["reasons"][0])

        assignment["workload_wrapper"] = _wrapper("remote-worker")
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        self.assertTrue(report["valid"], report)

    def test_attach_projects_contract_without_provider_or_ssh_execution(self):
        assignment, host, route = _inputs()
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        packet = {
            "schema_version": 1,
            "packet_id": "packet-spark",
            "job_id": "spark-job",
            "pool_id": "codex.spark",
            "provider": "codex",
            "model": "gpt-5.3-codex-spark",
            "variant": "xhigh",
            "workspace": "/controller/staging",
            "write_scope": "src/spark",
            "required_artifacts": ["/srv/lad/spark-job/result.json"],
            "validation_required": True,
            "validation_argv": [sys.executable, "-c", "import sys; sys.exit(0)"],
            "attempts": [
                {
                    "attempt_id": "spark-attempt",
                    "adapter": "placeholder",
                    "transport": "ssh",
                    "model": "gpt-5.3-codex-spark",
                }
            ],
        }
        projected = placement.attach_remote_cli_contract(packet, report)
        self.assertEqual("remote_cli", projected["attempts"][0]["adapter"])
        self.assertEqual("ssh", projected["attempts"][0]["transport"])
        self.assertEqual("westd", projected["execution_host"])
        self.assertEqual("/srv/lad/spark-job", projected["workspace"])
        self.assertFalse(projected["provider_execution"])
        self.assertFalse(projected["model_prompts_sent"])
        self.assertEqual(
            projected["remote_cli_placement"]["contract_digest"],
            report["contract"]["contract_digest"],
        )
        # The existing strict packet validator accepts the marker as a packet
        # representation but does not execute it.
        continuity_controller.validate_task_packet(projected)

    def test_attach_rejects_tampered_contract_and_inline_prompt(self):
        assignment, host, route = _inputs()
        report = placement.build_remote_cli_contract(
            assignment, host, route, now_utc=NOW
        )
        packet = {
            "schema_version": 1,
            "packet_id": "packet-spark",
            "job_id": "spark-job",
            "attempts": [{
                "attempt_id": "spark-attempt",
                "adapter": "placeholder",
                "transport": "ssh",
                "model": "gpt-5.3-codex-spark",
            }],
        }
        tampered = dict(report["contract"])
        tampered["model"] = "gpt-5.6-luna"
        with self.assertRaisesRegex(placement.RemoteCliPlacementError, "digest mismatch"):
            placement.attach_remote_cli_contract(packet, tampered)

        packet["prompt"] = "this must not enter a placement packet"
        with self.assertRaisesRegex(placement.RemoteCliPlacementError, "inline prompt"):
            placement.attach_remote_cli_contract(packet, report)

    def test_cli_build_defaults_to_stdout_dry_run_without_output_file(self):
        assignment, host, route = _inputs()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            paths = {}
            for name, value in (("assignment", assignment), ("host", host), ("route", route)):
                path = root / f"{name}.json"
                path.write_text(__import__("json").dumps(value), encoding="utf-8")
                paths[name] = path
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = placement.main([
                    "build",
                    "--assignment", str(paths["assignment"]),
                    "--host", str(paths["host"]),
                    "--route", str(paths["route"]),
                    "--now-utc", NOW,
                ])
            self.assertEqual(0, rc)
            self.assertIn('"provider_execution": false', output.getvalue())
            self.assertFalse((root / "contract.json").exists())


if __name__ == "__main__":
    unittest.main()
