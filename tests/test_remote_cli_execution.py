"""Provider-free tests for the reviewed server CLI execution boundary."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest

from scripts import remote_cli_execution as execution


NOW = "2026-08-29T15:45:00+00:00"


def sha(letter: str) -> str:
    return "sha256:" + letter * 64


def write_executable(path: pathlib.Path, body: str) -> None:
    # The central controller intentionally has no global ``python3`` shim;
    # bind fake provider scripts to the interpreter running this test suite.
    if body.startswith("#!/usr/bin/env python3\n"):
        body = f"#!{sys.executable}\n" + body.split("\n", 1)[1]
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def build_contract(root: pathlib.Path, *, provider: str, cli: pathlib.Path) -> dict[str, object]:
    model = "gpt-5.3-codex-spark" if provider == "codex" else "gemini-3.6-flash-high"
    pool = "codex.spark" if provider == "codex" else "antigravity.gemini"
    variant = "xhigh" if provider == "codex" else None
    contract: dict[str, object] = {
        "schema_version": 1,
        "contract_type": "local-agent-dispatch.remote-cli-placement",
        "contract_version": "0.1.0",
        "provider": provider,
        "pool_id": pool,
        "model": model,
        "variant": variant,
        "project_id": "lad-project",
        "attempt_id": "attempt-1",
        "execution_host": "remote-1",
        "execution_transport": "ssh",
        "remote_workspace": str(root),
        "write_scope": "src",
        "write_scope_path": str(root / "src"),
        "cli": {
            "name": "codex" if provider == "codex" else "agy",
            "path": str(cli),
            "version": "test-cli-1",
            "install_state": "installed",
            "auth": {
                "state": "authenticated",
                "scope": "remote_host",
                "host_id": "remote-1",
                "observed_at_utc": NOW,
                "ttl_seconds": 3600,
                "source": "server-local-preflight",
            },
        },
        "route_evidence": {
            "provider": "racknerd",
            "kind": "execution",
            "status": "verified",
            "verified": True,
            "target_host_id": "remote-1",
            "egress_ip": "198.51.100.10",
            "observed_at_utc": NOW,
            "ttl_seconds": 3600,
            "source": "server-route-verify",
        },
        "receipt": {
            "path": str(root / ".lad" / "receipts" / "attempt-1.json"),
            "relative_path": ".lad/receipts/attempt-1.json",
            "format": "json",
            "status": "required_pending",
        },
    }
    contract["contract_digest"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in contract.items() if key != "contract_digest"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return contract


def authorization(contract: dict[str, object], *, provider: str) -> dict[str, object]:
    pool = "codex.spark" if provider == "codex" else "antigravity.gemini"
    model = "gpt-5.3-codex-spark" if provider == "codex" else "gemini-3.6-flash-high"
    return {
        "schema_version": 1,
        "approved": True,
        "decision": "allow_provider_execution",
        "contract_digest": contract["contract_digest"],
        "provider": provider,
        "pool_id": pool,
        "model": model,
        "variant": "xhigh" if provider == "codex" else None,
        "attempt_id": "attempt-1",
        "run_id": "run-canary-1",
        "observed_at_utc": NOW,
        "ttl_seconds": 1800,
        "quota_snapshot_digest": sha("a"),
        "capacity_receipt_digest": sha("b"),
    }


class RemoteCliExecutionTests(unittest.TestCase):
    def make_workspace(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        workspace = root / "workspace"
        (workspace / "src").mkdir(parents=True)
        prompt = workspace / "TASK.md"
        prompt.write_text("SECRET prompt must never enter argv\n", encoding="utf-8")
        return workspace, prompt

    def test_dry_run_is_provider_free_and_contains_no_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace, prompt = self.make_workspace(root)
            cli = root / "codex"
            write_executable(cli, "#!/bin/sh\nprintf 'should not run'\n")
            contract = build_contract(workspace, provider="codex", cli=cli)
            report = execution.run_once(
                contract,
                prompt_file=prompt,
                result_source=workspace / "src" / "result.txt",
                execute=False,
                now_utc=NOW,
            )
            self.assertEqual("planned", report["status"])
            self.assertFalse(report["provider_execution"])
            self.assertNotIn("SECRET", json.dumps(report))
            self.assertFalse((workspace / ".lad").exists())

    def test_codex_execute_requires_authorization_and_writes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace, prompt = self.make_workspace(root)
            cli = root / "codex"
            write_executable(
                cli,
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "args=sys.argv\n"
                "p=pathlib.Path(args[args.index('--output-last-message')+1])\n"
                "p.write_text('codex result\\n', encoding='utf-8')\n"
                "print(json.dumps({'type':'item.completed','item':{'text':'codex result'}}))\n",
            )
            contract = build_contract(workspace, provider="codex", cli=cli)
            result = workspace / "src" / "codex-result.txt"
            with self.assertRaisesRegex(execution.RemoteCliExecutionError, "authorization"):
                execution.run_once(
                    contract,
                    prompt_file=prompt,
                    result_source=result,
                    execute=True,
                    now_utc=NOW,
                )
            report = execution.run_once(
                contract,
                authorization=authorization(contract, provider="codex"),
                prompt_file=prompt,
                result_source=result,
                execute=True,
                now_utc=NOW,
            )
            self.assertEqual("completed", report["status"])
            self.assertTrue(report["provider_execution"])
            self.assertTrue(report["model_prompts_sent"])
            self.assertEqual("codex result", result.read_text(encoding="utf-8").strip())
            receipt = workspace / ".lad" / "receipts" / "attempt-1.json"
            self.assertTrue(receipt.is_file())
            stored = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual("completed", stored["status"])
            self.assertNotIn("SECRET", json.dumps(stored))

    def test_antigravity_json_text_is_published_without_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace, prompt = self.make_workspace(root)
            cli = root / "agy"
            write_executable(
                cli,
                "#!/usr/bin/env python3\n"
                "import json\n"
                "print(json.dumps({'type':'text','text':'antigravity result'}))\n",
            )
            contract = build_contract(workspace, provider="antigravity", cli=cli)
            result = workspace / "src" / "agy-result.txt"
            report = execution.run_once(
                contract,
                authorization=authorization(contract, provider="antigravity"),
                prompt_file=prompt,
                result_source=result,
                execute=True,
                now_utc=NOW,
            )
            self.assertEqual("completed", report["status"])
            self.assertEqual("antigravity result", result.read_text(encoding="utf-8").strip())
            self.assertNotIn("antigravity result", json.dumps(report))

    def test_stale_route_or_wrong_model_fails_before_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace, prompt = self.make_workspace(root)
            cli = root / "codex"
            write_executable(cli, "#!/bin/sh\nexit 99\n")
            contract = build_contract(workspace, provider="codex", cli=cli)
            contract["route_evidence"] = dict(contract["route_evidence"], ttl_seconds=1)
            contract["contract_digest"] = execution._digest(
                {key: value for key, value in contract.items() if key != "contract_digest"}
            )
            with self.assertRaisesRegex(execution.RemoteCliExecutionError, "stale"):
                execution.run_once(
                    contract,
                    prompt_file=prompt,
                    result_source=workspace / "src" / "result.txt",
                    now_utc="2026-08-29T15:50:00+00:00",
                )

            fresh = build_contract(workspace, provider="codex", cli=cli)
            fresh["model"] = "gpt-5.6-luna"
            fresh["contract_digest"] = execution._digest(
                {key: value for key, value in fresh.items() if key != "contract_digest"}
            )
            with self.assertRaisesRegex(execution.RemoteCliExecutionError, "exact model"):
                execution.run_once(
                    fresh,
                    prompt_file=prompt,
                    result_source=workspace / "src" / "result.txt",
                    now_utc=NOW,
                )

    def test_existing_result_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workspace, prompt = self.make_workspace(root)
            cli = root / "codex"
            write_executable(cli, "#!/bin/sh\nexit 0\n")
            contract = build_contract(workspace, provider="codex", cli=cli)
            result = workspace / "src" / "result.txt"
            result.write_text("old\n", encoding="utf-8")
            with self.assertRaisesRegex(execution.RemoteCliExecutionError, "already exists"):
                execution.run_once(
                    contract,
                    authorization=authorization(contract, provider="codex"),
                    prompt_file=prompt,
                    result_source=result,
                    execute=True,
                    now_utc=NOW,
                )


if __name__ == "__main__":
    unittest.main()
