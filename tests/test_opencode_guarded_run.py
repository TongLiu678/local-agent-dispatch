from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


guard = load_module("lad_opencode_guard", ROOT / "scripts" / "opencode_guarded_run.py")


class OpenCodeGuardTests(unittest.TestCase):
    def test_extracts_only_text_events(self):
        raw = "\n".join(
            [
                '{"type":"step_start","part":{"type":"step-start"}}',
                '{"type":"text","part":{"type":"text","text":"hello "}}',
                "not json",
                '{"type":"text","part":{"type":"text","text":"world"}}',
                '{"type":"step_finish","part":{"type":"step-finish"}}',
            ]
        )
        self.assertEqual("hello world", guard.text_from_events(raw))

    def test_detects_explicit_error_event(self):
        raw = '{"type":"error","error":{"name":"ProviderError","message":"quota"}}\n'
        diagnostic = guard.error_from_events(raw)
        self.assertIn("ProviderError", diagnostic or "")

    def test_rejects_non_go_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(
                cwd=temporary,
                model="opencode/big-pickle",
                variant=None,
                pure=True,
                auto_approve=False,
            )
            with self.assertRaisesRegex(ValueError, "opencode-go"):
                guard.build_argv(args)

    def test_prompt_file_avoids_putting_packet_contents_in_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            prompt = pathlib.Path(temporary) / "task.md"
            prompt.write_text("private task body", encoding="utf-8")
            args = argparse.Namespace(
                prompt=None,
                prompt_file=str(prompt),
                cwd=temporary,
                model="opencode-go/mimo-v2.5",
                variant=None,
                pure=True,
                auto_approve=False,
            )
            task_text = guard.load_prompt(args)
            argv = guard.build_argv(args)
            self.assertEqual("private task body", task_text)
            self.assertNotIn("private task body", " ".join(argv))
            self.assertNotIn("--file", argv)
            self.assertNotIn("--auto", argv)

    def test_main_sends_task_on_stdin_without_attachment_or_argv_leak(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            prompt = root / "task.md"
            result = root / "result.txt"
            prompt.write_text("private stdin task", encoding="utf-8")
            completed_argv = []
            completed_input = []

            class Completed:
                returncode = 0
                stdout = '{"type":"text","part":{"type":"text","text":"done"}}\n'
                stderr = ""

            def fake_run(argv, **kwargs):
                completed_argv.extend(argv)
                completed_input.append(kwargs.get("input"))
                return Completed()

            original = guard.subprocess.run
            guard.subprocess.run = fake_run
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = guard.main(
                        [
                            "--cwd", temporary,
                            "--model", "opencode-go/mimo-v2.5",
                            "--prompt-file", str(prompt),
                            "--result-source", str(result),
                        ]
                    )
            finally:
                guard.subprocess.run = original
            self.assertEqual(0, code)
            self.assertEqual(["private stdin task"], completed_input)
            self.assertNotIn("private stdin task", " ".join(completed_argv))
            self.assertNotIn("--file", completed_argv)
            self.assertEqual("done\n", result.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
