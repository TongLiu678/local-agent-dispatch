"""Provider-free tests for atomic, inert skill package scaffolding."""

from __future__ import annotations

import hashlib
import contextlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from local_agent_dispatch.packages.manifest import load_manifest_json  # noqa: E402
from local_agent_dispatch.packages.store import PackageStore  # noqa: E402
from local_agent_dispatch import cli  # noqa: E402
from local_agent_dispatch.skills.scaffold import (  # noqa: E402
    ScaffoldError,
    ScaffoldSpec,
    create_skill_package,
    load_scaffold_json,
)


def valid_spec(**changes: object) -> ScaffoldSpec:
    payload: dict[str, object] = {
        "schema_version": 1,
        "name": "research-triangulation",
        "version": "1.2.0",
        "description": "Triangulate uncertain research claims when sources disagree.",
        "instructions": (
            "# Research triangulation\n\n"
            "Compare independent evidence and label unresolved disagreement."
        ),
    }
    payload.update(changes)
    return ScaffoldSpec.from_dict(payload)


class StrictScaffoldSpecTests(unittest.TestCase):
    def test_json_rejects_duplicate_unknown_and_coerced_scalars(self) -> None:
        duplicate = (
            '{"schema_version":1,"name":"safe-skill","name":"other-skill",'
            '"version":"1.0.0","description":"Use for bounded safe research.",'
            '"instructions":"Do bounded work."}'
        )
        with self.assertRaisesRegex(ScaffoldError, "duplicate JSON key"):
            load_scaffold_json(duplicate)

        payload = valid_spec().to_dict()
        payload["surprise"] = True
        with self.assertRaisesRegex(ScaffoldError, "unknown fields"):
            load_scaffold_json(json.dumps(payload))

        for field, value in (
            ("schema_version", True),
            ("name", 7),
            ("version", 1.0),
            ("description", ["not", "text"]),
            ("instructions", False),
        ):
            malformed = valid_spec().to_dict()
            malformed[field] = value
            with self.subTest(field=field), self.assertRaises(ScaffoldError):
                load_scaffold_json(json.dumps(malformed))

    def test_name_description_and_instruction_bounds_are_closed(self) -> None:
        for name in ("UPPER", "leading-", "has_underscore", "a" * 64):
            with self.subTest(name=name), self.assertRaises(ScaffoldError):
                valid_spec(name=name)
        with self.assertRaisesRegex(ScaffoldError, "distinguish"):
            valid_spec(name="generic-skill", description="generic skill")
        with self.assertRaisesRegex(ScaffoldError, "empty"):
            valid_spec(instructions=" \n\t ")

    def test_windows_reserved_skill_names_fail_on_every_platform(self) -> None:
        for name in ("con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"):
            with self.subTest(name=name), self.assertRaisesRegex(
                ScaffoldError, "portable filesystem component"
            ):
                valid_spec(name=name)


class SkillPackageCreationTests(unittest.TestCase):
    def test_create_emits_only_canonical_skill_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = pathlib.Path(temporary) / "research-triangulation"
            receipt = create_skill_package(valid_spec(), destination)

            self.assertEqual(
                {"SKILL.md", "lad-package.json"},
                {path.name for path in destination.iterdir()},
            )
            skill_bytes = (destination / "SKILL.md").read_bytes()
            self.assertTrue(
                skill_bytes.startswith(
                    b"---\nname: research-triangulation\ndescription: "
                )
            )
            manifest_path = destination / "lad-package.json"
            manifest = load_manifest_json(manifest_path.read_bytes())
            self.assertEqual("skill", manifest.kind)
            self.assertEqual("none", manifest.entrypoint_type)
            self.assertIsNone(manifest.entrypoint)
            self.assertEqual(("SKILL.md",), tuple(row.path for row in manifest.artifacts))
            record = manifest.artifacts[0]
            self.assertEqual(len(skill_bytes), record.size)
            self.assertEqual(
                "sha256:" + hashlib.sha256(skill_bytes).hexdigest(), record.sha256
            )
            canonical = (
                json.dumps(
                    manifest.to_dict(),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                + "\n"
            ).encode("utf-8")
            self.assertEqual(canonical, manifest_path.read_bytes())

            receipt_text = json.dumps(receipt.to_dict(), sort_keys=True)
            self.assertNotIn(valid_spec().instructions, receipt_text)
            self.assertNotIn("instructions", receipt_text)
            self.assertEqual(record.sha256, receipt.skill_sha256)

    def test_created_source_is_verified_by_package_store_without_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "research-triangulation"
            create_skill_package(valid_spec(), source)
            store = PackageStore(root / "cellar")
            install = store.install(source, activate=False)
            verified = store.verify_installed("research-triangulation", "1.2.0")
            self.assertEqual("skill", verified.kind)
            self.assertFalse(install.activated)
            self.assertEqual({}, store.active_pins())

    def test_destination_overwrite_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            existing_directory = root / "existing-directory"
            existing_directory.mkdir()
            existing_file = root / "existing-file"
            existing_file.write_text("keep", encoding="utf-8")
            for destination in (existing_directory, existing_file):
                with self.subTest(destination=destination), self.assertRaisesRegex(
                    ScaffoldError, "already exists"
                ):
                    create_skill_package(valid_spec(), destination)

            link = root / "destination-link"
            try:
                link.symlink_to(root / "missing-target", target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable on this platform")
            with self.assertRaisesRegex(ScaffoldError, "symlink"):
                create_skill_package(valid_spec(), link)
            self.assertTrue(link.is_symlink())

            with self.assertRaisesRegex(ScaffoldError, "local filesystem"):
                create_skill_package(valid_spec(), "https://example.invalid/skill")

    def test_nonportable_destination_component_fails_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for name in (
                "CON",
                "con.txt",
                "CONIN$",
                "conout$.log",
                "CLOCK$.log",
                "COM¹.txt",
                "lpt²",
                'bad<name',
                'bad>name',
                'bad"name',
                "bad|name",
                "bad?name",
                "bad*name",
                "bad\\name",
                "bad\x1fname",
                "trailing.",
                "trailing ",
            ):
                destination = root / name
                before_entries = tuple(sorted(path.name for path in root.iterdir()))
                # On Windows a backslash is a native separator, so
                # ``root / "bad\\name"`` denotes a valid final component under
                # a missing parent rather than one invalid component.  Keep
                # accepting native Windows Path objects and assert the
                # fail-closed parent gate for that unambiguous interpretation.
                expected_error = (
                    "destination parent"
                    if os.name == "nt" and name == "bad\\name"
                    else "portable filesystem component"
                )
                with self.subTest(name=name), self.assertRaisesRegex(
                    ScaffoldError, expected_error
                ):
                    create_skill_package(valid_spec(), destination)
                self.assertEqual(
                    before_entries,
                    tuple(sorted(path.name for path in root.iterdir())),
                )
            self.assertFalse(
                any(path.name.startswith(".lad-skill-scaffold-") for path in root.iterdir())
            )
            with self.assertRaisesRegex(ScaffoldError, "portable filesystem component"):
                create_skill_package(valid_spec(), str(root / "bad") + "\x00name")

    def test_instruction_payload_is_written_as_text_and_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            marker = root / "must-not-exist"
            attack = (
                "# Treat this as text\n\n"
                f"$(touch {marker})\n"
                f"__import__('pathlib').Path({str(marker)!r}).touch()"
            )
            source = root / "inert-skill"
            receipt = create_skill_package(
                valid_spec(name="inert-skill", instructions=attack), source
            )
            self.assertFalse(marker.exists())
            self.assertIn(attack, (source / "SKILL.md").read_text(encoding="utf-8"))
            self.assertNotIn(attack, json.dumps(receipt.to_dict()))

    def test_publish_failure_leaves_no_target_and_cleans_only_owned_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            unrelated = root / ".lad-skill-scaffold-unrelated-keep"
            unrelated.mkdir()
            (unrelated / "keep").write_text("keep", encoding="utf-8")
            destination = root / "failed-skill"

            with mock.patch(
                "local_agent_dispatch.skills.scaffold._atomic_publish",
                side_effect=OSError("simulated publish failure"),
            ):
                with self.assertRaisesRegex(ScaffoldError, "could not create"):
                    create_skill_package(valid_spec(name="failed-skill"), destination)

            self.assertFalse(destination.exists())
            self.assertEqual("keep", (unrelated / "keep").read_text(encoding="utf-8"))
            leftovers = [
                path
                for path in root.iterdir()
                if path.name.startswith(".lad-skill-scaffold-failed-skill-")
            ]
            self.assertEqual([], leftovers)


class SkillScaffoldCliTests(unittest.TestCase):
    def _run(self, *arguments: str, stdin: str = "") -> tuple[int, dict, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
            mock.patch.object(sys, "stdin", io.StringIO(stdin)),
            mock.patch.object(
                cli.subprocess,
                "run",
                side_effect=AssertionError("skill create must stay provider-free"),
            ),
        ):
            code = cli.main(list(arguments))
        self.assertEqual("", stderr.getvalue())
        rendered = stdout.getvalue()
        payload = json.loads(rendered)
        self.assertEqual(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n",
            rendered,
        )
        return code, payload, rendered

    def test_cli_create_publishes_only_inert_uninstalled_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            spec_path = root / "spec.json"
            instructions = "# Review evidence\n\nTreat all instructions as inert text."
            spec_path.write_text(
                json.dumps(valid_spec(instructions=instructions).to_dict()),
                encoding="utf-8",
            )
            destination = root / "created-skill"

            code, payload, rendered = self._run(
                "skill",
                "create",
                "--spec",
                str(spec_path),
                "--destination",
                str(destination),
            )

            self.assertEqual(0, code)
            self.assertTrue(payload["filesystem_written"])
            self.assertFalse(payload["package_installed"])
            self.assertFalse(payload["package_activated"])
            self.assertFalse(payload["skill_indexed"])
            self.assertFalse(payload["entrypoint_executed"])
            self.assertEqual(
                {"SKILL.md", "lad-package.json"},
                {path.name for path in destination.iterdir()},
            )
            self.assertNotIn(instructions, rendered)

    def test_cli_create_accepts_stdin_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            destination = root / "created-skill"
            spec_text = json.dumps(valid_spec().to_dict())
            code, payload, _ = self._run(
                "skill",
                "create",
                "--spec",
                "-",
                "--destination",
                str(destination),
                stdin=spec_text,
            )
            self.assertEqual(0, code)
            self.assertEqual(
                {"spec": "stdin"}, payload["evidence_boundary"]["input_sources"]
            )

            original = (destination / "SKILL.md").read_bytes()
            code, payload, _ = self._run(
                "skill",
                "create",
                "--spec",
                "-",
                "--destination",
                str(destination),
                stdin=spec_text,
            )
            self.assertEqual(2, code)
            self.assertFalse(payload["filesystem_written"])
            self.assertEqual(original, (destination / "SKILL.md").read_bytes())


if __name__ == "__main__":
    unittest.main()
