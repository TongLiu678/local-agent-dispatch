"""Keep the public reproducibility contract tied to unittest discovery.

Only the compact public documentation participates in this check. Private run
history and machine-specific evidence are deliberately not required for a
clean public checkout. The static counting contract mirrors the current test
layout: top-level ``unittest.TestCase`` classes and synchronous ``test_*``
methods only.
"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
STATUS = ROOT / "docs" / "status.md"
REPRODUCIBILITY = ROOT / "docs" / "reproducibility.md"
RESEARCH_PROGRAM = ROOT / "docs" / "research-program.md"
ARCHITECTURE = ROOT / "docs" / "architecture.md"
PUBLIC_EXCLUDED_TESTS = frozenset({"test_m0_evidence_consistency.py"})


def _count_tests(path: pathlib.Path) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return sum(
        1
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        for item in node.body
        if isinstance(item, ast.FunctionDef) and item.name.startswith("test_")
    )


def _suite_size() -> int:
    return sum(
        _count_tests(path)
        for path in sorted(TESTS.glob("test_*.py"))
        if path.name not in PUBLIC_EXCLUDED_TESTS
    )


def _documented_count() -> int:
    text = REPRODUCIBILITY.read_text(encoding="utf-8")
    matches = re.findall(
        r"(?m)^`current_provider_free_test_methods: ([0-9]+)`$",
        text,
    )
    if len(matches) != 1:
        raise AssertionError(
            f"{REPRODUCIBILITY}: expected exactly one current test-count field"
        )
    return int(matches[0])


class SuiteCountBookkeepingTests(unittest.TestCase):
    def test_full_suite_count_matches_public_reproducibility_field(self) -> None:
        documented = _documented_count()
        self.assertEqual(
            documented,
            _suite_size(),
            "public provider-free test count is stale",
        )

    def test_reproducibility_documents_provider_free_entrypoints(self) -> None:
        text = REPRODUCIBILITY.read_text(encoding="utf-8")
        self.assertIn("unittest discover", text)
        self.assertIn("doctor --offline", text)
        self.assertIn("demo --offline", text)
        self.assertIn("without credentials", text)

    def test_public_docs_do_not_link_private_history(self) -> None:
        forbidden = (
            "docs/superpowers",
            "release-checklist.md",
            "roadmap.md",
            "baseline-registry-v1.md",
            "continuous-operation-v1.md",
            "EXAMPLE_",
        )
        for path in (STATUS, REPRODUCIBILITY, RESEARCH_PROGRAM, ARCHITECTURE):
            text = path.read_text(encoding="utf-8")
            for value in forbidden:
                self.assertNotIn(value, text, f"{path}: private-history link {value!r}")

    def test_static_suite_and_documentation_contracts_match(self) -> None:
        problems: list[str] = []
        for path in sorted(TESTS.glob("test_*.py")):
            if path.name in PUBLIC_EXCLUDED_TESTS:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                    problems.append(f"{path.name}:{node.lineno}: top-level test function")
                if isinstance(node, ast.AsyncFunctionDef):
                    problems.append(f"{path.name}:{node.lineno}: async test function")
                if isinstance(node, ast.ClassDef):
                    bases = [
                        base.attr if isinstance(base, ast.Attribute) else base.id
                        for base in node.bases
                        if isinstance(base, (ast.Name, ast.Attribute))
                    ]
                    has_tests = any(
                        isinstance(item, ast.FunctionDef)
                        and item.name.startswith("test_")
                        for item in node.body
                    )
                    if has_tests and not any("TestCase" in base for base in bases):
                        problems.append(
                            f"{path.name}:{node.lineno}: {node.name} lacks TestCase base"
                        )
        self.assertEqual([], problems, "test-counting contract drifted")

        status = STATUS.read_text(encoding="utf-8")
        architecture = ARCHITECTURE.read_text(encoding="utf-8")
        for name, text in (
            ("status", status),
            ("architecture", architecture),
        ):
            self.assertIn(
                "offline_implementation",
                text,
                f"{name} does not declare the offline implementation track",
            )
            self.assertIn(
                "live_promotion",
                text,
                f"{name} does not declare the live promotion track",
            )
        for name, text in (
            ("status", status),
            ("architecture", architecture),
        ):
            self.assertIn("sqlite_database_schema = 7", text, name)
            self.assertIn("resource_packet_schema = 3", text, name)

        research = RESEARCH_PROGRAM.read_text(encoding="utf-8")
        self.assertIn("Observe -> Compile -> Plan -> Reserve -> Execute", research)
        self.assertIn("skill-evolution proposals", research)


if __name__ == "__main__":
    unittest.main()
