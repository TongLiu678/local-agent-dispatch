"""Provider-free tests for the exact Codex model preflight presets."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import codex_model_preflight  # noqa: E402


class CodexModelPreflightTests(unittest.TestCase):
    def _cache(self, models: list[dict[str, object]]) -> pathlib.Path:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        self.addCleanup(lambda: pathlib.Path(handle.name).unlink(missing_ok=True))
        json.dump({"models": models}, handle)
        handle.close()
        return pathlib.Path(handle.name)

    def test_sol_max_is_an_exact_preset(self) -> None:
        cache = self._cache([
            {
                "slug": "gpt-5.6-sol",
                "supported_reasoning_levels": [{"effort": "max"}],
            },
            {
                "slug": "gpt-5.6-luna",
                "supported_reasoning_levels": [{"effort": "max"}],
            },
        ])
        result = codex_model_preflight.main(["--preset", "sol-max", "--cache", str(cache)])
        self.assertEqual(0, result)

    def test_sol_does_not_fallback_when_cache_lacks_exact_slug(self) -> None:
        cache = self._cache([
            {
                "slug": "gpt-5.6-luna",
                "supported_reasoning_levels": [{"effort": "max"}],
            },
        ])
        result = codex_model_preflight.main(["--preset", "sol-max", "--cache", str(cache)])
        self.assertEqual(2, result)


if __name__ == "__main__":
    unittest.main()
