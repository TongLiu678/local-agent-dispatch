"""Provider-free regression test package.

Keeping the test tree importable makes ``unittest discover -s tests``
deterministic on the older Python runtimes used by the central PBS cluster;
without this marker some runtimes also discover legacy root-level test files.
"""
