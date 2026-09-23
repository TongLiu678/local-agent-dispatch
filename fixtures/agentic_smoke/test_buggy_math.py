import unittest

from buggy_math import clamp


class ClampTests(unittest.TestCase):
    def test_below_range(self):
        self.assertEqual(clamp(-4, 0, 10), 0)

    def test_inside_range(self):
        self.assertEqual(clamp(6, 0, 10), 6)

    def test_above_range(self):
        self.assertEqual(clamp(18, 0, 10), 10)


if __name__ == "__main__":
    unittest.main()
