"""Tests for data normalization helpers (utils/helpers.py)."""

import unittest
from datetime import datetime

from utils.helpers import as_list, bytes_to_gb, days_since, parse_datetime, safe_float, safe_int


class TestParseDatetime(unittest.TestCase):
    def test_dotnet_date_format(self):
        # Captured live from Win32_OperatingSystem.LastBootUpTime via ConvertTo-Json.
        result = parse_datetime("/Date(1787063746500)/")
        self.assertIsInstance(result, datetime)
        self.assertEqual(result.year, 2026)

    def test_cim_readable_string_format(self):
        # Captured live from Win32_QuickFixEngineering.InstalledOn.DateTime.
        result = parse_datetime("16 August 2026 00:00:00")
        self.assertEqual(result, datetime(2026, 8, 16, 0, 0, 0))

    def test_iso_format(self):
        result = parse_datetime("2026-08-16T00:00:00")
        self.assertEqual(result, datetime(2026, 8, 16, 0, 0, 0))

    def test_none_input(self):
        self.assertIsNone(parse_datetime(None))

    def test_empty_string(self):
        self.assertIsNone(parse_datetime(""))

    def test_garbage_input(self):
        self.assertIsNone(parse_datetime("not a date"))

    def test_non_string_input(self):
        self.assertIsNone(parse_datetime(12345))


class TestDaysSince(unittest.TestCase):
    def test_none_returns_none(self):
        self.assertIsNone(days_since(None))

    def test_past_date(self):
        past = datetime(2020, 1, 1)
        self.assertGreater(days_since(past), 0)


class TestBytesToGb(unittest.TestCase):
    def test_conversion(self):
        self.assertEqual(bytes_to_gb(16 * 1024 ** 3), 16.0)

    def test_none_input(self):
        self.assertIsNone(bytes_to_gb(None))

    def test_non_numeric_input(self):
        self.assertIsNone(bytes_to_gb("not a number"))


class TestSafeConversions(unittest.TestCase):
    def test_safe_int_valid(self):
        self.assertEqual(safe_int("42"), 42)

    def test_safe_int_none(self):
        self.assertIsNone(safe_int(None))

    def test_safe_int_invalid(self):
        self.assertIsNone(safe_int("not a number"))

    def test_safe_float_valid(self):
        self.assertEqual(safe_float("3.14"), 3.14)


class TestAsList(unittest.TestCase):
    def test_none_becomes_empty_list(self):
        self.assertEqual(as_list(None), [])

    def test_list_passthrough(self):
        self.assertEqual(as_list([1, 2, 3]), [1, 2, 3])

    def test_scalar_becomes_single_item_list(self):
        # PowerShell's ConvertTo-Json collapses a single-item array to a
        # bare object; collectors normalize that back to a list.
        self.assertEqual(as_list({"a": 1}), [{"a": 1}])


if __name__ == "__main__":
    unittest.main()
