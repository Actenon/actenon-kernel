"""Timestamps are RFC 3339 section 5.6 date-time, parsed identically on every supported Python.

Before 1.3.0 parse_timestamp delegated to datetime.fromisoformat, whose grammar changed in Python 3.11, so
the same signed proof verified on one interpreter and was refused on another (north-star evidence:
evidence/release/north-star/differential/corpus-addendum-timestamp-grammar). Each expectation below is
the RFC 3339 grammar plus the two ecosystem conventions documented on parse_timestamp.
"""

from __future__ import annotations

import unittest
from datetime import date, datetime, timezone

from actenon.models.contracts import parse_calendar_date, parse_timestamp

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

ACCEPTED = {
    "2026-01-01T12:00:00Z": T0,
    "2026-01-01T12:00:00.5Z": T0.replace(microsecond=500000),
    "2026-01-01T12:00:00.0Z": T0,
    "2026-01-01T12:00:00.123Z": T0.replace(microsecond=123000),
    "2026-01-01T12:00:00.1234567Z": T0.replace(
        microsecond=123456
    ),  # truncated, not rounded
    "2026-01-01T12:00:00.000000000Z": T0,
    "2026-01-01T12:00:00.000000+00:00": T0,
    "2026-01-01T12:00:00-00:00": T0,
    "2026-01-01T17:30:00+05:30": T0,
    "2026-01-01T07:00:00-05:00": T0,
    "2026-01-01t12:00:00Z": T0,  # RFC 3339 5.6 NOTE: lower-case "t" is permitted
    "2026-01-01 12:00:00Z": T0,  # RFC 3339 5.6 NOTE: space left to applications; kept
}

REFUSED = [
    "2026-01-01T12:00Z",  # no seconds
    "2026-01-01T12Z",  # hour only
    "2026-01-01T12:00:00.Z",  # empty fraction
    "2026-01-01T12:00:00,5Z",  # comma decimal sign
    "20260101T120000Z",  # basic format
    "2026-01-01T120000Z",
    "2026-W01-4T12:00:00Z",  # week date
    "2026-001T12:00:00Z",  # ordinal date
    "2026-01-01T12:00:00+0000",
    "2026-01-01T12:00:00+00",
    "2026-01-01T12:00:00+00:00:00",
    "2026-01-01T12:00:00+05:60",
    "2026-01-01T12:00:00+24:00",
    "2026-01-01T12:00:00 Z",
    " 2026-01-01T12:00:00Z",
    "2026-01-01T12:00:00Z\n",
    "2026-1-01T12:00:00Z",
    "2026-01-01x12:00:00Z",  # fromisoformat takes any separator character
    "2026-01-01T12:00:00z",  # ecosystem convention: upper-case Z only
    "2026-01-01T12:00:0٠Z",  # non-ASCII digit
    "2026-01-01T24:00:00Z",
    "2026-01-01T12:00:60Z",
    "2026-13-01T12:00:00Z",
    "2026-02-30T12:00:00Z",
    "2026-01-01",
    "",
]


class TimestampGrammarTests(unittest.TestCase):
    def test_accepted_forms_parse_to_the_same_instant(self) -> None:
        for raw, expected in ACCEPTED.items():
            with self.subTest(raw=raw):
                self.assertEqual(parse_timestamp(raw, "t"), expected)

    def test_refused_forms(self) -> None:
        for raw in REFUSED:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_timestamp(raw, "t")

    def test_missing_offset_keeps_its_message(self) -> None:
        with self.assertRaisesRegex(ValueError, "must include timezone information"):
            parse_timestamp("2026-01-01T12:00:00", "issued_at")

    def test_non_string_is_refused(self) -> None:
        for raw in (None, 1767268800, b"2026-01-01T12:00:00Z"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_timestamp(raw, "t")


class CalendarDateGrammarTests(unittest.TestCase):
    def test_full_date_only(self) -> None:
        self.assertEqual(parse_calendar_date("2026-01-31", "d"), date(2026, 1, 31))
        for raw in (
            "20260131",
            "2026-W05-6",
            "2026-031",
            "2026-1-31",
            "2026-02-30",
            " 2026-01-31",
            20260131,
            None,
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_calendar_date(raw, "d")


if __name__ == "__main__":
    unittest.main()
