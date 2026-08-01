"""Glob matching.

These cases are the contract shared with the policy backend's own matcher. If the two
disagree, an operator authors a rule that previews one way wherever rules are simulated and
enforces another in production — the worst kind of security bug, because it is invisible
until it matters.
"""

from __future__ import annotations

import pytest

from mcp_guard.matching import glob_matches


class TestLiterals:
    def test_exact_match(self):
        assert glob_matches("dbo.orders", "dbo.orders")

    def test_non_match(self):
        assert not glob_matches("dbo.orders", "dbo.payroll")

    def test_is_case_insensitive(self):
        # Rules are authored as `dbo.Payroll`; SQL identifiers arrive in whatever case the
        # model wrote them.
        assert glob_matches("dbo.Payroll", "DBO.PAYROLL")

    def test_is_anchored_at_both_ends(self):
        assert not glob_matches("orders", "dbo.orders")
        assert not glob_matches("dbo.order", "dbo.orders")


class TestWildcards:
    def test_trailing_wildcard(self):
        assert glob_matches("dbo.payroll*", "dbo.payroll_2024")

    def test_bare_wildcard_matches_everything(self):
        assert glob_matches("*", "anything at all")

    def test_wildcard_matches_the_empty_string(self):
        assert glob_matches("dbo.payroll*", "dbo.payroll")

    def test_leading_wildcard(self):
        assert glob_matches("*.payroll", "hr.payroll")

    def test_interior_wildcard(self):
        assert glob_matches("dbo.*_archive", "dbo.orders_archive")

    def test_multiple_wildcards(self):
        assert glob_matches("*pay*roll*", "hr.PAYcheck.ROLLup")


class TestMetacharacters:
    def test_a_dot_is_literal(self):
        # Every `schema.table` contains one. If `.` stayed a regex wildcard, a rule for
        # `dbo.x` would also cover `dboax` — silently widening the grant.
        assert not glob_matches("dbo.x", "dboax")

    @pytest.mark.parametrize(
        "pattern,value",
        [
            ("a+b", "a+b"),
            ("a(b)c", "a(b)c"),
            ("a|b", "a|b"),
            ("a[b]c", "a[b]c"),
            ("a{2}", "a{2}"),
            ("a^b", "a^b"),
            ("a$b", "a$b"),
            ("a\\b", "a\\b"),
            ("a?b", "a?b"),
        ],
    )
    def test_regex_metacharacters_are_literal(self, pattern, value):
        assert glob_matches(pattern, value)

    def test_a_plus_does_not_repeat(self):
        assert not glob_matches("a+b", "aab")

    def test_a_question_mark_is_not_a_single_char_wildcard(self):
        # Unlike shell globbing. `*` is the ONLY wildcard.
        assert not glob_matches("a?c", "abc")

    def test_patterns_containing_spaces_survive(self):
        # Regression: an earlier implementation substituted a sentinel character for `*`
        # before escaping, which corrupted any pattern containing that sentinel.
        assert glob_matches("my table*", "my table 1")
        assert glob_matches("*my table*", "prefix my table suffix")
