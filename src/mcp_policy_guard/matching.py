"""Resource pattern matching.

These semantics are a **contract with the policy backend's own matcher**. Wherever an
operator previews or simulates a rule, that preview and this guard must agree about whether
`dbo.Payroll*` covers `dbo.payroll_2024` — otherwise a rule previews one way and enforces
another. `test_matching.py` pins the shared cases; keep the two implementations in step.
"""

from __future__ import annotations

import re
from functools import lru_cache


@lru_cache(maxsize=1024)
def _compiled(pattern: str) -> re.Pattern[str]:
    # Split on the wildcard FIRST, then escape each literal segment. Escaping first and
    # substituting a sentinel afterwards breaks on any pattern containing that sentinel.
    source = "^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$"
    return re.compile(source, re.IGNORECASE)


def glob_matches(pattern: str, value: str) -> bool:
    """Case-insensitive glob where `*` is the only wildcard.

    Everything else is escaped, so a resource name containing regex metacharacters — and
    `.` is in every `schema.table` — can never widen the match. `dbo.x` must not match
    `dboax`.
    """
    return _compiled(pattern).fullmatch(value) is not None
