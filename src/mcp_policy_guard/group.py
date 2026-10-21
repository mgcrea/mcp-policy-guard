"""The alternatives label carried by a row filter.

Filters of one rule on the same resource that share a `group` label are OR'ed by the tool;
groups and ungrouped filters still AND. The guard only carries and validates the label (and
joins members with "or" in `scope_notice`); the tool applies it.

The wire field is omitted, never null, when a filter has no group, so a present-but-null
`group` is malformed. A receiver that cannot tell which filters are alternatives would AND
them, which is narrower but not what the policy says, so anything unusable is refused.
"""

from __future__ import annotations

import re

_GROUP_LABEL = re.compile(r"[a-z0-9_-]{1,32}")


def parse_group(raw_filter: dict) -> str | None:
    """The `group` of a wire filter: `None` when absent, `ValueError` when present but malformed."""
    if "group" not in raw_filter:
        return None
    value = raw_filter["group"]
    if not isinstance(value, str) or _GROUP_LABEL.fullmatch(value) is None:
        raise ValueError("filter group must be a string matching [a-z0-9_-]{1,32}")
    return value
