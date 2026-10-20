"""The join path carried by an `in_via` row filter.

`in_via` narrows a table by a column it does not hold: the tool follows up to three hops
(`table.key` joined to the previous hop's `column`) and compares the last hop's column with
the values. The guard only carries and validates the path; the tool applies it.

Validation is strict because a receiver that cannot apply a path must refuse, and a path
quietly truncated or defaulted would be applied as a different, wider filter.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_VIA_HOPS = 3
IN_VIA = "in_via"


@dataclass(frozen=True)
class ViaHop:
    """One join step: rows of `table` whose `column` is in the next level, yielding `key`."""

    table: str
    key: str
    column: str


def parse_via(raw: object) -> tuple[ViaHop, ...]:
    """A `via` list off the wire, or `ValueError` if it is anything but 1-3 well-formed hops."""
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_VIA_HOPS:
        raise ValueError(f"in_via path must be a list of 1-{MAX_VIA_HOPS} hops")
    hops: list[ViaHop] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("in_via hop must be an object")
        fields: dict[str, str] = {}
        for name in ("table", "key", "column"):
            value = entry.get(name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"in_via hop needs a non-empty string {name!r}")
            fields[name] = value
        hops.append(ViaHop(**fields))
    return tuple(hops)


def via_for_operator(operator: str, raw_filter: dict) -> tuple[ViaHop, ...]:
    """The path a filter must carry: required for `in_via`, forbidden for any other operator."""
    if operator == IN_VIA:
        return parse_via(raw_filter.get("via"))
    if "via" in raw_filter:
        raise ValueError(f"operator {operator!r} must not carry a via path")
    return ()
