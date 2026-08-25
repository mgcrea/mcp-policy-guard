"""The package version, and the User-Agent the PDP identifies this guard by.

Separate from `__init__` so `policy` and `snapshot` can import it without a circular import.

**The User-Agent is a wire contract, not a courtesy.** The platform parses it to learn which
guard release answered (`/mcp-policy-guard\\/([\\w.+-]+)/i`) and uses that to decide whether it
may hand this guard a row predicate at all. A guard that reports no version is read as too old
to apply one, and the resources a predicate would have narrowed are denied instead of served
unscoped. Until 0.6.1 no version was sent at all, so that check could never pass: every
row-filtered resource denied, everywhere, with nothing to indicate why.
"""

from __future__ import annotations

import sys

__version__ = "0.6.1"

#: e.g. `mcp-policy-guard/0.6.1 (python/3.13)`
USER_AGENT = f"mcp-policy-guard/{__version__} (python/{sys.version_info.major}.{sys.version_info.minor})"
