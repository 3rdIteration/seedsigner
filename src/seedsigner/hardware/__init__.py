"""Hardware package exports.

This package intentionally re-exports selected hardware submodules so callers
can patch/import via ``seedsigner.hardware.<module>`` attributes.
"""

from . import battery_hat

__all__ = ["battery_hat"]
