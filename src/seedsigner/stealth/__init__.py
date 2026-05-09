"""Stealth boot mode: optional Snake-on-boot with secret unlock combo.

This package MUST NOT import from ``seedsigner.models.seed*`` or
``seedsigner.helpers.keycard*``. The whole point of stealth mode is to
isolate the boot game from any code that handles secrets.
"""
