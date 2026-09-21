"""Documentation screenshot capture for the fork's smartcard features.

Unlike ``tests/screenshot_generator`` (which renders one frame per View against a
mocked Controller), this suite drives *real* Views and Screens against real JavaCard
applets running in jcardsim, so the captured frames show the actual data the applet
returns -- card UIDs, secret labels, free space, sealed addresses and so on.

It is opt-in: set ``SEEDSIGNER_DOCS_OUT`` to the directory the images should be
written to (e.g. ``docs/img/guide``) and run the suite; without it the whole directory
is ignored by pytest. When jcardsim is unavailable the tests skip cleanly.
"""
