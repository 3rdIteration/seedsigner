#!/usr/bin/env python

import argparse
import logging
import os
import sys

from seedsigner.controller import Controller
from seedsigner.views.view import Destination

logger = logging.getLogger(__name__)

DEFAULT_MODULE_LOG_LEVELS = {
    "PIL": logging.WARNING,
    # "seedsigner.gui.toast": logging.DEBUG,  # example of more specific submodule logging config
}


def main(sys_argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-l",
        "--loglevel",
        choices=list((logging._nameToLevel.keys())),
        default="INFO",
        type=str,
        help=(
            "Set the log level (default: %(default)s), WARNING: changing the log level "
            "to something more verbose than %(default)s may result in unwanted data "
            "being written to stderr"
        ),
    )
    parser.add_argument(
        "--iotest",
        action="store_true",
        help="Launch directly into the I/O test screen",
    )
    parser.add_argument(
        "--testing-build",
        action="store_true",
        help="Launch with the testing build's Home menu (I/O Test, Test Smartcard, Flash Applet, Settings)",
    )

    args = parser.parse_args(sys_argv)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.getLevelName(args.loglevel))
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)8s [%(name)s %(funcName)s (%(lineno)d)]: %(message)s")
    )
    root_logger.addHandler(console_handler)

    # Set log levels for specific modules
    for module, level in DEFAULT_MODULE_LOG_LEVELS.items():
        logging.getLogger(module).setLevel(level)

    logger.info(f"Starting SeedSigner with: {args.__dict__}")

    if args.testing_build:
        os.environ["SEEDSIGNER_TESTING_BUILD"] = "1"

    # Get the one and only Controller instance and start our main loop
    initial_destination = None
    if args.iotest:
        from seedsigner.views.settings_views import IOTestView

        initial_destination = Destination(IOTestView)

    Controller.get_instance().start(
        initial_destination=initial_destination,
        skip_startup_interstitials=args.iotest,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
