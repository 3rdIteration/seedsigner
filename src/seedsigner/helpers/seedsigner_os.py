import os


def is_seedsigner_os_dev_build() -> bool:
    """Return True if running on a developer SeedSignerOS image.

    Developer OS images include additional utilities such as
    ``/usr/bin/microsd_notice.py`` used during boot to load sources
    from an external microSD card. The presence of this file marks a
    development build that is not intended for production use.
    """
    return os.path.exists("/usr/bin/microsd_notice.py")

