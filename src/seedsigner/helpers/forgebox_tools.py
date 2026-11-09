"""Resolve the OS-provided ForgeBox protocol; never execute code from microSD."""
import importlib.util
import os
from seedsigner.helpers.secure_boot_tools import candidate_dirs


def find_path():
    for directory in candidate_dirs():
        path = os.path.join(directory, 'forgebox_sign.py')
        if os.path.isfile(path):
            return path
    return None


def is_available():
    return find_path() is not None


def load():
    path = find_path()
    if path is None:
        raise RuntimeError('ForgeBox signing tools are not installed in this OS')
    spec = importlib.util.spec_from_file_location('seedsigner_os_forgebox', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
