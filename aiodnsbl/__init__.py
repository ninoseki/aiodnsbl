import importlib.metadata as importlib_metadata

from .checker import DNSBLChecker  # noqa: F401

__version__ = importlib_metadata.version(__name__)
