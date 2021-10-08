from .checker import DNSBLChecker

try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata

__version__ = importlib_metadata.version(__name__)

__all__ = ["DNSBLChecker"]
