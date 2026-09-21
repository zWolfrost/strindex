from strindex import core, utils

try:
	from strindex import gui
except ImportError:
	gui = None

__all__ = ["core", "gui", "utils"]
__version__ = "5.1.0"
