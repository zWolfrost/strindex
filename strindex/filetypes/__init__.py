import importlib
import pkgutil

from strindex.filetypes import *
from strindex.filetypes import force
from strindex.utils import FileBytearray, Print, Strindex, StrindexSettings

MODULES = [
	importlib.import_module(f"{__name__}.{n}") for _, n, _ in
	pkgutil.iter_modules(__path__) if not n.startswith("_")
]


class GenericModule:
	""" A class representing a generic module that can be used to extract and patch strings from a filetype. """

	def __init__(self, data: FileBytearray, force_mode: bool = False):
		if force_mode:
			self.module = force
			Print.debug("Force mode enabled.")
			return

		for module in MODULES:
			self.module = module
			if self.match(data):
				filetype = module.__name__.split(".")[-1]
				Print.debug(f'Detected filetype: "{filetype}".')
				return

		raise NotImplementedError(
			"This file type has no associated module,\n"
			"or the required libraries to handle it are not installed.\n"
			"You can use the --force flag to enable force mode\n"
			"and attempt to extract strings from the file anyway."
		)

	def init(self, data: FileBytearray) -> FileBytearray:
		""" Initializes the file data for the module. """
		data = data.copy()
		data.byte_length = self.module.SETTINGS.default_byte_length
		data.byte_order = self.module.SETTINGS.default_byte_order
		return data

	def match(self, data: FileBytearray) -> bool:
		""" Checks if the file is of the target filetype. """
		return self.module.match(self.init(data))

	def create(self, data: FileBytearray, settings: StrindexSettings, compatible: bool = False) -> Strindex:
		""" Creates a Strindex object from the file data. """
		strindex = self.module.create(self.init(data), settings)

		if self.module.SETTINGS.filter_after_create:
			for i in reversed(range(len(strindex.strings))):
				string = strindex.strings[i].encode("utf-8")
				pointers = [p for p in strindex.pointers[i] if (
					settings.is_in_any_range(p) and
					settings.matches_prefix(data, p) and
					settings.matches_suffix(data, p + len(string))
				)]
				if not (pointers and len(string) >= settings.min_length and settings.is_in_whitelist(string)):
					del strindex.pointers[i]
					del strindex.strings[i]

		if compatible:
			strindex.type_order = ["compatible"] * len(strindex.strings)
			strindex.pointers = [[bool(p) for p in pointers] for pointers in strindex.pointers]
			strindex.strings = [[s, s] for s in strindex.strings]
		else:
			strindex.type_order = ["overwrite"] * len(strindex.strings)

		strindex.settings = settings
		strindex.settings.md5 = data.md5

		return strindex

	def patch(self, data: FileBytearray, strindex: Strindex) -> FileBytearray:
		""" Patches the file data with the Strindex object. """
		return self.module.patch(self.init(data), strindex)
