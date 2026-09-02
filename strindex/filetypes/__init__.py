import functools
import importlib
import pkgutil

from strindex.filetypes import force
from strindex.utils import FileBuffer, ModuleProtocol, Print, Strindex, StrindexSettings

MODULES = [
	importlib.import_module(f"{__name__}.{name}") for _, name, _ in
	pkgutil.iter_modules(__path__) if not name.startswith("_")
]

def use_force_module(force_mode):
	def decorator(func):
		@functools.wraps(func)
		def wrapper(self: ModuleWrapper, *args, **kwargs):
			if force_mode(*args, **kwargs):
				prev_module = self.module
				self.module = force
				try:
					return func(self, *args, **kwargs)
				finally:
					self.module = prev_module
			else:
				if self.module is None:
					raise NotImplementedError(
						"This file type has no associated module,\n"
						"or the required libraries to handle it are not installed.\n"
						"You can use the --force flag to enable force mode\n"
						"and attempt to extract strings from the file anyway."
					)
				return func(self, *args, **kwargs)

		return wrapper
	return decorator

class ModuleWrapper:
	""" A class representing a generic module that can be used to extract and patch strings from a filetype. """

	module: ModuleProtocol | None

	def __init__(self, module: ModuleProtocol | None = None):
		self.module = module

	@classmethod
	def detect_from_data(cls, data: FileBuffer):
		generic_module = cls()

		for module in MODULES:
			generic_module.module = module
			if generic_module.match(data):
				filetype = module.__name__.split(".")[-1]
				Print.info(f'Detected filetype: "{filetype}".')
				break
		else:
			generic_module.module = None

		return generic_module

	def init(self, data: FileBuffer) -> FileBuffer:
		""" Initializes the file data for the module. """
		data = data.copy()
		data.cursor = 0
		data.byte_length = self.module.SETTINGS.default_byte_length
		data.byte_order = self.module.SETTINGS.default_byte_order
		return data

	def match(self, data: FileBuffer) -> bool:
		""" Checks if the file is of the target filetype. """
		return self.module.match(self.init(data)) if self.module else False

	@use_force_module(lambda _, settings: settings.force_mode)
	def create(self, data: FileBuffer, settings: StrindexSettings) -> Strindex:
		""" Creates a Strindex object from the file data. """
		empty_strindex = Strindex()
		empty_strindex.settings = settings
		strindex = self.module.create(self.init(data), empty_strindex)

		if self.module.SETTINGS.filter_after_create:
			starting_length = len(strindex.strings)

			for i in reversed(range(len(strindex.strings))):
				string_length = len(strindex.strings[i].encode("utf-8"))
				pointers = [p for p in strindex.pointers[i] if (
					settings.is_in_any_range(p) and
					settings.matches_prefix(data, p) and
					settings.matches_suffix(data, p + string_length)
				)]
				if not (
					pointers and
					string_length >= settings.min_length and
					settings.is_in_whitelist(strindex.strings[i])
				):
					del strindex.pointers[i]
					del strindex.strings[i]

			Print.debug(f"Filtered down to {len(strindex.strings)} / {starting_length} strings.")

		if settings._compatible:
			strindex.type_order = ["compatible"] * len(strindex.strings)
			strindex.pointers = [[bool(p) for p in pointers] for pointers in strindex.pointers]
			strindex.strings = [[s, s] for s in strindex.strings]
		else:
			strindex.type_order = ["overwrite"] * len(strindex.strings)

		strindex.settings = settings
		strindex.settings.md5 = data.md5

		return strindex

	@use_force_module(lambda _, strindex: strindex.settings.force_mode)
	def patch(self, data: FileBuffer, strindex: Strindex) -> FileBuffer:
		""" Patches the file data with the Strindex object. """
		return self.module.patch(self.init(data), strindex)
