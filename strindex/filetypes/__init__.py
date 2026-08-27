from strindex.filetypes import force, iff, pe
from strindex.utils import FileBytearray, Print, Strindex, StrindexSettings

MODULES = (force, pe, iff)


class GenericModule:
	"""
	A class representing a generic module that can be used to extract and patch strings from a filetype.
	"""

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
		return self.module.init(data.copy()) if hasattr(self.module, "init") else data.copy()

	def match(self, data: FileBytearray) -> bool:
		""" Checks if the file is of the target filetype. """
		return self.module.match(self.init(data))

	def create(self, data: FileBytearray, settings: StrindexSettings) -> Strindex:
		""" Creates a Strindex object from the file data. """
		return self.module.create(self.init(data), settings)

	def patch(self, data: FileBytearray, strindex: Strindex) -> FileBytearray:
		""" Patches the file data with the Strindex object. """
		return self.module.patch(self.init(data), strindex)
