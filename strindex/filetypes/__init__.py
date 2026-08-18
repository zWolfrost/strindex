from strindex.utils import FileBytearray, Strindex, StrindexSettings, Print
from strindex.filetypes import force, pe, iff

MODULES = (force, pe, iff)


class GenericModule():
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

	def match(self, data: FileBytearray) -> bool:
		""" Checks if the file is of the target filetype. """
		return self.module.match(data.copy())

	def create(self, data: FileBytearray, settings: StrindexSettings) -> Strindex:
		""" Creates a Strindex object from the file data. """
		return self.module.create(data.copy(), settings)

	def patch(self, data: FileBytearray, strindex: Strindex) -> FileBytearray:
		""" Patches the file data with the Strindex object. """
		return self.module.patch(data.copy(), strindex)
