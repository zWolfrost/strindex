from strindex.utils import FileBytearray, Strindex, StrindexSettings
from strindex.filetypes import pe, iff

class GenericModule():
	"""
	A class representing a generic module that can be used to extract and patch strings from a filetype.
	"""

	def __init__(self, data: FileBytearray):
		MODULES = [pe, iff]

		for module in MODULES:
			self.module = module
			if self.validate(data):
				module.FILETYPE = module.__name__.split(".")[-1]
				print(f'Detected filetype: "{module.FILETYPE}".')
				return

		raise NotImplementedError("This file type has no associated module, or the required libraries to handle it are not installed.")

	def __getattribute__(self, action):
		module = object.__getattribute__(self, "module")
		if action not in dir(module):
			raise NotImplementedError(f"Action '{action}' is not available for module '{module.FILETYPE}'.")
		return getattr(module, action)

	def validate(self, data: FileBytearray) -> bool:
		""" Checks if the file is of the target filetype. """
		pass

	def create(self, data: FileBytearray, settings: StrindexSettings) -> Strindex:
		""" Creates a Strindex object from the file data. """
		pass

	def patch(self, data: FileBytearray, strindex: Strindex) -> FileBytearray:
		""" Patches the file data with the Strindex object. """
		pass
