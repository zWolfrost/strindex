import os, argparse
from strindex.utils import PrintProgress, Strindex, StrindexSettings, FileBytearray
from strindex.filetypes import MODULES


def get_module_methods(data: FileBytearray, action: str) -> dict:
	"""
		Returns the methods of the module associated with the file type.
	"""

	for module in MODULES:
		if module.validate(data):
			print(f'Detected filetype: "{module.__name__.split(".")[-1]}".')
			assert action in module.__dict__, f"Action '{action}' is not available for this file type."
			return module.__dict__[action]

	raise ValueError("This file type has no associated module, or the required libraries to handle it are not installed.")


def create(file_filepath: str, strindex_filepath: str, compatible: bool, settings: StrindexSettings):
	"""
		Calls the create method of the module associated with the file type.
	"""

	strindex_filepath = strindex_filepath or (os.path.splitext(file_filepath)[0] + "_strindex.txt")

	data = FileBytearray(open(file_filepath, 'rb').read())

	STRINDEX: Strindex = get_module_methods(data, "create")(data, settings)

	if compatible:
		STRINDEX.type_order = ["compatible"] * len(STRINDEX.strings)
		for i in range(len(STRINDEX.strings)):
			STRINDEX.strings[i] = [STRINDEX.strings[i], STRINDEX.strings[i]]

	STRINDEX.settings = settings
	STRINDEX.settings.md5 = data.md5

	STRINDEX.write(strindex_filepath)

	print("Created strindex file.")

def patch(file_filepath: str, strindex_filepath: str, file_patched_filepath: str):
	"""
		Calls the patch method of the module associated with the file type.
	"""

	file_filepath_bak = file_filepath + '.bak'

	data = FileBytearray(open(file_filepath_bak if os.path.exists(file_filepath_bak) else file_filepath, 'rb').read())

	STRINDEX = Strindex.read(strindex_filepath)

	if STRINDEX.settings.md5 and STRINDEX.settings.md5 != data.md5:
		print("MD5 hash does not match the one the strindex was created for. You may encounter issues.")

	data: FileBytearray = get_module_methods(data, "patch")(data, STRINDEX)

	if not file_patched_filepath:
		if not os.path.exists(file_filepath_bak):
			os.rename(file_filepath, file_filepath_bak)
		file_patched_filepath = file_filepath

	open(file_patched_filepath, 'wb').write(data)

	print("File was patched successfully.")

def update(file_filepath: str, strindex_filepath: str, file_updated_filepath: str):
	"""
		Update a strindex file with newly created pointers.
	"""

	file_updated_filepath = file_updated_filepath or (os.path.splitext(strindex_filepath)[0] + "_updated.txt")

	data = FileBytearray(open(file_filepath, 'rb').read())

	STRINDEX = Strindex.read(strindex_filepath)
	STRINDEX_UPDATED: Strindex = get_module_methods(data, "create")(data, STRINDEX.settings)

	STRINDEX_STRINGS_FLAT_ORIGINAL = STRINDEX.get_strings_flat_original

	updated_pointers = 0
	search_index = 0
	for index in range(len(STRINDEX.strings)):
		try:
			search_index = STRINDEX_UPDATED.strings.index(STRINDEX_STRINGS_FLAT_ORIGINAL[index], search_index)
		except ValueError:
			pass
		else:
			if len(STRINDEX.pointers[index]) != len(STRINDEX_UPDATED.pointers[search_index]):
				updated_pointers += 1
				STRINDEX.pointers[index] = STRINDEX_UPDATED.pointers[search_index]

	STRINDEX.write(file_updated_filepath)

	print(f"Created strindex file with {updated_pointers} updated pointer(s).")

def filter(strindex_filepath: str, strindex_filter_filepath: str):
	"""
		Filters a strindex file with respect to length, whitelist and source language.
	"""

	strindex_filter_filepath = strindex_filter_filepath or (os.path.splitext(strindex_filepath)[0] + "_filtered.txt")

	STRINDEX = Strindex.read(strindex_filepath)
	STRINDEX_FILTER = Strindex()
	STRINDEX_FILTER.full_header = STRINDEX.full_header

	if STRINDEX.settings.source_language:
		try:
			from lingua import LanguageDetectorBuilder, IsoCode639_1
		except ImportError:
			raise ImportError("Please install the 'lingua' package (pip install lingua-language-detector) to filter by language.")

		ALL_LANGUAGES = [code for code in IsoCode639_1.__dict__.values() if isinstance(code, IsoCode639_1)]
		SETTINGS_LANGUAGES = [getattr(IsoCode639_1, code.upper()) for code in STRINDEX.settings.among_languages or []]

		detector = LanguageDetectorBuilder.from_iso_codes_639_1(*(SETTINGS_LANGUAGES or ALL_LANGUAGES)).build()

	def is_source_language(string: str) -> bool:
		string_clean = STRINDEX.settings.clean_string(string)
		confidence = detector.compute_language_confidence_values(string_clean)[0]
		return confidence.language.iso_code_639_1 == getattr(IsoCode639_1, STRINDEX.settings.source_language.upper()) and confidence.value > 0.5

	print_progress = PrintProgress(len(STRINDEX.strings))
	for index, (string, type) in enumerate(zip(STRINDEX.strings, STRINDEX.type_order)):
		actual_string = string[0] if type == "compatible" else string

		valid_language = not STRINDEX.settings.source_language or is_source_language(actual_string)
		valid_length = len(actual_string) >= STRINDEX.settings.min_length
		valid_whitelist = not STRINDEX.settings.whitelist or not any(ch not in STRINDEX.settings.whitelist for ch in actual_string)

		if all([valid_language, valid_length, valid_whitelist]):
			STRINDEX_FILTER.append_strindex_index(STRINDEX, index)

		print_progress(index)

	STRINDEX_FILTER.write(strindex_filter_filepath)
	print(f"Created strindex file with {len(STRINDEX_FILTER.strings)} / {len(STRINDEX.strings)} strings.")

def delta(strindex_full_filepath: str, strindex_diff_filepath: str, strindex_delta_filepath: str):
	"""
		Filters a full strindex file with a delta strindex file, or intersects them.
	"""

	strindex_delta_filepath = strindex_delta_filepath or (os.path.splitext(strindex_full_filepath)[0] + "_delta.txt")

	STRINDEX_1 = Strindex.read(strindex_full_filepath)
	STRINDEX_2 = Strindex.read(strindex_diff_filepath)

	STRINDEX_1_FLAT_ORIGINAL = STRINDEX_1.get_strings_flat_original
	STRINDEX_2_FLAT_ORIGINAL = STRINDEX_2.get_strings_flat_original

	STRINDEX_DELTA = Strindex()
	STRINDEX_DELTA.full_header = STRINDEX_1.full_header

	search_index = 0
	for index in range(len(STRINDEX_1.strings)):
		try:
			search_index = STRINDEX_2_FLAT_ORIGINAL.index(STRINDEX_1_FLAT_ORIGINAL[index], search_index)
		except ValueError:
			STRINDEX_DELTA.append_strindex_index(STRINDEX_1, index)

	STRINDEX_DELTA.write(strindex_delta_filepath)
	print(f"Created delta strindex file with {len(STRINDEX_DELTA.strings)} / {len(STRINDEX_1.strings)} strings.")

def spellcheck(strindex_filepath: str, strindex_spellcheck_filepath: str):
	"""
		Creates a spellcheck file from a strindex file, for the specified language.
	"""

	strindex_spellcheck_filepath = strindex_spellcheck_filepath or (os.path.splitext(strindex_filepath)[0] + "_spellcheck.txt")

	try:
		from language_tool_python import LanguageTool
	except ImportError:
		raise ImportError("Please install the 'language-tool-python' package (pip install language-tool-python) to use this feature.")

	STRINDEX = Strindex.read(strindex_filepath)
	STRINDEX_FLAT_REPLACE = STRINDEX.get_strings_flat_replace

	if not STRINDEX.settings.target_language:
		raise ValueError("Please specify the target language to spellcheck in the strindex file ('target_language').")

	lang = LanguageTool(STRINDEX.settings.target_language)
	print("Created language tool.")

	with open(strindex_spellcheck_filepath, 'w', encoding='utf-8') as f:
		print_progress = PrintProgress(len(STRINDEX_FLAT_REPLACE))
		for index, string in enumerate(STRINDEX_FLAT_REPLACE):
			string_clean = STRINDEX.settings.clean_string(string)
			for error in lang.check(string_clean):
				f.write('\n'.join(str(error).split('\n')[-3:]) + '\n')

			print_progress(index)
	print("Spellchecked strindex file.")


def create_gui():
	from strindex.utils import StrindexGUI

	class CreateGUI(StrindexGUI):
		def setup(self):
			self.create_file_selection(line_text="*Select a file"),

			self.create_lineedit("Minimum length of strings")
			self.create_padding(1)

			self.create_lineedit("Prefix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424")
			self.create_padding(1)

			self.create_lineedit("Suffix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424")
			self.create_padding(1)

			self.create_checkbox("Compatible Mode")
			self.create_padding(1)

			self.create_action_button(
				text="Create strindex", progress_text="Creating... (2-step) %p%", complete_text="Strindex created successfully.",
				callback=lambda file, length, prefix, suffix, comp: create(
					file, None, comp, StrindexSettings(**{
						"min_length": length,
						"prefix_bytes": prefix.split(","),
						"suffix_bytes": suffix.split(",")
					})
				)
			)
			self.create_padding(1)

			self.create_grid_layout(2).setColumnStretch(0, 1)

			self.set_window_properties(title="Strindex Create")

	StrindexGUI.execute(CreateGUI)

def patch_gui():
	from strindex.utils import StrindexGUI

	class PatchGUI(StrindexGUI):
		def setup(self):
			self.create_file_selection(line_text="*Select a file to patch")
			self.create_strindex_selection(line_text="*Select a strindex file")

			self.create_action_button(
				text="Patch file", progress_text="Patching... %p%", complete_text="File patched successfully.",
				callback=lambda file, strdex: patch(file, strdex, None)
			)
			self.create_padding(1)

			self.create_grid_layout(2).setColumnStretch(0, 1)

			self.set_window_properties(title="Strindex Patch")

	StrindexGUI.execute(PatchGUI)


def main(sysargs=None):
	parser = argparse.ArgumentParser(prog="strindex", description="A command line utility to extract and patch strings of some filetypes, with a focus on compatibility and translation.")

	parser.add_argument("action", type=str, choices=["create", "patch", "update", "filter", "delta", "spellcheck"], help="Action to perform.")
	parser.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE, help="One or more files to process.")
	parser.add_argument("-o", "--output", type=str, help="Output file.")
	parser.add_argument("-g", "--gui", action="store_true", help="Enable GUI mode.")

	# create arguments
	parser.add_argument("-c", "--compatible", action="store_true", help="Whether to create a strindex file compatible with the previous versions of a program.")
	parser.add_argument("-m", "--min-length", type=int, help="Minimum length of the strings to be included.")
	parser.add_argument("-p", "--prefix-bytes", type=str, action="append", default=[], help="Prefix bytes that can prefix a pointer.")
	parser.add_argument("-s", "--suffix-bytes", type=str, action="append", default=[], help="Suffix bytes that can suffix a pointer.")

	parser.add_argument("--version", action="version", version="3.6.0")
	parser.add_argument("-v", "--verbose", action="store_true", help="Print full error messages.")

	args = parser.parse_args(sysargs)

	try:
		if not all([os.path.isfile(file) for file in args.files]):
			raise FileNotFoundError("One or more files do not exist.")

		if args.gui:
			try:
				from strindex.utils import StrindexGUI
			except ImportError:
				raise ImportError("Please install the 'PySide6' package (pip install pyside6) to use this feature.")

			match args.action:
				case "create":
					create_gui()
				case "patch":
					patch_gui()
				case _:
					raise NotImplementedError("GUI mode is not available for this action.")
		else:
			def assert_files_num(n: int) -> tuple[bool, str]:
				assert len(args.files) == n, f"Expected {n} files, got {len(args.files)}."

			match args.action:
				case "create":
					assert_files_num(1)
					create(args.files[0], args.output, args.compatible,
						StrindexSettings(**{
							"min_length": args.min_length,
							"prefix_bytes": args.prefix_bytes,
							"suffix_bytes": args.suffix_bytes
						})
					)
				case "patch":
					assert_files_num(2)
					patch(args.files[0], args.files[1], args.output)
				case "update":
					assert_files_num(2)
					update(args.files[0], args.files[1], args.output)
				case "filter":
					assert_files_num(1)
					filter(args.files[0], args.output)
				case "delta":
					assert_files_num(2)
					delta(args.files[0], args.files[1], args.output)
				case "spellcheck":
					assert_files_num(1)
					spellcheck(args.files[0], args.output)
	except KeyboardInterrupt:
		print("Interrupted by user.")
	except Exception as e:
		if args.verbose:
			raise
		else:
			print(f"{type(e).__name__}: {e}")

if __name__ == "__main__":
	main()
