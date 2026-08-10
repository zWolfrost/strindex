import os
import argparse
from strindex.utils import Strindex, StrindexSettings, FileBytearray, PrintWrapper, PrintProgress
from strindex.filetypes import GenericModule


VERSION = "3.10.0"


def create(file_filepath: str, strindex_filepath: str | None, compatible: bool, settings: StrindexSettings) -> str:
	"""
		Calls the create method of the module associated with the file type.
	"""

	print_progress = PrintProgress(2)

	strindex_filepath = strindex_filepath or (os.path.splitext(file_filepath)[0] + "_strindex.txt")

	data = FileBytearray.read(file_filepath)

	STRINDEX = GenericModule(data, settings.force_mode).create(data, settings)

	print_progress(1)

	if compatible:
		STRINDEX.type_order = ["compatible"] * len(STRINDEX.strings)
		for i in range(len(STRINDEX.strings)):
			STRINDEX.strings[i] = [STRINDEX.strings[i], STRINDEX.strings[i]]

	STRINDEX.settings = settings
	STRINDEX.settings.md5 = data.md5

	STRINDEX.write(strindex_filepath)

	print_progress(2)

	return PrintWrapper.print(f'Successfully created strindex file at:\n{strindex_filepath}')


def patch(file_filepath: str, strindex_filepath: str, file_patched_filepath: str | None) -> str:
	"""
		Calls the patch method of the module associated with the file type.
	"""

	print_progress = PrintProgress(5)

	orig_file_filepath_bak = file_filepath + FileBytearray.read(file_filepath).md5_backup_suffix

	print_progress(1)

	if os.path.exists(orig_file_filepath_bak):
		PrintWrapper.print("Detected backup file, patching that instead.")
		data = FileBytearray.read(orig_file_filepath_bak)
	else:
		data = FileBytearray.read(file_filepath)

	print_progress(2)

	STRINDEX = Strindex.read(strindex_filepath)

	if STRINDEX.settings.md5 and STRINDEX.settings.md5 != data.md5:
		PrintWrapper.print("MD5 hash does not match the one the strindex was created for. You may encounter issues.")

	print_progress(3)

	data = GenericModule(data, STRINDEX.settings.force_mode).patch(data, STRINDEX)

	print_progress(4)

	repl_file_filepath_bak = file_filepath + data.md5_backup_suffix

	if not file_patched_filepath:
		os.replace(orig_file_filepath_bak if os.path.exists(orig_file_filepath_bak) else file_filepath, repl_file_filepath_bak)
		file_patched_filepath = file_filepath

	data.write(file_patched_filepath)

	print_progress(5)

	return PrintWrapper.print("File was patched successfully.")


def unpatch(file_filepath: str) -> str:
	"""
		Restores a backup file if it exists.
	"""

	data = FileBytearray.read(file_filepath)

	repl_file_filepath_bak = file_filepath + data.md5_backup_suffix

	if not os.path.exists(repl_file_filepath_bak):
		raise FileNotFoundError("No backup file was found to restore from.")

	os.replace(repl_file_filepath_bak, file_filepath)

	return PrintWrapper.print("File was restored from backup successfully.")


def infer(file_filepath: str, strindex_filepath: str) -> str:
	"""
		List the most common bytes that can prefix or suffix a pointer in a file, as well as the most suitable range to use.
	"""

	infer_output = ""

	flat_list = lambda l: [x for xs in l for x in xs]

	MAX_COUNT = 10
	MAX_LENGTH = 10

	data = FileBytearray.read(file_filepath)

	STRINDEX = Strindex.read(strindex_filepath)

	STRINDEX_OFFSETS = flat_list(STRINDEX.get_offsets)
	STRINDEX_OVERWRITE_AND_ORIGINAL = STRINDEX.get_overwrite_and_original

	def print_affixes(start_fun, end_fun):
		nonlocal infer_output

		got_any = False

		affixes = set()
		length = 1
		while True:
			for offsets in STRINDEX_OFFSETS:
				affixes.add(bytes(data[start_fun(offsets, length) : end_fun(offsets, length)]))

			if len(affixes) >= MAX_COUNT or length >= MAX_LENGTH:
				return got_any

			got_any = True
			infer_output += f"Length {length*2}: " + ", ".join(a.hex() for a in affixes) + "\n"

			affixes.clear()
			length += 1

	if STRINDEX_OFFSETS:
		infer_output += "PREFIXES:\n"
		if not print_affixes(lambda o, l: o - l, lambda o, l: o):
			infer_output += "No suitable prefixes found.\n"

		infer_output += "\nSUFFIXES:\n"
		if not print_affixes(lambda o, l: o + 4, lambda o, l: o + 4 + l):
			infer_output += "No suitable suffixes found.\n"

	if STRINDEX_OVERWRITE_AND_ORIGINAL:
		lowest_range = len(data)
		highest_range = 0

		for offset in data.strings_search_ordered(STRINDEX_OVERWRITE_AND_ORIGINAL):
			if offset is not None:
				lowest_range = min(lowest_range, offset)
				highest_range = max(highest_range, offset)

		infer_output += f"\nRANGE:\n{lowest_range:08x}:{highest_range:08x}"

	return PrintWrapper.print(infer_output)


def update(file_filepath: str, strindex_filepath: str, file_updated_filepath: str | None) -> str:
	"""
		Update a strindex file with newly created pointers.
	"""

	file_updated_filepath = file_updated_filepath or (os.path.splitext(strindex_filepath)[0] + "_updated.txt")

	data = FileBytearray.read(file_filepath)

	STRINDEX = Strindex.read(strindex_filepath)
	STRINDEX_UPDATED = GenericModule(data, STRINDEX.settings.force_mode).create(data, STRINDEX.settings)

	STRINDEX_STRINGS_ORIGINAL = STRINDEX.get_overwrite_and_original

	updated_pointers = 0
	search_index = 0
	print_progress = PrintProgress(len(STRINDEX.strings))
	for index in range(len(STRINDEX.strings)):
		print_progress(index)
		try:
			search_index = STRINDEX_UPDATED.strings.index(STRINDEX_STRINGS_ORIGINAL[index], search_index)
		except ValueError:
			pass
		else:
			if len(STRINDEX.pointers[index]) != len(STRINDEX_UPDATED.pointers[search_index]):
				updated_pointers += 1
				STRINDEX.pointers[index] = STRINDEX_UPDATED.pointers[search_index]

	STRINDEX.write(file_updated_filepath)

	return PrintWrapper.print(f'Created strindex file with {updated_pointers} updated pointer(s) at:\n{file_updated_filepath}')


def filter(strindex_filepath: str, strindex_filter_filepath: str | None) -> str:
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
			if "__compiled__" in globals():
				PrintWrapper.print("Warning: Filtering by language is not supported in compiled builds.")
			else:
				raise ImportError('Please install the "lingua" package (pip install lingua-language-detector) to filter by language.')

		ALL_LANGUAGES = [code for code in IsoCode639_1.__dict__.values() if isinstance(code, IsoCode639_1)]
		SETTINGS_LANGUAGES = [getattr(IsoCode639_1, code.upper()) for code in STRINDEX.settings.among_languages or []]

		detector = LanguageDetectorBuilder.from_iso_codes_639_1(*(SETTINGS_LANGUAGES or ALL_LANGUAGES)).build()

	def is_source_language(string: str) -> bool:
		string_clean = STRINDEX.settings.clean_string(string)
		confidence = detector.compute_language_confidence_values(string_clean)[0]
		return confidence.language.iso_code_639_1 == getattr(IsoCode639_1, STRINDEX.settings.source_language.upper()) and confidence.value > 0.5

	print_progress = PrintProgress(len(STRINDEX.strings))
	for index, string in enumerate(STRINDEX.get_overwrite_and_original):
		valid_language = not STRINDEX.settings.source_language or is_source_language(string)
		valid_length = len(string) >= STRINDEX.settings.min_length
		valid_whitelist = not (STRINDEX.settings.whitelist and any(ch not in STRINDEX.settings.whitelist for ch in string))

		if all([valid_language, valid_length, valid_whitelist]):
			STRINDEX_FILTER.append_strindex_index(STRINDEX, index)

		print_progress(index)

	STRINDEX_FILTER.write(strindex_filter_filepath)

	return PrintWrapper.print(f'Created strindex file with {len(STRINDEX_FILTER.strings)} / {len(STRINDEX.strings)} strings at:\n{strindex_filter_filepath}')


def delta(strindex_full_filepath: str, strindex_diff_filepath: str, strindex_delta_filepath: str | None) -> str:
	"""
		Filters a full strindex file with a delta strindex file, or intersects them.
	"""

	strindex_delta_filepath = strindex_delta_filepath or (os.path.splitext(strindex_full_filepath)[0] + "_delta.txt")

	STRINDEX_1 = Strindex.read(strindex_full_filepath)
	STRINDEX_2 = Strindex.read(strindex_diff_filepath)

	STRINDEX_1_ID = STRINDEX_1.get_identifiers
	STRINDEX_2_ID = STRINDEX_2.get_identifiers

	STRINDEX_DELTA = Strindex()
	STRINDEX_DELTA.full_header = STRINDEX_1.full_header

	search_index = 0
	print_progress = PrintProgress(len(STRINDEX_1.strings))
	for index in range(len(STRINDEX_1.strings)):
		print_progress(index)
		try:
			search_index = STRINDEX_2_ID.index(STRINDEX_1_ID[index], search_index)
		except ValueError:
			STRINDEX_DELTA.append_strindex_index(STRINDEX_1, index)

	STRINDEX_DELTA.write(strindex_delta_filepath)

	return PrintWrapper.print(f'Created delta strindex file with {len(STRINDEX_DELTA.strings)} / {len(STRINDEX_1.strings)} strings at:\n{strindex_delta_filepath}')


def spellcheck(strindex_filepath: str, strindex_spellcheck_filepath: str | None) -> str:
	"""
		Creates a spellcheck file from a strindex file, for the specified language.
	"""

	strindex_spellcheck_filepath = strindex_spellcheck_filepath or (os.path.splitext(strindex_filepath)[0] + "_spellcheck.txt")

	try:
		from language_tool_python import LanguageTool
	except ImportError:
		raise ImportError('Please install the "language-tool-python" package (pip install language-tool-python) to use this feature.')

	STRINDEX = Strindex.read(strindex_filepath)
	STRINDEX_STRINGS_REPLACE = STRINDEX.get_overwrite_and_replace

	if not STRINDEX.settings.target_language:
		raise ValueError('Please specify the target language to spellcheck in the strindex file ("target_language").')

	lang = LanguageTool(STRINDEX.settings.target_language)
	PrintWrapper.print("Created language tool.")

	with open(strindex_spellcheck_filepath, 'w', encoding='utf-8') as f:
		print_progress = PrintProgress(len(STRINDEX_STRINGS_REPLACE))
		for index, string in enumerate(STRINDEX_STRINGS_REPLACE):
			string_clean = STRINDEX.settings.clean_string(string)
			for error in lang.check(string_clean):
				f.write('\n'.join(str(error).split('\n')[-3:]) + '\n')

			print_progress(index)

	return PrintWrapper.print(f'Created spellcheck file at "{strindex_spellcheck_filepath}".')


def main(sysargs=None):
	parser = argparse.ArgumentParser(prog="strindex", description="A command line utility to extract and patch strings of some filetypes, with a focus on compatibility and translation.")

	parser.add_argument("action", type=str, choices=["create", "patch", "unpatch", "infer", "update", "filter", "delta", "spellcheck", "gui"], help="Action to perform.")
	parser.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE, help="One or more files to process.")
	parser.add_argument("-o", "--output", type=str, help="Output file.")

	# create arguments
	parser.add_argument("-f", "--force-mode", action="store_true", help="Force the replacement of strings at the same offset they were found.")
	parser.add_argument("-c", "--compatible", action="store_true", help="Whether to create a strindex file compatible with the previous versions of a program.")
	parser.add_argument("-m", "--min-length", type=int, help="Minimum length of the strings to be included.")
	parser.add_argument("-p", "--prefix-bytes", type=str, action="append", default=[], help="Prefix bytes that can prefix a pointer.")
	parser.add_argument("-s", "--suffix-bytes", type=str, action="append", default=[], help="Suffix bytes that can suffix a pointer.")
	parser.add_argument("-r", "--range", type=str, action="append", default=[], help="Range of the hexadecimal offsets to search for strings, in the format 'start:end'. Can be specified multiple times.")

	parser.add_argument("--version", action="version", version=VERSION, help="Show the version of strindex and exit.")
	parser.add_argument("-v", "--verbose", action="store_true", help="Print full error messages.")
	parser.add_argument("-q", "--quiet", action="store_true", help="Suppress all output except for errors.")

	args = parser.parse_args(sysargs)

	try:
		if not all(os.path.isfile(file) for file in args.files):
			raise FileNotFoundError("One or more files do not exist.")

		if "__compiled__" in globals() and args.action == "spellcheck":
			raise ImportError("Spellchecking is not supported in compiled builds.")

		if args.quiet:
			PrintWrapper.QUIET = True

		if args.action == "gui":
			try:
				from strindex.gui import MainStrindexGUI
			except ModuleNotFoundError:
				raise ImportError('Please install the "PySide6" package (pip install pyside6) to use this feature.')

			MainStrindexGUI()
		else:
			def assert_files_num(n: int):
				assert len(args.files) == n, f"Expected {n} files, got {len(args.files)}."

			match args.action:
				case "create":
					assert_files_num(1)
					create(
						args.files[0],
						args.output,
						args.compatible,
						StrindexSettings(**{
							"force_mode": args.force_mode,
							"min_length": args.min_length,
							"prefix_bytes": args.prefix_bytes,
							"suffix_bytes": args.suffix_bytes,
							"ranges": args.range,
						})
					)
				case "patch":
					assert_files_num(2)
					patch(args.files[0], args.files[1], args.output)
				case "unpatch":
					assert_files_num(1)
					unpatch(args.files[0])
				case "infer":
					assert_files_num(2)
					infer(args.files[0], args.files[1])
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
		PrintWrapper.print("Interrupted by user.")
	except Exception as e:
		if args.verbose:
			raise
		else:
			PrintWrapper.print(f"{type(e).__name__}: {e}")


if __name__ == "__main__":
	main()
