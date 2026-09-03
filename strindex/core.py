import argparse
import sys
from pathlib import Path

from strindex.filetypes import ModuleWrapper
from strindex.utils import FileBuffer, Print, Progress, Strindex, StrindexSettings

VERSION = "5.0.0"


def edit_extension(filepath: str, suffix: str) -> str:
	_path = Path(filepath)
	return _path.with_name(_path.stem + suffix).resolve().as_posix()


def create(file_filepath: str, strindex_filepath: str | None, settings: StrindexSettings) -> str:
	""" Calls the create method of the module associated with the file type. """

	Progress.init_global_instance(4)

	strindex_filepath = strindex_filepath or edit_extension(file_filepath, "_strindex.txt")

	data = FileBuffer.read(file_filepath)

	strindex = ModuleWrapper.detect_from_data(data).create(data, settings)

	strindex.write(strindex_filepath)

	return Print.success(f"Successfully created strindex file at\n{strindex_filepath}")


def patch(file_filepath: str, strindex_filepath: str, file_patched_filepath: str | None) -> str:
	""" Calls the patch method of the module associated with the file type. """

	if not hasattr(Progress, "global_instance"):
		Progress.init_global_instance(6)

	backup_filepath = file_filepath + FileBuffer.read(file_filepath).md5_backup_suffix

	if Path(backup_filepath).exists():
		Print.info("Detected backup file, patching that one instead.")
		data = FileBuffer.read(backup_filepath)
	else:
		data = FileBuffer.read(file_filepath)

	strindex = Strindex.read(strindex_filepath)

	data = ModuleWrapper.detect_from_data(data).patch(data, strindex)

	if not file_patched_filepath:
		backup_filepath = backup_filepath if Path(backup_filepath).exists() else file_filepath
		Path(backup_filepath).replace(file_filepath + data.md5_backup_suffix)
		file_patched_filepath = file_filepath

	data.write(file_patched_filepath)

	return Print.success("File was patched successfully.")


def unpatch(file_filepath: str) -> str:
	""" Restores a backup file if it exists. """

	Progress.init_global_instance(1)

	file_md5 = FileBuffer.read(file_filepath).md5_backup_suffix

	backup_filepath = file_filepath + file_md5

	if not Path(backup_filepath).exists():
		raise FileNotFoundError("No backup file was found to restore from.")

	Path(backup_filepath).replace(file_filepath)

	return Print.success("File was restored from backup successfully.")


def infer(file_filepath: str, strindex_filepath: str) -> str:
	"""
		List the most common bytes that can prefix or suffix a pointer in a file,
		as well as the most suitable range to use.
	"""

	Progress.init_global_instance(5)

	infer_output = ""

	def flat_list(lst: list[list[int]]) -> list[int]:
		return [x for xs in lst for x in xs]

	MAX_COUNT = 10
	MAX_LENGTH = 10

	data = FileBuffer.read(file_filepath)

	strindex = Strindex.read(strindex_filepath)

	STRINDEX_OFFSETS = flat_list(strindex.get_offsets)

	def infer_affixes(start_fun, end_fun):
		nonlocal infer_output

		got_any = False

		affixes = set()
		length = 1
		while length <= MAX_LENGTH:
			for offsets in STRINDEX_OFFSETS:
				affixes.add(bytes(data[start_fun(offsets, length) : end_fun(offsets, length)]))

			if len(affixes) >= MAX_COUNT:
				break

			got_any = True
			infer_output += f"Length {length*2:02}: " + ", ".join(a.hex() for a in affixes) + "\n"

			affixes.clear()
			length += 1

		return got_any

	if STRINDEX_OFFSETS:
		infer_output += "[PREFIXES]\n"
		if not infer_affixes(lambda offset, length: offset - length, lambda offset, _: offset):
			infer_output += "No suitable prefixes found.\n"

		infer_output += "\n[SUFFIXES]\n"
		if not infer_affixes(lambda offset, _: offset + 4, lambda offset, length: offset + 4 + length):
			infer_output += "No suitable suffixes found.\n"

		infer_output += f"\n[NARROWEST RANGE]\n{min(STRINDEX_OFFSETS):08x}:{max(STRINDEX_OFFSETS):08x}"

	Progress.global_instance()
	Print.info("")

	return Print.info(infer_output)


def update(
	file_filepath: str,
	strindex_filepath: str,
	strindex_updated_filepath: str | None,
	convert_type: str | None = None
) -> str:
	""" Update a strindex file with newly created pointers and settings. """

	Progress.init_global_instance(6)

	strindex_updated_filepath = strindex_updated_filepath or edit_extension(strindex_filepath, "_updated.txt")

	data = FileBuffer.read(file_filepath)

	strindex = Strindex.read(strindex_filepath)
	strindex_updated = ModuleWrapper.detect_from_data(data).create(data, strindex.settings)

	no_pointers_count = 0
	search_index = 0
	for index in range(len(strindex.strings)):
		try:
			if strindex.type_order[index] == "compatible":
				search_index = strindex_updated.strings.index(strindex.strings[index][0], search_index)
			elif strindex.type_order[index] == "overwrite":
				search_index = strindex_updated.pointers.index(strindex.pointers[index], search_index)
		except ValueError:
			strindex.pointers[index] = []
			no_pointers_count += 1
		else:
			if convert_type == "compatible" and strindex.type_order[index] == "overwrite":
				strindex.type_order[index] = "compatible"
				strindex.strings[index] = [strindex_updated.strings[search_index], strindex.strings[index]]
			elif convert_type == "overwrite" and strindex.type_order[index] == "compatible":
				strindex.type_order[index] = "overwrite"
				strindex.strings[index] = strindex.strings[index][1]
			strindex.pointers[index] = strindex_updated.pointers[search_index]
			search_index += 1

	if no_pointers_count > 0:
		Print.warning(
			f"{no_pointers_count} strings could not be found and therefore\n"
			"will have no pointers in the updated strindex file."
		)

	Progress.global_instance()

	strindex.write(strindex_updated_filepath)

	return Print.success(f"Created updated strindex at\n{strindex_updated_filepath}")


def filter(strindex_filepath: str, strindex_filtered_filepath: str | None) -> str:
	""" Filters a strindex file with respect to length, whitelist and source language. """

	Progress.init_global_instance(4)

	strindex_filtered_filepath = strindex_filtered_filepath or edit_extension(strindex_filepath, "_filtered.txt")

	strindex = Strindex.read(strindex_filepath)
	initial_count = len(strindex.strings)

	if strindex.settings.source_language:
		try:
			from lingua import IsoCode639_1, LanguageDetectorBuilder
		except ImportError:
			if "__compiled__" in globals():
				Print.warning("Filtering by language is not supported in compiled builds.")
			else:
				raise ImportError(
					'Please install the "lingua" package (pip install lingua-language-detector) to filter by language.'
				) from None

		ALL_LANGUAGES = [code for code in vars(IsoCode639_1).values() if isinstance(code, IsoCode639_1)]
		SETTINGS_LANGUAGES = [IsoCode639_1.from_str(code.upper()) for code in strindex.settings.among_languages or []]

		detector = LanguageDetectorBuilder.from_iso_codes_639_1(*(SETTINGS_LANGUAGES or ALL_LANGUAGES)).build()

	Progress.global_instance()

	def is_source_language(string: str) -> bool:
		string_clean = strindex.settings.clean_string(string)
		confidence = detector.compute_language_confidence_values(string_clean)[0]
		isocode_639_1 = IsoCode639_1.from_str(strindex.settings.source_language.upper())
		return confidence.language.iso_code_639_1 == isocode_639_1 and confidence.value > 0.5

	STRINDEX_OVERWRITE_AND_ORIGINAL = strindex.get_overwrite_and_original

	for i in reversed(range(len(STRINDEX_OVERWRITE_AND_ORIGINAL))):
		string = STRINDEX_OVERWRITE_AND_ORIGINAL[i]
		valid_language = not strindex.settings.source_language or is_source_language(string)
		valid_length = len(string.encode("utf-8")) >= strindex.settings.min_length
		valid_whitelist = strindex.settings.is_in_whitelist(string)

		if not all([valid_language, valid_length, valid_whitelist]):
			strindex.delete_index(i)

	Progress.global_instance()

	strindex.write(strindex_filtered_filepath)

	return Print.success(
		f"Created strindex file with {len(strindex.strings)} strings out of {initial_count} at\n"
		f"{strindex_filtered_filepath}"
	)


def delta(strindex_full_filepath: str, strindex_diff_filepath: str, strindex_delta_filepath: str | None) -> str:
	""" Filters a full strindex file with a delta strindex file, or intersects them. """

	Progress.init_global_instance(4)

	strindex_delta_filepath = strindex_delta_filepath or edit_extension(strindex_full_filepath, "_delta.txt")

	strindex_1 = Strindex.read(strindex_full_filepath)
	strindex_2 = Strindex.read(strindex_diff_filepath)

	initial_count = len(strindex_1.strings)

	strindex_1_ids = strindex_1.get_identifiers
	strindex_2_ids = strindex_2.get_identifiers

	search_index = 0
	for index in range(len(strindex_1.strings)):
		try:
			search_index = strindex_2_ids.index(strindex_1_ids[index], search_index)
		except ValueError:
			pass
		else:
			strindex_1.pointers[index] = []
			search_index += 1

	for i in reversed(range(len(strindex_1.strings))):
		if not strindex_1.pointers[i]:
			strindex_1.delete_index(i)

	Progress.global_instance()

	strindex_1.write(strindex_delta_filepath)

	return Print.success(
		f"Created delta strindex file with {len(strindex_1.strings)} strings out of {initial_count} at\n"
		f"{strindex_delta_filepath}"
	)


def spellcheck(strindex_filepath: str, strindex_spellcheck_filepath: str | None) -> str:
	""" Creates a spellcheck file from a strindex file, for the specified language. """

	strindex_spellcheck_filepath = strindex_spellcheck_filepath or edit_extension(strindex_filepath, "_spellcheck.txt")

	try:
		from language_tool_python import LanguageTool
	except ImportError:
		raise ImportError(
			'Please install the "language-tool-python" package (pip install language-tool-python) to use this feature.'
		) from None

	strindex = Strindex.read(strindex_filepath)

	if not strindex.settings.target_language:
		raise ValueError(
			'Please specify the target language to spellcheck in the strindex file header ("target_language").'
		)

	lang = LanguageTool(strindex.settings.target_language)
	Print.debug("Created language tool.")

	Progress.init_global_instance(len(strindex.strings), 1)

	with Path(strindex_spellcheck_filepath).open("w", encoding="utf-8") as f:
		for i, string in enumerate(strindex.get_overwrite_and_replace, start=1):
			Progress.global_instance(i)
			string_clean = strindex.settings.clean_string(string)
			f.writelines("\n".join(str(error).split("\n")[-3:]) + "\n" for error in lang.check(string_clean))

	return Print.success(f"Created spellcheck file at\n{strindex_spellcheck_filepath}")


def help_whitelist():
	prnt = Print.info("Available whitelist character sets (LEAVE EMPTY FOR NO FILTERING):\n", end="")
	for key, value in StrindexSettings.CHARACTER_SETS.items():
		prnt += Print.info(f'\n"{key}":', end="")
		if key == "_default":
			prnt += Print.info(" (enabled by default)", end="")
		prnt += Print.debug(f"\n{repr(value)[1:-1]}\n", end="")
	return prnt


def main(sysargs=None):
	parser = argparse.ArgumentParser(
		prog="strindex",
		exit_on_error=False,
		description=(
			"A command line utility that allows you to easily extract, list and patch "
			"the strings embedded in a few filetypes. "
		)
	)

	parser.add_argument("action", type=str, nargs=argparse.OPTIONAL,
		choices=["create", "patch", "unpatch", "infer", "update", "filter", "delta", "spellcheck", "gui"],
		help="Action to perform.")
	parser.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE, help="One or more files to process.")
	parser.add_argument("-o", "--output", type=str, help="Output file.")
	parser.add_argument("--version", action="version", version=VERSION, help="Show the version of strindex and exit.")

	# Strindex create writing settings
	parser.add_argument("-C", "--compatible", action="store_true",
		help="Whether to create a strindex file compatible with the previous versions of a program.")
	parser.add_argument("-R", "--references", action="store_true",
		help="Whether to add string references comments to the strindex file.")

	# Strindex create header settings
	parser.add_argument("-f", "--force-mode", action="store_true",
		help="Force the replacement of strings at the same offset they were found.")
	parser.add_argument("-m", "--min-length", default=3, type=int,
		help="Minimum length of the strings to be included.")
	parser.add_argument("-p", "--prefix-bytes", type=str, action="append", default=[],
		help="Prefix bytes that can prefix a pointer.")
	parser.add_argument("-s", "--suffix-bytes", type=str, action="append", default=[],
		help="Suffix bytes that can suffix a pointer.")
	parser.add_argument("-r", "--range", type=str, action="append", default=[],
		help=("Ranges of offsets to consider for searching pointers, in the format 'start:end'."
			"Can be specified multiple times."))
	parser.add_argument("-w", "--whitelist", type=str, action="append", default=[],
		help="Character sets to whitelist for filtering strings. Can be specified multiple times.")

	# Strindex update settings
	to_type_parser = parser.add_mutually_exclusive_group()
	to_type_parser.add_argument("--convert-to-compatible", action="store_true")
	to_type_parser.add_argument("--convert-to-overwrite", action="store_true")

	parser.add_argument("-v", "--verbose", action="store_true", help="Print full error messages.")
	parser.add_argument("-q", "--quiet", action="store_true", help="Suppress all output except for errors.")

	try:
		Print.quiet_mode = False

		args = parser.parse_args(sysargs)

		Print.quiet_mode = args.quiet
		Print.color_mode = sys.stdout.isatty()

		if "help" in args.whitelist:
			help_whitelist()
			return

		if args.action is None:
			raise ValueError("No action specified. Use -h / --help to see the available actions.")

		if not all(Path(file).is_file() for file in args.files):
			raise FileNotFoundError("One or more specified files do not exist.")

		if "__compiled__" in globals() and args.action == "spellcheck":
			raise ImportError("Spellchecking is not supported in compiled builds.")

		if args.action == "gui":
			try:
				from strindex.gui import MainStrindexGUI
			except ModuleNotFoundError:
				raise ImportError(
					'Please install the "PySide6" package (pip install pyside6) to use this feature.'
				) from None

			MainStrindexGUI()
		else:
			def assert_files_num(n: int):
				assert len(args.files) == n, \
					f'Expected {n} file(s) for "{args.action}" action, got {len(args.files)}.'

			match args.action:
				case "create":
					assert_files_num(1)
					create(
						args.files[0], args.output,
						StrindexSettings(
							_compatible = args.compatible,
							_references = args.references,
							force_mode = args.force_mode,
							min_length = args.min_length,
							prefix_bytes = args.prefix_bytes,
							suffix_bytes = args.suffix_bytes,
							ranges = args.range,
							whitelist = args.whitelist
						)
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
					update(
						args.files[0], args.files[1], args.output,
						convert_type = (
							"overwrite" if args.convert_to_overwrite else
							"compatible" if args.convert_to_compatible else None
						)
					)
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
		Print.error("Interrupted by user.")
	except Exception as e:
		if "args" in locals() and args.verbose:
			raise
		Print.error(f"[{type(e).__name__}] {e}\nPlease use -v / --verbose to see the full traceback.")


if __name__ == "__main__":
	main()
