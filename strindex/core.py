import argparse
import sys
from pathlib import Path

from strindex.filetypes import ModuleWrapper
from strindex.utils import FileBuffer, Print, Progress, Strindex, StrindexSettings

VERSION = "5.0.0"


def edit_extension(filepath: str, suffix: str) -> str:
	_path = Path(filepath)
	return _path.with_name(_path.stem + suffix).resolve().as_posix()


def gui() -> None:
	"""
	Open strindex in GUI mode.
	"""

	try:
		from strindex.gui import MainStrindexGUI
	except ModuleNotFoundError:
		raise ImportError(
			'Please install the "PySide6" package (pip install pyside6) to use this feature.'
		) from None

	MainStrindexGUI()


def create(file_filepath: str, strindex_filepath: str | None, settings: StrindexSettings) -> str:
	"""
	Create a list of string replacement instructions (a strindex file)
	extracting them from a file.
	"""

	Progress.init_global_instance(4)

	strindex_filepath = strindex_filepath or edit_extension(file_filepath, "_strindex.txt")

	data = FileBuffer.read(file_filepath)

	strindex = ModuleWrapper.detect_from_data(data).create(data, settings)

	strindex.write(strindex_filepath)

	return Print.success(f"Successfully created strindex file at\n{strindex_filepath}")


def patch(file_filepath: str, strindex_filepath: str, file_patched_filepath: str | None) -> str:
	"""
	Patch a file using a strindex, or, in other words,
	replace strings in the file following the strindex instructions.
	"""

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
	"""
	Unpatch a file that was patched with a strindex,
	using the backup file that's created by default.
	"""

	Progress.init_global_instance(1)

	file_md5 = FileBuffer.read(file_filepath).md5_backup_suffix

	backup_filepath = file_filepath + file_md5

	if not Path(backup_filepath).exists():
		raise FileNotFoundError("No backup file was found to restore from.")

	Path(backup_filepath).replace(file_filepath)

	return Print.success("File was restored from backup successfully.")


def update(
	file_filepath: str,
	strindex_filepath: str,
	strindex_updated_filepath: str | None,
	convert_type: str | None = None
) -> str:
	"""
	Update a strindex file pointers'
	with another version of a file.
	"""

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


def infer(file_filepath: str, strindex_filepath: str) -> str:
	"""
	Infer the most suitable values for
	"prefix_bytes", "suffix_bytes" and "range"
	given an already-filtered strindex.
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


def filter(strindex_filepath: str, strindex_filtered_filepath: str | None) -> str:
	"""
	Filter a strindex by detected language, wordlist or length.
	Those can be specified in the strindex settings.
	"""

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


def diff(strindex_1_filepath: str, strindex_2_filepath: str, strindex_diff_filepath: str | None) -> str:
	"""
	Subtract the entries of a strindex file from another,
	creating a strindex file with their differences.
	"""

	Progress.init_global_instance(4)

	strindex_diff_filepath = strindex_diff_filepath or edit_extension(strindex_1_filepath, "_diff.txt")

	strindex_1 = Strindex.read(strindex_1_filepath)
	strindex_2 = Strindex.read(strindex_2_filepath)

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

	strindex_1.write(strindex_diff_filepath)

	return Print.success(
		f"Created diff strindex file with {len(strindex_1.strings)} strings out of {initial_count} at\n"
		f"{strindex_diff_filepath}"
	)


def merge(strindex_1_filepath: str, strindex_2_filepath: str, strindex_merged_filepath: str | None) -> str:
	"""
	Merge the first strindex file into the second one,
	prioritizing the first one in case of conflicts.
	"""

	Progress.init_global_instance(4)

	strindex_merged_filepath = strindex_merged_filepath or edit_extension(strindex_2_filepath, "_merged.txt")

	strindex_1 = Strindex.read(strindex_1_filepath)
	strindex_2 = Strindex.read(strindex_2_filepath)

	merged_entries = 0

	strindex_1_ids = strindex_1.get_identifiers
	strindex_2_ids = strindex_2.get_identifiers

	for index in range(len(strindex_2.strings)):
		try:
			search_index = strindex_1_ids.index(strindex_2_ids[index])
		except ValueError:
			pass
		else:
			if strindex_2.type_order[index] == "overwrite":
				strindex_2.strings[index] = strindex_1.strings[search_index]
			elif strindex_2.type_order[index] == "compatible":
				strindex_2.strings[index][1] = strindex_1.strings[search_index][1]
			search_index += 1
			merged_entries += 1

	Progress.global_instance()

	strindex_2.write(strindex_merged_filepath)

	return Print.success(
		f"Created merged strindex file with {merged_entries} entries merged out of {len(strindex_2.strings)} at\n"
		f"{strindex_merged_filepath}"
	)


def spellcheck(strindex_filepath: str, strindex_spellcheck_filepath: str | None) -> str:
	"""
	Spellcheck a strindex, and write the results to a file.
	The target language can be specified in the strindex settings.
	"""

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


def get_parser() -> argparse.ArgumentParser:
	ACTIONS = (gui, create, patch, unpatch, infer, update, filter, diff, merge, spellcheck)

	parser = argparse.ArgumentParser(
		prog="strindex",
		exit_on_error=False,
		formatter_class=argparse.RawTextHelpFormatter
	)

	parser.description = (
		"A command line utility that allows you to\n"
		"easily extract, list and patch the strings embedded in a few filetypes.\n\n"
		"\033[1m\033[34mactions:\033[0m\n" +
		"\n".join(
			f"  \033[1m\033[36m{action.__name__: <12}\033[0m{action.__doc__.strip().replace("\n", "\n" + " "*16)}"
			for action in ACTIONS
		) +
		"\n\n  Strindex files compressed with gzip are also supported, for all actions."
	)

	parser.add_argument("action", type=str, nargs=argparse.OPTIONAL, choices=[a.__name__ for a in ACTIONS],
		help="Action to perform.")
	parser.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE,
		help="One or more files/strindex files to pass to the action.")
	parser.add_argument("-o", "--output", type=str,
		help="Output file path.\nIf not specified, a default one will be used.")
	parser.add_argument("-q", "--quiet", action="store_true",
		help="Suppress all output except for errors.")
	parser.add_argument("-v", "--verbose", action="store_true",
		help="Print full error messages.")
	parser.add_argument("--version", action="version", version=VERSION,
		help="Show the version of strindex and exit.")

	write_parser = parser.add_argument_group("[create] writing options")
	write_parser.add_argument("-C", "--compatible", action="store_true",
		help=StrindexSettings.get_doc("_compatible"))
	write_parser.add_argument("-R", "--references", action="store_true",
		help=StrindexSettings.get_doc("_references"))
	write_parser.add_argument("-M", "--minimal", action="store_true",
		help=StrindexSettings.get_doc("_minimal"))

	APPEND_SPECIFY_INFO = "\nCan be specified multiple times."

	create_parser = parser.add_argument_group("[create] options")
	create_parser.add_argument("-f", "--force-mode", action="store_true",
		help=StrindexSettings.get_doc("force_mode"))
	create_parser.add_argument("-m", "--min-length", default=3, type=int,
		help=StrindexSettings.get_doc("min_length"))
	create_parser.add_argument("-p", "--prefix-bytes", type=str, action="append", default=[],
		help=(StrindexSettings.get_doc("prefix_bytes") + APPEND_SPECIFY_INFO))
	create_parser.add_argument("-s", "--suffix-bytes", type=str, action="append", default=[],
		help=(StrindexSettings.get_doc("suffix_bytes") + APPEND_SPECIFY_INFO))
	create_parser.add_argument("-r", "--range", type=str, action="append", default=[],
		help=(StrindexSettings.get_doc("ranges") + APPEND_SPECIFY_INFO))
	create_parser.add_argument("-w", "--whitelist", type=str, action="append", default=[],
		help=(StrindexSettings.get_doc("whitelist") + APPEND_SPECIFY_INFO))

	create_parser.description = (
		"For more information about the following options,\n"
		"as well a showcase of a valid strindex file, please refer to\n"
		"https://github.com/zWolfrost/strindex/blob/main/strindex_example.txt"
	)

	update_parser = parser.add_argument_group("[update] options").add_mutually_exclusive_group()
	update_parser.add_argument("--convert-to-compatible", action="store_true",
		help="When using the [update] action,\nconvert overwrite strings to compatible strings.")
	update_parser.add_argument("--convert-to-overwrite", action="store_true",
		help="When using the [update] action,\nconvert compatible strings to overwrite strings.")

	return parser


def main(sysargs=None):
	try:
		Print.quiet_mode = False

		args = get_parser().parse_args(sysargs)

		Print.quiet_mode = args.quiet
		Print.color_mode = sys.stdout.isatty()

		if "help" in args.whitelist:
			help_whitelist()
			return

		if args.action is None:
			raise ValueError("No action specified. Use -h / --help to see the available actions.")

		for file in args.files:
			if not Path(file).is_file():
				raise FileNotFoundError(f"File '{file}' is not a file or does not exist.")

		if "__compiled__" in globals() and args.action == "spellcheck":
			raise ImportError("Spellchecking is not supported in compiled builds.")

		def require_files_num(n: int):
			if len(args.files) != n:
				raise ValueError(f'Expected {n} file(s) for "{args.action}" action, got {len(args.files)}.')

		match args.action:
			case "gui":
				require_files_num(0)
				gui()
			case "create":
				require_files_num(1)
				create(*args.files, args.output,
					StrindexSettings(
						_compatible = args.compatible,
						_references = args.references,
						_minimal = args.minimal,
						force_mode = args.force_mode,
						min_length = args.min_length,
						prefix_bytes = args.prefix_bytes,
						suffix_bytes = args.suffix_bytes,
						ranges = args.range,
						whitelist = args.whitelist
					)
				)
			case "patch":
				require_files_num(2)
				patch(*args.files, args.output)
			case "unpatch":
				require_files_num(1)
				unpatch(*args.files)
			case "infer":
				require_files_num(2)
				infer(*args.files)
			case "update":
				require_files_num(2)
				update(
					*args.files, args.output,
					convert_type = (
						"overwrite" if args.convert_to_overwrite else
						"compatible" if args.convert_to_compatible else None
					)
				)
			case "filter":
				require_files_num(1)
				filter(*args.files, args.output)
			case "diff":
				require_files_num(2)
				diff(*args.files, args.output)
			case "merge":
				require_files_num(2)
				merge(*args.files, args.output)
			case "spellcheck":
				require_files_num(1)
				spellcheck(*args.files, args.output)
	except KeyboardInterrupt:
		Print.error("Interrupted by user.")
	except Exception as e:
		if "args" in locals() and args.verbose:
			raise
		Print.error(f"[{type(e).__name__}] {e}\nPlease use -v / --verbose to see the full traceback.")


if __name__ == "__main__":
	main()
