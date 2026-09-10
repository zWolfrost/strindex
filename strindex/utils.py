import dataclasses
import functools
import gzip
import re
import time
import tomllib
import zlib
from collections.abc import Callable
from json import JSONEncoder
from pathlib import Path
from typing import ClassVar, Protocol

from ahocorasick_rs import BytesAhoCorasick, Implementation

from strindex.strings_find_fast import strings_find_fast


class Print:
	""" A wrapper for the print function. """

	class PrintLevel:
		DEBUG = ""
		INFO = "\033[1m"
		SUCCESS = "\033[1m\033[92m"
		WARNING = "\033[93m"
		ERROR = "\033[91m"
		RESET = "\033[0m"

	quiet_mode = True
	color_mode = True

	@classmethod
	def print(cls, msg: str, tag: str | None = None, level: str | None = None, **kwargs):
		if not cls.quiet_mode:
			tag = f"[{tag}] " if tag is not None and not msg.startswith("[") else ""
			if cls.color_mode and level:
				print(level, tag, msg, cls.PrintLevel.RESET, sep="", **kwargs) # noqa: T201
			else:
				print(tag, msg, sep="", **kwargs) # noqa: T201
		return msg

	@classmethod
	def debug(cls, msg: str, **kwargs) -> str:
		return cls.print(msg, level=cls.PrintLevel.DEBUG, **kwargs)
	@classmethod
	def info(cls, msg: str, **kwargs) -> str:
		return cls.print(msg, level=cls.PrintLevel.INFO, **kwargs)
	@classmethod
	def success(cls, msg: str, **kwargs) -> str:
		return cls.print(msg, level=cls.PrintLevel.SUCCESS, **kwargs)
	@classmethod
	def warning(cls, msg: str, **kwargs) -> str:
		return cls.print(msg, tag="Warning", level=cls.PrintLevel.WARNING, **kwargs)
	@classmethod
	def error(cls, msg: str, **kwargs) -> str:
		return cls.print(msg, tag="Error", level=cls.PrintLevel.ERROR, **kwargs)


class Progress:
	""" A class to handle progress printing. """

	global_instance: "Progress"
	global_callback: Callable[["Progress"], None]

	global_instance_priority: int

	total: int
	limit: int
	delta: int
	round: int
	percent: float
	start: float

	def __init__(self, total: int, decimals: int = 0):
		assert total > 0, "Total must be greater than 0."
		self.total = total
		self.limit = 0
		self.delta = max(1, total // (10 ** (decimals + 2)))
		self.round = decimals
		self.percent = 0
		self.start = time.time()
		self(0)

	def __call__(self, iteration: int | None = None):
		if iteration is None:
			iteration = self.limit
		if iteration >= self.limit and self.percent < 100:
			self.limit += self.delta
			self.percent = round(iteration / self.total * 100, self.round)
			if (hasattr(Progress, "global_instance") and self is Progress.global_instance
				and hasattr(Progress, "global_callback")):
					Progress.global_callback(self)
			if self.total >= 100:
				Print.debug(f"\r{self.percent:.{self.round}f}% ({iteration}/{self.total})",
					end=("\r" if self.percent >= 100 else ""))
			#if self.percent >= 100:
			#	Print.debug(f"Action completed in {time.time() - self.start:.2f}s.")

	@classmethod
	def global_mark[**P, T](cls, func: Callable[P, T]) -> Callable[P, T]:
		""" Decorator to mark a function for progress printing. """
		@functools.wraps(func)
		def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
			result = func(*args, **kwargs)
			if hasattr(Progress, "global_instance"):
				Progress.global_instance()
			return result
		return wrapper

	@staticmethod
	def init_global_instance(*args, priority: int = 0, **kwargs):
		if not hasattr(Progress, "global_instance_priority") or priority >= Progress.global_instance_priority:
			Progress.global_instance = Progress(*args, **kwargs)
			Progress.global_instance_priority = priority


@dataclasses.dataclass
class StrindexSettings:
	# These are really limited, so I would really like
	# if you added your language's characters here and open a pull request <3
	CHARACTER_SETS: ClassVar[dict[str, str]] = {
		"_default": """\t\n\r !"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~… """, # noqa: RUF001
		"latin": """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz""",
		"spanish": """¡¿ÁÉÍÓÚÜÑáéíóúüñã""",
		"italian": """ÀÈÉÌÒÓÙàèéìòóù""",
		"cyrillic": """ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂҃҄҅҆҇҈҉ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽӾ""", # noqa: E501
	}

	_raw: str | None = dataclasses.field(default=None)
	_dynamic: bool = dataclasses.field(default=False, metadata={"help":
		"Whether to create a strindex file with\ndynamic pointers instead of fixed pointers.\n"
		"Dynamic pointers use the original strings\nas references, instead of offsets."})
	_references: bool = dataclasses.field(default=False, metadata={"help":
		"Whether to add reference comments\nof the original strings to fixed pointers."})
	_minimal: bool = dataclasses.field(default=False, metadata={"help":
		"Whether to strip the strindex file of\ninformational comments and unnecessary newlines."})
	_whitelist_set: set[str] = dataclasses.field(default_factory=set)

	hash: str | None = dataclasses.field(default=None)
	force_mode: bool = dataclasses.field(default=False, metadata={"help": (
		'Whether to use the "force" module\nand force the replacement of strings\n'
		"at the same offset they were found.\nThis will effectively make every binary file patchable,\n"
		"but the length of the replaced strings\ncannot exceed the length of the original strings.")})
	min_length: int = dataclasses.field(default=1, metadata={"help":
		"Minimum length of the strings to be considered."})
	prefix_bytes: list[bytes] = dataclasses.field(default_factory=list, metadata={"help":
		"Prefix bytes that must prefix a pointer, in hex format."})
	suffix_bytes: list[bytes] = dataclasses.field(default_factory=list, metadata={"help":
		"Suffix bytes that must suffix a pointer, in hex format."})
	ranges: list[range] = dataclasses.field(default_factory=list, metadata={"help":
		'Ranges of offsets to consider when searching pointers,\nin the format "start:end".\n'
		'If not set, all offsets are considered.'})
	whitelist: list[str] = dataclasses.field(default_factory=list, metadata={"help":
		"Character sets to whitelist when filtering strings.\nIf not set, all characters are allowed."})
	patch_replace: dict[str, str] = dataclasses.field(default_factory=dict)
	clean_pattern: str = dataclasses.field(default="")
	source_language: str | None = dataclasses.field(default=None)
	target_language: str | None = dataclasses.field(default=None)
	among_languages: list[str] = dataclasses.field(default_factory=list)

	def __post_init__(self):
		self.min_length = max(int(self.min_length), 1)
		self.prefix_bytes = self.handle_bytes_list(self.prefix_bytes)
		self.suffix_bytes = self.handle_bytes_list(self.suffix_bytes)
		self.ranges = self.handle_ranges(self.ranges)
		self._whitelist_set = self.handle_whitelist(self.whitelist)

	@classmethod
	def toml_parse(cls, toml_str: str) -> "StrindexSettings":
		""" Reads the settings from TOML data. """
		try:
			return cls(**tomllib.loads(toml_str), _raw=toml_str)
		except Exception as e:
			raise ValueError(f"Error parsing Strindex TOML header:\n{e}") from e

	def toml_dumps(self) -> str: # HACK
		""" Dumps the settings to a TOML string. """

		def formatter(val):
			if isinstance(val, list):
				return "[ " + ", ".join(formatter(v) for v in val) + " ]"
			if isinstance(val, dict):
				return "{ " + ", ".join(f'"{k}" = "{v}"' for k, v in val.items()) + " }"
			if isinstance(val, bytes):
				return f'"{val.hex()}"'
			if isinstance(val, range):
				return f'"{val.start:08x}:{val.stop - 1:08x}"'
			return JSONEncoder(ensure_ascii=False).encode(val)

		dumps = ""
		for key, value in self.get_changed().items():
			dumps += f"{key} = {formatter(value)}\n"
		return dumps

	def get_changed(self) -> dict:
		""" Returns a dictionary with the settings that are different from the default settings. """
		CURRENT_SETTINGS = self.get_dict()
		DEFAULT_SETTINGS = StrindexSettings().get_dict()
		return {k: v for k, v in CURRENT_SETTINGS.items() if DEFAULT_SETTINGS.get(k) != v}

	@staticmethod
	def handle_whitelist(whitelist: str) -> set[str]:
		if not whitelist:
			return set()

		return set("".join([StrindexSettings.CHARACTER_SETS.get(w, w) for w in [*whitelist, "_default"]]))

	@staticmethod
	def handle_bytes_list(bytes_hex_list: list[str]) -> list[bytes]:
		if any(len(bytes_str.strip()) % 2 != 0 for bytes_str in bytes_hex_list):
			raise ValueError("All of the hex byte strings must contain an even number of characters.")
		return [bytes.fromhex(bytes_hex_str) for bytes_hex_str in bytes_hex_list]

	@staticmethod
	def handle_ranges(ranges: list[str]) -> list[tuple[int, int]]:
		parsed_ranges = []
		for range_str in ranges:
			if range_str == "":
				continue

			try:
				beg_str, end_str = range_str.split(":")
				beg = int(beg_str, 16)
				end = int(end_str, 16) + 1
			except ValueError as e:
				raise ValueError(f"Invalid range format: {range_str}. Expected format is 'start:end'.") from e
			if beg > end:
				raise ValueError(f"Invalid range: {range_str}. Start must be less than or equal to end.")
			parsed_ranges.append(range(beg, end))
		return parsed_ranges

	def clean_string(self, string: str) -> str:
		return re.sub(self.clean_pattern, "", string)

	def patch_replace_string(self, string: str) -> str:
		""" Replaces the strings in the patch with the new strings. """
		for key, value in self.patch_replace.items():
			string = string.replace(key, value)
		return string

	def matches_prefix(self, data: bytearray, beg_offset: int) -> bool:
		""" Checks if the data at the given offset matches any of the prefixes. """
		return any(data[beg_offset - len(p):beg_offset] == p for p in self.prefix_bytes) if self.prefix_bytes else True

	def matches_suffix(self, data: bytearray, end_offset: int) -> bool:
		""" Checks if the data at the given offset matches any of the suffixes. """
		return any(data[end_offset:end_offset + len(s)] == s for s in self.suffix_bytes) if self.suffix_bytes else True

	def is_in_any_range(self, val: int) -> bool:
		""" Checks if the value is in any of the ranges. """
		return any(val in r for r in self.ranges) if self.ranges else True

	def is_in_whitelist(self, string: str) -> bool:
		""" Checks if the string is whitelisted. """
		return all(char in self._whitelist_set for char in string) if self._whitelist_set else True

	def get_dict(self) -> dict:
		return {k: v for k, v in vars(self).items() if not k.startswith("_")}

	@staticmethod
	def get_doc(var):
		return next((f.metadata.get("help") for f in dataclasses.fields(StrindexSettings) if f.name == var), None)

	def __repr__(self) -> str:
		return str(self.get_changed())


class Strindex:
	""" A class to parse and create strindex files. """

	settings: StrindexSettings

	types: list[int]
	pointers: list[list[int | str | bool]]
	strings: list[str]


	class Type:
		FIXED = 1
		DYNAMIC = 2

	TOKEN_DELIMITER = " "
	POINTERS_PREFIX = "@"
	STRING_PREFIX = ">>" + TOKEN_DELIMITER

	FIXED_PREFIX = POINTERS_PREFIX + "f" + TOKEN_DELIMITER
	DYNAMIC_PREFIX = POINTERS_PREFIX + "d" + TOKEN_DELIMITER
	DYNAMIC_TRUE = "+"
	DYNAMIC_FALSE = "-"


	_UNESCAPE_DICT: ClassVar[dict[str, str]] = {
		"\\": "\\",
		"t": "\t",
		"n": "\n",
		"r": "\r",
	}
	_UNESCAPE_RE = re.compile(r"\\([\\tnr])")
	@staticmethod
	def unescape_ctrl(string: str) -> str: # HACK
		return Strindex._UNESCAPE_RE.sub(lambda m: Strindex._UNESCAPE_DICT[m.group(1)], string)

	_ESCAPE_MAP = str.maketrans({
		"\\": r"\\",
		"\t": r"\t",
		"\n": r"\n",
		"\r": r"\r",
	})
	@staticmethod
	def escape_ctrl(string: str) -> str: # HACK
		return string.translate(Strindex._ESCAPE_MAP)


	@property
	def count(self) -> int:
		return max(len(self.types), len(self.pointers), len(self.strings))


	def get_type_pointers(self, ch_type: "Strindex.Type") -> list[list[int]] | tuple[list[str], list[list[bool]]]:
		res = [pointers for type, pointers in zip(self.types, self.pointers, strict=True) if type == ch_type]
		if ch_type == Strindex.Type.FIXED:
			return res
		if ch_type == Strindex.Type.DYNAMIC:
			return zip(*((p[0], p[1:]) for p in res), strict=True) if res else ([], [])
		raise ValueError(f"Invalid strindex type: {ch_type}.")

	def get_type_strings(self, ch_type: "Strindex.Type") -> list[str]:
		return [string for type, string in zip(self.types, self.strings, strict=True) if type == ch_type]


	def get_overwrite_or_original(self) -> list[str]:
		return [
			(string if type == Strindex.Type.FIXED else pointers[0])
			for type, pointers, string in zip(self.types, self.pointers, self.strings, strict=True)
		]

	def get_offsets_or_original(self) -> list[str]:
		return [
			(",".join(str(p) for p in pointers) if type == Strindex.Type.FIXED else string[0])
			for type, pointers, string in zip(self.types, self.pointers, self.strings, strict=True)
		]


	def __init__(self):
		""" Parses a strindex file and returns a dictionary with the data. """

		self.settings = StrindexSettings()

		self.types = []
		self.pointers = []
		self.strings = []

	def parse_body_line(self, line: str):
		try:
			line = line.removesuffix("\n")

			if line.startswith(Strindex.POINTERS_PREFIX):
				if self.strings and self.strings[-1] is None:
					raise ValueError

				if line.startswith(Strindex.FIXED_PREFIX):
					processed_line = line.removeprefix(Strindex.FIXED_PREFIX)
					self.types.append(Strindex.Type.FIXED)
					self.pointers.append([int(p, 16) for p in processed_line.split(Strindex.TOKEN_DELIMITER) if p])
					self.strings.append(None)
				elif line.startswith(Strindex.DYNAMIC_PREFIX):
					processed_line = line.removeprefix(Strindex.DYNAMIC_PREFIX)
					original, switches = processed_line.rsplit(Strindex.TOKEN_DELIMITER, 1)
					self.types.append(Strindex.Type.DYNAMIC)
					self.pointers.append([Strindex.unescape_ctrl(original), *(
						[True] * int(switches.removeprefix("x")) if switches.removeprefix("x").isdigit() else
						[s == Strindex.DYNAMIC_TRUE for s in switches if s]
					)])
					self.strings.append(None)
				else:
					raise ValueError
			elif line.startswith(Strindex.STRING_PREFIX):
				processed_line = line.removeprefix(Strindex.STRING_PREFIX)
				if self.strings[-1] is None:
					self.strings[-1] = Strindex.unescape_ctrl(processed_line)
				else:
					raise ValueError
			elif line and not line.startswith("#"):
				raise ValueError
		except ValueError as e:
			raise ValueError(f"Invalid line in strindex body:\n{line!r}") from e

	def dump_body_entry(self, i: int) -> str:
		if self.types[i] == Strindex.Type.FIXED:
			escaped_string = Strindex.escape_ctrl(self.strings[i])
			return (
				Strindex.FIXED_PREFIX +
				Strindex.TOKEN_DELIMITER.join(f"{p or 0:08x}" for p in self.pointers[i]) + "\n" +
				(f"## {escaped_string}\n" if self.settings._references else "") +
				Strindex.STRING_PREFIX + escaped_string +
				("\n" if self.settings._minimal else "\n\n")
			)
		if self.types[i] == Strindex.Type.DYNAMIC:
			return (
				Strindex.DYNAMIC_PREFIX +
				Strindex.escape_ctrl(self.pointers[i][0]) + Strindex.TOKEN_DELIMITER +
				(("x" + str(len(self.pointers[i][1:]))) if all(self.pointers[i][1:]) else
				"".join((Strindex.DYNAMIC_TRUE if p else Strindex.DYNAMIC_FALSE) for p in self.pointers[i][1:])) +
				"\n" + Strindex.STRING_PREFIX + Strindex.escape_ctrl(self.strings[i]) +
				("\n" if self.settings._minimal else "\n\n")
			)
		raise ValueError(f"Invalid strindex type: {self.types[i]}")

	@classmethod
	@Progress.global_mark
	def read(cls, filepath: str) -> "Strindex":
		""" Parses a strindex file and returns a dictionary with the data. """

		strindex = cls()

		with Path(filepath).open("rb") as f:
			is_gzipped = (f.read(2) == b"\x1f\x8b")

		with (
			gzip.open(filepath, "rt", encoding="utf-8", newline=None) if is_gzipped
				else Path(filepath).open("r", encoding="utf-8", newline=None)
		) as f:
			full_header = ""
			while line := f.readline():
				if line.startswith(Strindex.POINTERS_PREFIX):
					strindex.parse_body_line(line)
					break
				full_header += line

			strindex.settings = StrindexSettings.toml_parse(full_header)

			while line := f.readline():
				strindex.parse_body_line(line)

		if strindex.strings[-1] is None:
			raise ValueError("The last entry in the strindex file is incomplete.")

		strindex.assert_data()

		return strindex

	@Progress.global_mark
	def write(self, filepath: str) -> str:
		""" Saves the strindex data to a file. """

		HEADER_INFO = (
			"# You can freely create & delete comments anywhere in the strindex file.\n"
			"# For more information about strindex files' settings and syntax, see:\n"
			"# https://github.com/zWolfrost/strindex/blob/main/strindex_example.txt\n"
		)
		FIXED_INFO = (
			"# EXAMPLE OF REPLACEMENT:\n"
			f"# {Strindex.FIXED_PREFIX}"
			f"[pointer]{Strindex.TOKEN_DELIMITER}[pointer]{Strindex.TOKEN_DELIMITER}[...]\n"
			f"# {Strindex.STRING_PREFIX}replace the string that was previously provided here, with this one!\n\n"
		)
		DYNAMIC_INFO = (
			"# EXAMPLE OF REPLACEMENT:\n"
			f"# {Strindex.DYNAMIC_PREFIX}"
			f"replace this string...{Strindex.TOKEN_DELIMITER}[reallocate N pointers if [xN] OR [+/-] N times]\n"
			f"# {Strindex.STRING_PREFIX}...with this string!\n\n"
		)

		self.assert_data()

		with Path(filepath).open("w", encoding="utf-8", newline="\n") as f:
			if self.settings._raw is not None:
				f.write(self.settings._raw)
			else:
				if self.settings._minimal:
					f.write(self.settings.toml_dumps())
				else:
					f.write(HEADER_INFO + "\n" + self.settings.toml_dumps() + "\n")
					if self.count > 0:
						f.write(FIXED_INFO if self.types[0] == Strindex.Type.FIXED else DYNAMIC_INFO)

			f.writelines(self.dump_body_entry(i) for i in range(self.count))

			f.seek(max(f.tell() - 1, 0))
			f.truncate()

	def normalize_to_fixed(self, full_lst_offsets: list[int], full_lst_strings: list[str]):
		""" Converts dynamic strings to fixed strings and deletes them if necessary. """

		assert len(full_lst_strings) == len(full_lst_offsets), \
			"The full string and offset lists must be the same length."

		search_i = 0
		for i in range(self.count):
			if self.types[i] != Strindex.Type.DYNAMIC:
				continue

			try:
				search_i = full_lst_strings.index(self.pointers[i][0], search_i)
				offsets = full_lst_offsets[search_i]
			except ValueError:
				pass
			else:
				if any(self.pointers[i][1:]):
					self.types[i] = Strindex.Type.FIXED
					if len(offsets) != len(self.pointers[i][1:]):
						Print.warning(
							f"The number of switches for string #{i}\n"
							f"doesn't match the number of pointers ({len(offsets)} != {len(self.pointers[i][1:])})"
						)
					self.pointers[i] = [p for p, s in zip(offsets, self.pointers[i][1:], strict=False) if s]
				search_i += 1

		for i in reversed(range(self.count)):
			if self.types[i] == Strindex.Type.DYNAMIC:
				Print.warning(f'String #{i+1} not found: "{self.strings[i]}"')
				self.delete_index(i)

	def delete_index(self, i: int):
		if self.types:
			del self.types[i]
		if self.pointers:
			del self.pointers[i]
		if self.strings:
			del self.strings[i]

	def assert_data(self):
		assert len(self.types) == len(self.pointers) == len(self.strings), (
			f"Types, pointers and strings lists are not the same length"
			f" ({len(self.types)} != {len(self.pointers)} != {len(self.strings)})."
		)

	def __repr__(self) -> str:
		def dump_body_range(indexes: range) -> str:
			return "\n".join(self.dump_body_entry(i).replace("\n", "\t") for i in indexes)

		return (
			dump_body_range(range(3)) +
			(f"\n...{self.count - 6} more...\n" if self.count > 10 else "") +
			dump_body_range(range(self.count - 3, self.count))
		) if self.count > 10 else dump_body_range(range(self.count))


class FileBuffer(bytearray):
	""" A class to handle bytearrays with additional methods and shorthands focused on file manipulation. """

	cursor: int
	byte_length: int
	byte_order: str

	@classmethod
	@Progress.global_mark
	def read(cls, filepath: str):
		with Path(filepath).open("rb") as f:
			return cls(f.read())

	@Progress.global_mark
	def write(self, filepath: str):
		with Path(filepath).open("wb") as f:
			f.write(self)

	def copy(self) -> "FileBuffer":
		return type(self)(self)

	# Algorithms
	@Progress.global_mark
	def strings_find(
		self,
		sep: bytes = b"\x00",
		min_length: int = 1,
		ranges: list[range] | None = None
	) -> list[tuple[str, int, int]]:
		"""
		Returns all strings in a bytearray, separated by a given separator.
		Skips strings that contain control characters and ones that are not valid UTF-8.
		Implemented in C for speed.
		"""

		return strings_find_fast(
			self,
			int(sep[0]),
			min_length,
			[(r.start, r.stop) for r in (ranges or [])]
		)

	@Progress.global_mark
	def strings_search_ordered(
		self,
		search_lst: list[bytes],
		prefix: bytes = b"\x00",
		suffix: bytes = b"\x00"
	) -> list[int]:
		"""
		Returns the index of the first occurrence of every search list string in a bytearray.
		Can only can work for search lists that are ordered by occurrence order.
		"""

		search_lst = [search.encode("utf-8") if isinstance(search, str) else search for search in search_lst]
		indices = []
		prefix_length = len(prefix)
		start_index = 0
		misses = 0
		for search_index in range(len(search_lst)):
			found_index = self.find(prefix + search_lst[search_index] + suffix, start_index)
			if found_index == -1:
				indices.append(None)
				misses += 1
				if misses > 1000:
					raise ValueError(
						"More than 1000 strings not found.\n"
						"Please make sure the search list is ordered by occurrence order\n"
						"and that the strings are present in the bytearray."
					)
				continue
			start_index = found_index + prefix_length + len(search_lst[search_index])
			indices.append(found_index + prefix_length)
		return indices

	@Progress.global_mark
	def strings_search(
		self,
		search_lst: list[bytes],
		prefixes: list[bytes] | None = None,
		suffixes: list[bytes] | None = None
	) -> list[list[int]]:
		"""
		Returns a list containing the indexes of each occurrence of every search list string in the bytearray.
		Uses Aho-Corasick algorithm.
		"""

		if not search_lst:
			return []

		if not prefixes:
			prefixes = [b""]
		if not suffixes:
			suffixes = [b""]

		search_lst_safe = [s.encode("utf-8") if isinstance(s, str) else s for s in search_lst if s is not None]

		Print.debug(f"Created search list with {len(search_lst_safe)} x {len(prefixes) * len(suffixes)} strings.")

		if len(search_lst_safe) > 10**6:
			Print.warning(
				"The search list is very large!\n"
				"This may take a bit to process;\n"
				"consider increasing the minimum string length."
			)

		search_lst_full: list[bytes] = []
		search_lst_prefix_length: list[int] = []
		search_lst_indices: list[list[int]] = []
		for search_string in search_lst_safe:
			search_string_lst = []
			for prefix in prefixes:
				for suffix in suffixes:
					search_lst_full.append(prefix + search_string + suffix)
					search_lst_prefix_length.append(len(prefix))
					search_lst_indices.append(search_string_lst)

		ac = BytesAhoCorasick(search_lst_full, implementation=Implementation.ContiguousNFA)

		for i, start, _ in ac.find_matches_as_indexes(self, overlapping=True):
			search_lst_indices[i].append(start + search_lst_prefix_length[i])

		return search_lst_indices[::len(prefixes) * len(suffixes)]

	# Shorthands
	def get(self, byte_length: int | None = None) -> bytes:
		if byte_length is None:
			byte_length = self.byte_length
		byte_slice = self[self.cursor:self.cursor + byte_length]
		self.cursor += byte_length
		return bytes(byte_slice)

	def put(self, value: bytes, byte_length: int | None = None) -> bytes:
		if not isinstance(value, bytes):
			value = bytes(value, "utf-8")
		if byte_length is None:
			byte_length = len(value)
		self[self.cursor:self.cursor + byte_length] = value
		self.cursor += byte_length
		return value

	def get_int(self, byte_length: int | None = None, byte_order: str | None = None) -> int:
		if byte_order is None:
			byte_order = self.byte_order
		return int.from_bytes(self.get(byte_length), byte_order)

	def put_int(self, value: int, byte_length: int | None = None, byte_order: str | None = None) -> bytes:
		if byte_length is None:
			byte_length = self.byte_length
		self[self.cursor:self.cursor + byte_length] = self.from_int(value, byte_length, byte_order)
		return self.get(byte_length)

	def from_int(self, value: int, byte_length: int | None = None, byte_order: str | None = None) -> bytes:
		if byte_length is None:
			byte_length = self.byte_length
		if byte_order is None:
			byte_order = self.byte_order
		return value.to_bytes(byte_length, byte_order)

	def add_int(self, delta: int, byte_length: int | None = None, byte_order: str | None = None) -> bytes:
		if byte_length is None:
			byte_length = self.byte_length
		value = self.get_int(byte_length, byte_order)
		self.cursor -= byte_length
		return self.put_int(value + delta, byte_length, byte_order)

	def replace_string(self, replace: str, sep: bytes = b"\x00") -> bytes:
		try:
			original_length = self.index(sep, self.cursor) - self.cursor
		except ValueError:
			original_length = len(self) - self.cursor

		replace_bytes = replace.encode("utf-8")

		if len(replace_bytes) > original_length:
			Print.warning(
				f'Replace string "{replace}" at {hex(self.cursor)} is longer than the original string'
				f' ({len(replace_bytes)} > {original_length}); Truncating.'
			)
			replace_bytes = replace_bytes[:original_length]
		else:
			replace_bytes = replace_bytes.ljust(original_length, sep)

		self[self.cursor:self.cursor + original_length] = replace_bytes

	# Macros
	def create_pointers_macro(
		self,
		strindex: Strindex,
		original_bytes_from_offset: Callable[[int], bytes]
	) -> Strindex:
		temp_strindex = {
			"original_bytes": [],
			"pointers": [],
			"strings": []
		}

		for string, start_offset, _ in self.strings_find(min_length=strindex.settings.min_length):
			if ((
				original_bytes := original_bytes_from_offset(start_offset))
				and strindex.settings.is_in_whitelist(string)
			):
				temp_strindex["original_bytes"].append(original_bytes)
				temp_strindex["strings"].append(string)

		if not temp_strindex["strings"]:
			raise ValueError("No strings found in the file.")

		temp_strindex["pointers"] = self.strings_search(
			temp_strindex["original_bytes"], strindex.settings.prefix_bytes, strindex.settings.suffix_bytes
		)

		for string, pointers in zip(temp_strindex["strings"], temp_strindex["pointers"], strict=True):
			pointers = [p for p in pointers if strindex.settings.is_in_any_range(p)]
			if pointers:
				strindex.pointers.append(pointers)
				strindex.strings.append(string)

		Print.debug(f"Found pointers for {strindex.count} strings out of {len(temp_strindex['strings'])}.")

		return strindex

	def patch_pointers_macro(
		self,
		strindex: Strindex,
		original_bytes_from_offset: Callable[[int], bytes],
		replaced_bytes_from_offset: Callable[[int], bytes],
		data_from_string: Callable[[str], bytes]
	) -> bytearray:
		new_data = bytearray()

		update_dict = {
			"original_bytes": [],
			"replaced_bytes": [],
			"pointers": [],
			"switches": []
		}

		strindex_original, strindex_switches = strindex.get_type_pointers(Strindex.Type.DYNAMIC)
		strindex_dynamic_strings = strindex.get_type_strings(Strindex.Type.DYNAMIC)

		for i, offset in enumerate(self.strings_search_ordered(strindex_original)):
			if offset is None:
				Print.warning(f'String #{i+1} not found: "{strindex_original[i]}"')
				continue

			update_dict["original_bytes"].append(original_bytes_from_offset(offset))
			update_dict["replaced_bytes"].append(replaced_bytes_from_offset(len(new_data)))
			update_dict["switches"].append(strindex_switches[i])
			new_data += data_from_string(strindex.settings.patch_replace_string(strindex_dynamic_strings[i]))

		update_dict["pointers"] = self.strings_search(
			update_dict["original_bytes"], strindex.settings.prefix_bytes, strindex.settings.suffix_bytes
		)

		self.update_references(update_dict["pointers"], update_dict["replaced_bytes"], update_dict["switches"])

		update_dict = {
			"replaced_bytes": []
		}

		for string in strindex.get_type_strings(Strindex.Type.FIXED):
			update_dict["replaced_bytes"].append(replaced_bytes_from_offset(len(new_data)))
			new_data += data_from_string(strindex.settings.patch_replace_string(string))

		self.update_references(strindex.get_type_pointers(Strindex.Type.FIXED), update_dict["replaced_bytes"])

		return new_data

	def update_references(
		self,
		lst_offsets: list[list[int]],
		lst_replaced_bytes: list[bytes],
		lst_switches: list[list[bool]] | None = None
	):
		if lst_switches is None:
			lst_switches = [[True] * len(pointer) for pointer in lst_offsets]

		for i, (offsets, replaced_bytes, switches) in enumerate(
			zip(lst_offsets, lst_replaced_bytes, lst_switches, strict=True)
		):
			if offsets:
				if len(offsets) != len(switches):
					Print.warning(
						f"The number of switches for string #{i}\n"
						f"doesn't match the number of pointers ({len(switches)} != {len(offsets)})"
					)
				for offset, switch in zip(offsets, switches, strict=False):
					if switch:
						self[offset:offset + self.byte_length] = replaced_bytes
			else:
				Print.warning(f"No pointers found for string #{i}")

	@property
	def hash(self) -> str:
		""" Hash is CRC32 """
		return f"{zlib.crc32(self):08x}"

	@property
	def hash_backup_suffix(self) -> str:
		return "_" + self.hash + ".bak"


@dataclasses.dataclass(frozen=True)
class ModuleSettings:
	default_byte_length: int | None = None
	"""Default byte length for the file buffer."""
	default_byte_order: str | None = None
	"""Default byte order for the file buffer."""
	filter_after_create: bool = True
	"""Whether to filter the strindex after returning it using its settings."""
	supports_dynamic: bool = False


class ModuleProtocol(Protocol):
	SETTINGS: ModuleSettings
	"""Settings specific to this module."""
	match: Callable[[FileBuffer], bool]
	"""Return True if a file buffer (bytearray) is compatible with this module."""
	create: Callable[[FileBuffer, StrindexSettings], Strindex]
	"""Add strings & pointers to the strindex by extracting them from a file buffer (bytearray)."""
	patch: Callable[[FileBuffer, Strindex], FileBuffer]
	"""Patch a file buffer (bytearray) using the strings & pointers from the provided strindex."""
