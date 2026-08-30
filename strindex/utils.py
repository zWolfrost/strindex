import dataclasses
import gzip
import hashlib
import re
import time
import tomllib
from collections.abc import Callable
from functools import wraps
from io import StringIO
from json import JSONEncoder
from pathlib import Path
from typing import ClassVar

from ahocorasick_rs import BytesAhoCorasick, Implementation

from strindex.strings_find_fast import strings_find_fast


class Print:
	""" A wrapper for the print function. """

	class PrintLevel:
		DEBUG = ""
		INFO = "\033[1m"
		WARNING = "\033[93m"
		ERROR = "\033[91m"
		RESET = "\033[0m"

	quiet_mode = True
	color_mode = True

	@classmethod
	def print(cls, msg: str, tag: str | None = None, level: PrintLevel = None, **kwargs):
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
		self.total = total
		self.limit = 0
		self.delta = max(1, total // (10 ** (decimals + 2)))
		self.round = None if decimals == 0 else decimals
		self.percent = 0
		self.start = time.time()
		self(0)

	def __call__(self, iteration: int | None = None):
		if iteration is None:
			iteration = self.limit
		if iteration >= self.limit and self.percent < 100:
			self.limit += self.delta
			self.percent = round(iteration / self.total * 100, self.round)
			if (
				hasattr(Progress, "global_instance")
				and self is Progress.global_instance
				and hasattr(Progress, "global_callback")
			):
				Progress.global_callback(self)
			if self.percent >= 100:
				Print.debug(f"Action completed in {time.time() - self.start:.2f}s.")

	@classmethod
	def global_mark[**P, T](cls, func: Callable[P, T]) -> Callable[P, T]:
		""" Decorator to mark a function for progress printing. """
		@wraps(func)
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

	_compatible: bool | None
	_references: bool | None

	_raw: str | None
	md5: str | None
	force_mode: bool
	min_length: int
	prefix_bytes: list[bytes]
	suffix_bytes: list[bytes]
	ranges: list[range]
	whitelist: list[str]
	_whitelist: set[str]
	patch_replace: dict[str, str]
	clean_pattern: str
	source_language: str | None
	target_language: str | None
	among_languages: list[str]

	def __init__(self, **kwargs):
		self._compatible = kwargs.get("_compatible")
		self._references = kwargs.get("_references")

		self._raw = kwargs.get("_raw")
		self.md5 = kwargs.get("md5")
		self.force_mode = kwargs.get("force_mode") or False
		self.min_length = int(kwargs.get("min_length") or 1)
		self.prefix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("prefix_bytes") or [""])
		self.suffix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("suffix_bytes") or [""])
		self.ranges = StrindexSettings.handle_ranges(kwargs.get("ranges") or [])
		self.whitelist = kwargs.get("whitelist") or []
		self._whitelist = self.handle_whitelist(self.whitelist)
		self.patch_replace = kwargs.get("patch_replace") or {}
		self.clean_pattern = kwargs.get("clean_pattern") or ""
		self.source_language = kwargs.get("source_language")
		self.target_language = kwargs.get("target_language")
		self.among_languages = kwargs.get("among_languages") or []

	@classmethod
	def read_from_toml_data(cls, toml_data: str) -> "StrindexSettings":
		""" Reads the settings from TOML data. """
		try:
			toml_dict = tomllib.loads(toml_data)
		except Exception as e:
			raise ValueError("Error parsing Strindex TOML header.") from e

		return cls(**toml_dict, _raw=toml_data)

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
	def handle_bytes_list(bytes_list: list[bytes]) -> list[bytes]:
		assert all(len(bytes_str) % 2 == 0 for bytes_str in bytes_list), \
			"All of the hex byte strings must contain an even number of characters."
		return [bytes.fromhex(bytes_str) for bytes_str in bytes_list]

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
				if beg > end:
					raise ValueError(f"Invalid range: {range_str}. Start must be less than or equal to end.")
				parsed_ranges.append(range(beg, end))
			except ValueError as e:
				raise ValueError(f"Invalid range format: {range_str}. Expected format is 'start:end'.") from e
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
		return any(data[beg_offset - len(prefix):beg_offset] == prefix for prefix in self.prefix_bytes)

	def matches_suffix(self, data: bytearray, end_offset: int) -> bool:
		""" Checks if the data at the given offset matches any of the suffixes. """
		return any(data[end_offset:end_offset + len(suffix)] == suffix for suffix in self.suffix_bytes)

	def is_in_any_range(self, val: int) -> bool:
		""" Checks if the value is in any of the ranges. """
		return any(val in range for range in self.ranges) if self.ranges else True

	def is_in_whitelist(self, string: str) -> bool:
		""" Checks if the string is whitelisted. """
		return all(char in self._whitelist for char in string) if self._whitelist else True

	def get_dict(self) -> dict:
		return {k: v for k, v in vars(self).items() if not k.startswith("_")}

	def __repr__(self) -> str:
		return str(self.get_dict())


class Strindex:
	""" A class to parse and create strindex files. """

	TOKEN_DELIMITER = " "
	POINTERS_PREFIX = "@"
	OVERWRITE_PREFIX = POINTERS_PREFIX + "o" + TOKEN_DELIMITER
	COMPATIBLE_PREFIX = POINTERS_PREFIX + "c" + TOKEN_DELIMITER
	STRING_PREFIX = ">>" + TOKEN_DELIMITER
	COMPATIBLE_TRUE = "+"
	COMPATIBLE_FALSE = "-"

	_UNESCAPE_DICT: ClassVar[dict[str, str]] = {
		"\\": "\\",
		"t": "\t",
		"n": "\n",
		"r": "\r",
	}
	_UNESCAPE_RE = re.compile(r"\\([\\tnr])")
	@staticmethod
	def unescape_ctrl(s: str) -> str: # HACK
		return Strindex._UNESCAPE_RE.sub(lambda m: Strindex._UNESCAPE_DICT[m.group(1)], s)

	_ESCAPE_MAP = str.maketrans({
		"\\": r"\\",
		"\t": r"\t",
		"\n": r"\n",
		"\r": r"\r",
	})
	@staticmethod
	def escape_ctrl(string: str) -> str: # HACK
		return string.translate(Strindex._ESCAPE_MAP)

	@staticmethod
	def toml_dumps(obj: dict) -> str: # HACK
		""" Dumps a dictionary to a TOML string. """

		def formatter(val):
			if isinstance(val, list):
				return "[ " + ", ".join(formatter(v) for v in val) + " ]"
			if isinstance(val, dict):
				return "{ " + ", ".join(f'"{k}" = "{v}"' for k, v in val.items()) + " }"
			if isinstance(val, bytes):
				return f'"{val.hex()}"'
			if isinstance(val, range):
				return f'"{val.start:08x}:{val.stop - 1:08x}"'
			return JSONEncoder().encode(val)

		dumps = ""
		for key, value in obj.items():
			dumps += f"{key} = {formatter(value)}\n"
		return dumps

	settings: StrindexSettings

	strings: list[str | list[str, str]]
	pointers: list[list[int | bool]]
	type_order: list[str]

	@property
	def get_overwrite(self) -> list[str]:
		return [string for string, type in zip(self.strings, self.type_order, strict=True) if type == "overwrite"]

	@property
	def get_original(self) -> list[str]:
		return [string[0] for string, type in zip(self.strings, self.type_order, strict=True) if type == "compatible"]

	@property
	def get_replace(self) -> list[str]:
		return [string[1] for string, type in zip(self.strings, self.type_order, strict=True) if type == "compatible"]

	@property
	def get_offsets(self) -> list[list[int]]:
		return [pointers for pointers, type in zip(self.pointers, self.type_order, strict=True) if type == "overwrite"]

	@property
	def get_switches(self) -> list[list[bool]]:
		return [pointers for pointers, type in zip(self.pointers, self.type_order, strict=True) if type == "compatible"]

	@property
	def get_overwrite_and_original(self) -> list[str]:
		return [
			(string[0] if type == "compatible" else string) for string, type in
			zip(self.strings, self.type_order, strict=True)
		]

	@property
	def get_overwrite_and_replace(self) -> list[str]:
		return [
			(string[1] if type == "compatible" else string) for string, type in
			zip(self.strings, self.type_order, strict=True)
		]

	@property
	def get_identifiers(self) -> list[str]:
		return [
			(string[0] if type == "compatible" else ",".join(str(p) for p in pointers)) for string, pointers, type in
			zip(self.strings, self.pointers, self.type_order, strict=True)
		]

	def __init__(self):
		""" Parses a strindex file and returns a dictionary with the data. """

		self.settings = StrindexSettings()

		self.strings = []
		self.pointers = []
		self.type_order = []

	def parse_body_line(self, line: str):
		def raise_unexpected():
			raise ValueError(f"Unexpected line in strindex body:\n{line!r}")

		line = line.removesuffix("\n")

		if line.startswith(Strindex.POINTERS_PREFIX):
			if (
				self.type_order and self.strings and
				((self.type_order[-1] == "overwrite" and self.strings[-1] is None) or
				(self.type_order[-1] == "compatible" and self.strings[-1][1] is None))
			):
				raise_unexpected()

			if line.startswith(Strindex.OVERWRITE_PREFIX):
				line = line.removeprefix(Strindex.OVERWRITE_PREFIX)
				self.strings.append(None)
				self.pointers.append([int(p, 16) for p in line.split(Strindex.TOKEN_DELIMITER) if p])
				self.type_order.append("overwrite")
			elif line.startswith(Strindex.COMPATIBLE_PREFIX):
				line = line.removeprefix(Strindex.COMPATIBLE_PREFIX)
				original, switches = line.rsplit(Strindex.TOKEN_DELIMITER, 1)
				self.strings.append([Strindex.unescape_ctrl(original), None])
				self.pointers.append(
					[True] * int(switches.removeprefix("x")) if switches.removeprefix("x").isdigit() else
					[s == Strindex.COMPATIBLE_TRUE for s in switches if s]
				)
				self.type_order.append("compatible")
		elif line.startswith(Strindex.STRING_PREFIX):
			line = Strindex.unescape_ctrl(line.removeprefix(Strindex.STRING_PREFIX))
			if self.type_order[-1] == "overwrite" and self.strings[-1] is None:
				self.strings[-1] = line
			elif self.type_order[-1] == "compatible" and self.strings[-1][1] is None:
				self.strings[-1][1] = line
			else:
				raise_unexpected()
		elif line and not line.startswith("#"):
			raise_unexpected()

	def dump_body_entry(self, index: int) -> str:
		if self.type_order[index] == "overwrite":
			escaped_string = Strindex.escape_ctrl(self.strings[index])
			return (
				Strindex.OVERWRITE_PREFIX +
				Strindex.TOKEN_DELIMITER.join(f"{p or 0:08x}" for p in self.pointers[index]) + "\n" +
				(f"## {escaped_string}\n" if self.settings._references else "") +
				Strindex.STRING_PREFIX + escaped_string + "\n\n"
			)
		if self.type_order[index] == "compatible":
			return (
				Strindex.COMPATIBLE_PREFIX +
				Strindex.escape_ctrl(self.strings[index][0]) + Strindex.TOKEN_DELIMITER +
				(("x" + str(len(self.pointers[index]))) if all(self.pointers[index]) else
				"".join((Strindex.COMPATIBLE_TRUE if p else Strindex.COMPATIBLE_FALSE) for p in self.pointers[index])) +
				"\n" + Strindex.STRING_PREFIX + Strindex.escape_ctrl(self.strings[index][1]) + "\n\n"
			)
		raise ValueError(f"Invalid strindex type: {self.type_order[index]}")

	@classmethod
	@Progress.global_mark
	def read(cls, filepath: str) -> "Strindex":
		""" Parses a strindex file and returns a dictionary with the data. """

		strindex = cls()

		with Path.open(filepath, "rb") as f:
			is_gzipped = (f.read(2) == b"\x1f\x8b")

		with (
			gzip.open(filepath, "rt", encoding="utf-8", newline="") if is_gzipped
				else Path.open(filepath, "r", encoding="utf-8", newline="")
		) as f:
			full_header = ""
			while (line := f.readline()) and not line.startswith(Strindex.POINTERS_PREFIX):
				full_header += line

			strindex.settings = StrindexSettings.read_from_toml_data(full_header)

			f.seek(len(full_header.encode("utf-8")), 0)

			while line := f.readline():
				strindex.parse_body_line(line)

		strindex.assert_data()

		return strindex

	@Progress.global_mark
	def write(self, filepath: str, reference: bool = False) -> str:
		""" Saves the strindex data to a file. """

		HEADER_INFO = (
			"# You can freely create & delete comments in the header like these ones and the example below.\n"
			"# For more information about strindex files' settings and syntax see:\n"
			"# https://raw.githubusercontent.com/zWolfrost/strindex/refs/heads/main/strindex_example.txt\n"
		)
		OVERWRITE_INFO = (
			"# EXAMPLE OF REPLACEMENT:\n"
			f"# {Strindex.OVERWRITE_PREFIX}"
			f"[pointer]{Strindex.TOKEN_DELIMITER}[pointer]{Strindex.TOKEN_DELIMITER}[...]\n"
			f"# {Strindex.STRING_PREFIX}replace the string that was previously provided here, with this one!\n\n"
		)
		COMPATIBLE_INFO = (
			"# EXAMPLE OF REPLACEMENT:\n"
			f"# {Strindex.COMPATIBLE_PREFIX}"
			f"replace this string...{Strindex.TOKEN_DELIMITER}[reallocate N pointers if [xN] OR [+/-] N times]\n"
			f"# {Strindex.STRING_PREFIX}...with this string!\n\n"
		)

		self.assert_data()

		with (Path.open(filepath, "w", encoding="utf-8", newline="") if filepath else StringIO()) as f:
			if self.settings._raw is not None:
				f.write(self.settings._raw)
			else:
				f.write(HEADER_INFO + "\n" + Strindex.toml_dumps(self.settings.get_changed()) + "\n")

				if len(self.type_order) > 0:
					f.write(COMPATIBLE_INFO if self.type_order[0] == "compatible" else OVERWRITE_INFO)

			for i in range(len(self.strings)):
				f.write(self.dump_body_entry(i))

			f.seek(max(f.tell() - 1, 0))
			f.truncate()

			return f.getvalue() if filepath is None else filepath

	def normalize_to_overwrite(self, full_lst_offsets: list[int], full_lst_strings: list[str]):
		""" Converts compatible strings to overwrite strings and deletes them if necessary. """

		assert len(full_lst_strings) == len(full_lst_offsets), \
			"The full string and offset lists must be the same length."

		start_i = 0
		for i in range(len(self.strings)):
			if self.type_order[i] != "compatible":
				continue

			try:
				search_i = full_lst_strings.index(self.strings[i][0], start_i)
				offsets = full_lst_offsets[search_i]
			except ValueError:
				pass
			else:
				start_i = search_i + 1
				if any(self.pointers[i]):
					self.type_order[i] = "overwrite"
					self.pointers[i] = [p for p, s in zip(offsets, self.pointers[i], strict=False) if s]
					self.strings[i] = self.strings[i][1]

		for i in reversed(range(len(self.strings))):
			if self.type_order[i] == "compatible":
				Print.warning(f'String #{i+1} not found: "{self.strings[i][0]}"')
				del self.type_order[i]
				del self.pointers[i]
				del self.strings[i]

	def append_strindex_index(self, strindex: "Strindex", index: int):
		self.strings.append(strindex.strings[index])
		self.pointers.append(strindex.pointers[index])
		self.type_order.append(strindex.type_order[index])

	def assert_data(self):
		assert len(self.strings) == len(self.pointers) == len(self.type_order), (
			f"Overwrite, pointers and type order lists are not the same length"
			f" ({len(self.strings)} != {len(self.pointers)} != {len(self.type_order)})."
		)


class FileBytearray(bytearray):
	""" A class to handle bytearrays with additional methods and shorthands focused on file manipulation. """

	cursor: int = 0
	byte_length: int
	byte_order: str

	@classmethod
	@Progress.global_mark
	def read(cls, filepath: str):
		with Path.open(filepath, "rb") as f:
			return cls(f.read())

	@Progress.global_mark
	def write(self, filepath: str):
		with Path.open(filepath, "wb") as f:
			f.write(self)

	def copy(self) -> "FileBytearray":
		return FileBytearray(self)

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
			index = self.find(prefix + search_lst[search_index] + suffix, start_index)
			if index == -1:
				indices.append(None)
				misses += 1
				if misses > 1000:
					raise ValueError(
						"More than 1000 strings not found.\n"
						"Please make sure the search list is ordered by occurrence order\n"
						"and that the strings are present in the bytearray."
					)
				continue
			start_index = index + prefix_length + len(search_lst[search_index])
			indices.append(index + prefix_length)
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

		if prefixes is None:
			prefixes = [b""]
		if suffixes is None:
			suffixes = [b""]

		search_lst_safe = [s.encode("utf-8") if isinstance(s, str) else s for s in search_lst if s is not None]

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

		for index, start, _ in ac.find_matches_as_indexes(self, overlapping=True):
			search_lst_indices[index].append(start + search_lst_prefix_length[index])

		return search_lst_indices[::len(prefixes) * len(suffixes)]

	# Shorthands
	def get(self, byte_length: int | None = None) -> bytes:
		byte_slice = self[self.cursor:self.cursor + (byte_length or self.byte_length)]
		self.cursor += byte_length or self.byte_length
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
		return int.from_bytes(self.get(byte_length), byte_order or self.byte_order)

	def put_int(self, value: int, byte_length: int | None = None, byte_order: str | None = None) -> bytes:
		self[self.cursor:self.cursor + (byte_length or self.byte_length)] = (
			self.from_int(value, byte_length, byte_order)
		)
		return self.get(byte_length)

	def from_int(self, value: int, byte_length: int | None = None, byte_order: str | None = None) -> bytes:
		return value.to_bytes(byte_length or self.byte_length, byte_order or self.byte_order)

	def add_int(self, delta: int, byte_length: int | None = None, byte_order: str | None = None) -> bytes:
		value = self.get_int(byte_length, byte_order)
		self.cursor -= byte_length or self.byte_length
		return self.put_int(value + delta, byte_length, byte_order)

	def replace_string(self, replace: str, sep: bytes = b"\x00") -> bytes:
		original_length = 0

		for i in range(len(self) - self.cursor):
			if bytes([self[self.cursor + i]]) == sep:
				original_length = i
				break

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
		settings: StrindexSettings,
		original_bytes_from_offset: Callable[[int], bytes]
	) -> Strindex:
		temp_strindex = {
			"original": [],
			"pointers": [],
			"original_bytes": []
		}

		for string, start_offset, _ in self.strings_find(min_length=settings.min_length):
			if (original_bytes := original_bytes_from_offset(start_offset)) and settings.is_in_whitelist(string):
				temp_strindex["original"].append(string)
				temp_strindex["original_bytes"].append(original_bytes)

		if not temp_strindex["original"]:
			raise ValueError("No strings found in the file.")

		Print.debug(f"Created search list with {len(temp_strindex['original_bytes'])} strings.")

		if len(temp_strindex["original_bytes"]) > 10**6:
			Print.warning(
				"The search list is very large!\n"
				"This may take a bit to process;\n"
				"consider increasing the minimum string length."
			)

		temp_strindex["pointers"] = self.strings_search(
			temp_strindex["original_bytes"], settings.prefix_bytes, settings.suffix_bytes
		)

		strindex = Strindex()
		for string, pointers in zip(temp_strindex["original"], temp_strindex["pointers"], strict=True):
			pointers = [p for p in pointers if settings.is_in_any_range(p)]
			if pointers:
				strindex.pointers.append(pointers)
				strindex.strings.append(string)

		Print.debug(f"Found pointers for {len(strindex.strings)} / {len(temp_strindex['original'])} strings.")

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

		strindex_original = strindex.get_original
		strindex_replace = strindex.get_replace
		strindex_switches = strindex.get_switches

		for i, offset in enumerate(self.strings_search_ordered(strindex_original)):
			if offset is None:
				Print.warning(f'String #{i+1} not found: "{strindex_original[i]}"')
				continue

			update_dict["original_bytes"].append(original_bytes_from_offset(offset))
			update_dict["replaced_bytes"].append(replaced_bytes_from_offset(len(new_data)))
			update_dict["switches"].append(strindex_switches[i])
			new_data += data_from_string(strindex.settings.patch_replace_string(strindex_replace[i]))

		update_dict["pointers"] = self.strings_search(
			update_dict["original_bytes"], strindex.settings.prefix_bytes, strindex.settings.suffix_bytes
		)

		self.update_references(update_dict["pointers"], update_dict["replaced_bytes"], update_dict["switches"])

		update_dict = {
			"replaced_bytes": []
		}

		for overwrite in strindex.get_overwrite:
			update_dict["replaced_bytes"].append(replaced_bytes_from_offset(len(new_data)))
			new_data += data_from_string(strindex.settings.patch_replace_string(overwrite))

		self.update_references(strindex.get_offsets, update_dict["replaced_bytes"])

		return new_data

	def update_references(
		self,
		lst_pointers: list[list[int]],
		lst_replaced_bytes: list[bytes],
		lst_switches: list[list[bool]] | None = None
	):
		if lst_switches is None:
			lst_switches = [[True] * len(pointer) for pointer in lst_pointers]

		for i, (pointers, replaced_bytes, switches) in enumerate(
			zip(lst_pointers, lst_replaced_bytes, lst_switches, strict=True)
		):
			if pointers:
				if len(pointers) != len(switches):
					Print.warning(
						f"The number of switches for string #{i}\n"
						f"doesn't match the number of pointers ({len(switches)} != {len(pointers)})"
					)
				for pointer, switch in zip(pointers, switches, strict=False):
					if switch:
						self[pointer:pointer + self.byte_length] = replaced_bytes
			else:
				Print.warning(f"No pointers found for string #{i}")

	@property
	def md5(self) -> str:
		return hashlib.md5(self).hexdigest()

	@property
	def md5_backup_suffix(self) -> str:
		MD5_SLICE_LENGTH = 8
		return "_" + self.md5[:MD5_SLICE_LENGTH] + ".bak"


@dataclasses.dataclass(frozen=True)
class ModuleSettings:
	default_byte_length: int | None = None
	default_byte_order: str | None = None
	filter_after_create: bool = True
