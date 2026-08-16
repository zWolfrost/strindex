import tomllib
from json import JSONEncoder
import re
import gzip
import hashlib
import time
from io import StringIO
from ahocorasick_rs import BytesAhoCorasick, Implementation
from strindex.strings_find_fast import strings_find_fast
from functools import wraps
from typing import Callable


class Print():
	"""
	A wrapper for the print function.
	"""

	class PrintLevel():
		DEBUG = ""
		INFO = "\033[1m"
		WARNING = "\033[93m"
		ERROR = "\033[91m"
		RESET = "\033[0m"

	quiet_mode = True
	color_mode = True

	@classmethod
	def print(cls, msg: str, tag: str = None, level: PrintLevel = None, **kwargs):
		if not cls.quiet_mode:
			tag = f"[{tag}] " if tag and not msg.startswith("[") else ""
			if cls.color_mode and level:
				print(level, tag, msg, cls.PrintLevel.RESET, sep="", **kwargs)
			else:
				print(tag, msg, sep="", **kwargs)
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


class Progress():
	"""
	A class to handle progress printing.
	"""

	global_instance: "Progress"
	global_callback: Callable[["Progress"], None]

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

	def __call__(self, iteration: int = None):
		if not iteration:
			iteration = self.limit
		if iteration >= self.limit and self.percent < 100:
			self.limit += self.delta
			self.percent = round(iteration / self.total * 100, self.round)
			if hasattr(Progress, "global_instance") and self is Progress.global_instance \
		 		and hasattr(Progress, "global_callback"):
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


class StrindexSettings():
	# These are really limited, so I would really like if you added your language's characters here and open a pull request <3
	CHARACTER_CLASSES = {
		"default": """\t\n !"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~… """,
		"latin": """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz""",
		"spanish": """¡¿ÁÉÍÓÚÜÑáéíóúüñã""",
		"italian": """ÀÈÉÌÒÓÙàèéìòóù""",
		"cyrillic": """ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂҃҄҅҆҇҈҉ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽӾ""",
	}

	raw_settings: str
	md5: str
	whitelist: set[str]
	force_mode: bool
	min_length: int
	prefix_bytes: list[bytes]
	suffix_bytes: list[bytes]
	ranges: list[range]
	patch_replace: dict[str, str]
	clean_pattern: str
	source_language: str
	target_language: str
	among_languages: list[str]

	def __init__(self, **kwargs):
		self.raw_settings = None
		self.md5 = kwargs.get("md5")
		self.whitelist = StrindexSettings.handle_whitelist(kwargs.get("whitelist") or "")
		self.force_mode = kwargs.get("force_mode") or False
		self.min_length = int(kwargs.get("min_length") or 1)
		self.prefix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("prefix_bytes") or [''])
		self.suffix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("suffix_bytes") or [''])
		self.ranges = StrindexSettings.handle_ranges(kwargs.get("ranges") or [])
		self.patch_replace = kwargs.get("patch_replace") or {}
		self.clean_pattern = kwargs.get("clean_pattern") or ""
		self.source_language = kwargs.get("source_language")
		self.target_language = kwargs.get("target_language")
		self.among_languages = kwargs.get("among_languages") or []

	@classmethod
	def read_from_toml_str(cls, toml_str: str) -> "StrindexSettings":
		""" Reads the settings from a TOML string. """
		settings = cls(**tomllib.loads(toml_str))
		settings.raw_settings = toml_str
		return settings

	def get_changed(self) -> dict:
		""" Returns a dictionary with the settings that are different from the default settings. """
		CURRENT_SETTINGS = vars(self)
		DEFAULT_SETTINGS = vars(StrindexSettings())
		return {k: v for k, v in CURRENT_SETTINGS.items() if DEFAULT_SETTINGS.get(k) != v}

	@staticmethod
	def handle_whitelist(whitelist: str) -> set[str]:
		return set(''.join([StrindexSettings.CHARACTER_CLASSES.get(whitelist, whitelist) for whitelist in (whitelist + ["default"])])) if whitelist else set()

	@staticmethod
	def handle_bytes_list(bytes_list: list[bytes]) -> list[bytes]:
		assert all(len(bytes_str) % 2 == 0 for bytes_str in bytes_list), "All of the hex byte strings must contain an even number of characters."
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

	def __repr__(self) -> str:
		return str(vars(self))


class Strindex():
	""" A class to parse and create strindex files. """

	SEP_COUNT = 80
	ORIGINAL_DEL = '=' * SEP_COUNT
	REPLACE_DEL = '-' * SEP_COUNT
	POINTERS_DEL = '/'
	POINTERS_SWITCHES_DEL = '|'

	settings: StrindexSettings

	strings: list[str | list[str, str]]
	pointers: list[list[int | bool]]
	type_order: list[str]

	@property
	def get_overwrite(self) -> list[str]:
		return [string for string, type in zip(self.strings, self.type_order) if type == "overwrite"]

	@property
	def get_original(self) -> list[str]:
		return [string[0] for string, type in zip(self.strings, self.type_order) if type == "compatible"]

	@property
	def get_replace(self) -> list[str]:
		return [string[1] for string, type in zip(self.strings, self.type_order) if type == "compatible"]

	@property
	def get_offsets(self) -> list[list[int]]:
		return [pointers for pointers, type in zip(self.pointers, self.type_order) if type == "overwrite"]

	@property
	def get_switches(self) -> list[list[bool]]:
		return [pointers for pointers, type in zip(self.pointers, self.type_order) if type == "compatible"]

	@property
	def get_overwrite_and_original(self) -> list[str]:
		return [(string[0] if type == "compatible" else string) for string, type in zip(self.strings, self.type_order)]

	@property
	def get_overwrite_and_replace(self) -> list[str]:
		return [(string[1] if type == "compatible" else string) for string, type in zip(self.strings, self.type_order)]

	@property
	def get_identifiers(self) -> list[str]:
		return [(string[0] if type == "compatible" else ",".join(str(p) for p in pointers)) for string, pointers, type in zip(self.strings, self.pointers, self.type_order)]

	def __init__(self):
		""" Parses a strindex file and returns a dictionary with the data. """

		self.settings = StrindexSettings()

		self.strings = []
		self.pointers = []
		self.type_order = []

	@classmethod
	@Progress.global_mark
	def read(cls, filepath: str) -> "Strindex":
		""" Parses a strindex file and returns a dictionary with the data. """

		strindex = cls()

		with open(filepath, 'rb') as f:
			is_gzipped = (f.read(2) == b'\x1f\x8b')

		if is_gzipped:
			stream = gzip.open(filepath, 'rt', encoding='utf-8')
		else:
			stream = open(filepath, 'r', encoding='utf-8')

		with stream as f:
			try:
				full_header = ""
				previous_line_pos = 0
				while line := f.readline():
					if line.startswith(Strindex.ORIGINAL_DEL):
						f.seek(previous_line_pos)
						break
					previous_line_pos = f.tell()
					full_header += line

				strindex.settings = StrindexSettings.read_from_toml_str(full_header)

				next_str_type = ""
				is_start = True
				while line := f.readline():
					line = line.rstrip('\n')
					if line.startswith(Strindex.ORIGINAL_DEL):
						is_start = True
						line = line.lstrip(Strindex.ORIGINAL_DEL)

						if next_str_type == "original":
							strindex.strings[-1][1] = strindex.strings[-1][0]

						try:
							if Strindex.POINTERS_DEL in line:
								next_str_type = "overwrite"
								strindex.strings.append('')
								strindex.pointers.append([int(p, 16) for p in line.split(Strindex.POINTERS_DEL)[1:-1] if p])
								strindex.type_order.append("overwrite")
							else:
								next_str_type = "original"
								strindex.strings.append(['', ''])
								strindex.pointers.append([bool(int(p)) for p in line.strip(Strindex.POINTERS_SWITCHES_DEL) if p])
								strindex.type_order.append("compatible")
						except Exception as e:
							raise ValueError(f"Error parsing Strindex pointers: {line}") from e
					elif line == Strindex.REPLACE_DEL and next_str_type == "original":
						is_start = True
						next_str_type = "replace"
					else:
						if not is_start:
							line = "\n" + line
						is_start = False

						if next_str_type == "overwrite":
							strindex.strings[-1] += line
						elif next_str_type == "original":
							strindex.strings[-1][0] += line
						elif next_str_type == "replace":
							strindex.strings[-1][1] += line
			except UnicodeDecodeError as e:
				raise ValueError(f"Error decoding Strindex at char {f.tell()}") from e

		if strindex.strings and strindex.strings[-1] == ['', '']:
			strindex.strings.pop()
			strindex.pointers.pop()
			strindex.type_order.pop()

		strindex.assert_data()

		return strindex

	@Progress.global_mark
	def write(self, filepath: str) -> str | None:
		""" Saves the strindex data to a file. """

		HEADER_INFO = "# You can freely create & delete comments in the header like these ones and the example below.\n# For more information about strindex files settings and syntax see:\n# https://raw.githubusercontent.com/zWolfrost/strindex/refs/heads/main/strindex_example.txt\n"
		OVERWRITE_INFO = f"# EXAMPLE OF REPLACEMENT:\n# {'=' * Strindex.SEP_COUNT}/pointer(s)/\n# replace the string that was previously provided with this one!\n\n"
		COMPATIBLE_INFO = f"# EXAMPLE OF REPLACEMENT:\n# {'=' * Strindex.SEP_COUNT}|reallocate pointer(s) if 1, or skip if 0|\n# replace this string...\n# {'-' * Strindex.SEP_COUNT}\n# ...with this string!\n\n"

		HEX_RJUST = 8

		self.assert_data()

		def toml_dumps_hack(obj: dict) -> str:
			def formatter(val):
				if isinstance(val, list):
					return "[ " + ", ".join(formatter(v) for v in val) + " ]"
				if isinstance(val, bytes):
					return f"\"{val.hex()}\""
				if isinstance(val, range):
					return f"\"{val.start:0{HEX_RJUST}x}:{val.stop - 1:0{HEX_RJUST}x}\""
				return JSONEncoder().encode(val)

			dumps = ""
			for key, value in obj.items():
				dumps += f"{key} = {formatter(value)}\n"
			return dumps

		stream = open(filepath, 'w', encoding='utf-8', newline='\n') if filepath else StringIO()

		with stream as f:
			if self.settings.raw_settings:
				f.write(self.settings.raw_settings)
			else:
				f.write(HEADER_INFO + "\n" + toml_dumps_hack(self.settings.get_changed()) + "\n")

				if len(self.type_order) > 0:
					f.write(COMPATIBLE_INFO if self.type_order[0] == "compatible" else OVERWRITE_INFO)

			for strings, pointers, type in zip(self.strings, self.pointers, self.type_order):
				if type == "compatible":
					f.write(
						Strindex.ORIGINAL_DEL + Strindex.POINTERS_SWITCHES_DEL +
						"".join(str(int(bool(p))) for p in pointers) +
						Strindex.POINTERS_SWITCHES_DEL + "\n" +
						strings[0] + "\n" +
						Strindex.REPLACE_DEL + "\n" +
						strings[1] + "\n"
					)
				else:
					f.write(
						Strindex.ORIGINAL_DEL + Strindex.POINTERS_DEL +
						Strindex.POINTERS_DEL.join(f"{p or 0:0{HEX_RJUST}x}" for p in pointers) +
						Strindex.POINTERS_DEL + "\n" +
						strings + "\n"
					)

			f.seek(f.tell() - 1)
			f.truncate()

			if filepath is None:
				return f.getvalue()

	def append_strindex_index(self, strindex: "Strindex", index: int):
		self.strings.append(strindex.strings[index])
		self.pointers.append(strindex.pointers[index])
		self.type_order.append(strindex.type_order[index])

	def assert_data(self):
		assert len(self.strings) == len(self.pointers) == len(self.type_order), f"Overwrite, pointers and type order lists are not the same length ({len(self.strings)} != {len(self.pointers)} != {len(self.type_order)})."


class FileBytearray(bytearray):
	""" A class to handle bytearrays with additional methods and shorthands focused on file manipulation. """
	cursor: int = 0
	byte_length: int
	byte_order: str

	@classmethod
	@Progress.global_mark
	def read(cls, filepath: str):
		with open(filepath, 'rb') as f:
			return cls(f.read())

	@Progress.global_mark
	def write(self, filepath: str):
		with open(filepath, 'wb') as f:
			f.write(self)

	# Algorithms
	@Progress.global_mark
	def strings_find(self, sep: bytes = b'\x00', min_length: int = 1, ranges: list[range] = []) -> list[tuple[str, int, int]]:
		"""
		Returns all strings in a bytearray, separated by a given separator.
		Skips strings that contain control characters and ones that are not valid UTF-8.
		Implemented in C for speed.
		"""

		return strings_find_fast(self, int(sep[0]), min_length, [(r.start, r.stop) for r in ranges])

	@Progress.global_mark
	def strings_search_ordered(self, search_lst: list[bytes], prefix: bytes = b"\x00", suffix: bytes = b"\x00") -> list[int]:
		"""
		Returns the index of the first occurrence of every search list string in a bytearray.
		Can only can work for search lists that are ordered by occurrence order.
		"""
		search_lst = [search.encode('utf-8') if isinstance(search, str) else search for search in search_lst]
		indices = []
		prefix_length = len(prefix)
		start_index = 0
		for search_index in range(len(search_lst)):
			index = self.find(prefix + search_lst[search_index] + suffix, start_index)
			if index == -1:
				indices.append(None)
				continue
			start_index = index + prefix_length + len(search_lst[search_index])
			indices.append(index + prefix_length)
		return indices

	@Progress.global_mark
	def strings_search(self, search_lst: list[bytes], prefixes: list[bytes] = [b""], suffixes: list[bytes] = [b""]) -> list[list[int]]:
		"""
		Returns a list containing the indexes of each occurrence of every search list string in the bytearray.
		Uses Aho-Corasick algorithm.
		"""
		if not search_lst:
			return []

		search_lst_safe = [s.encode('utf-8') if isinstance(s, str) else s for s in search_lst if s is not None]

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
	def get(self, byte_length: int = None) -> bytes:
		byte_slice = self[self.cursor:self.cursor + (byte_length or self.byte_length)]
		self.cursor += byte_length or self.byte_length
		return bytes(byte_slice)

	def put(self, value: bytes, byte_length: int = None) -> bytes:
		if not isinstance(value, bytes):
			value = bytes(value, 'utf-8')
		if byte_length is None:
			byte_length = len(value)
		self[self.cursor:self.cursor + byte_length] = value
		self.cursor += byte_length
		return value

	def get_int(self, byte_length: int = None, byte_order: str = None) -> int:
		return int.from_bytes(self.get(byte_length), byte_order or self.byte_order)

	def put_int(self, value: int, byte_length: int = None, byte_order: str = None) -> bytes:
		self[self.cursor:self.cursor + (byte_length or self.byte_length)] = self.from_int(value, byte_length, byte_order)
		return self.get(byte_length)

	def from_int(self, value: int, byte_length: int = None, byte_order: str = None) -> bytes:
		return value.to_bytes(byte_length or self.byte_length, byte_order or self.byte_order)

	def add_int(self, delta: int, byte_length: int = None, byte_order: str = None) -> bytes:
		value = self.get_int(byte_length, byte_order)
		self.cursor -= byte_length or self.byte_length
		return self.put_int(value + delta, byte_length, byte_order)

	def replace_string(self, replace: str, delimiter: bytes = b'\x00') -> bytes:
		original_length = 0

		for i in range(len(self) - self.cursor):
			if bytes([self[self.cursor + i]]) == delimiter:
				original_length = i
				break

		replace_bytes = replace.encode('utf-8')

		if len(replace_bytes) > original_length:
			Print.warning(f'Replace string "{replace}" at {hex(self.cursor)} is longer than the original string ({len(replace_bytes)} > {original_length}); Truncating.')
			replace_bytes = replace_bytes[:original_length]
		else:
			replace_bytes = replace_bytes.ljust(original_length, delimiter)

		self[self.cursor:self.cursor + original_length] = replace_bytes

	# Macros
	def create_pointers_macro(self, settings: StrindexSettings, original_bytes_from_offset: Callable[[int], bytes]) -> Strindex:
		temp_strindex = {
			"original": [],
			"pointers": [],
			"original_bytes": []
		}

		for string, start_offset, _ in self.strings_find(min_length=settings.min_length, ranges=settings.ranges):
			if original_bytes := original_bytes_from_offset(start_offset):
				temp_strindex["original"].append(string)
				temp_strindex["original_bytes"].append(original_bytes)

		if not temp_strindex["original"]:
			raise ValueError("No strings found in the file.")

		Print.debug(f"Created search list with {len(temp_strindex['original_bytes'])} strings.")

		if len(temp_strindex['original_bytes']) > 10**6:
			Print.warning(f"The search list is very large!\nThis may take a bit to process;\nconsider increasing the minimum string length.")

		temp_strindex["pointers"] = self.strings_search(temp_strindex["original_bytes"], settings.prefix_bytes, settings.suffix_bytes)

		strindex = Strindex()
		for string, pointers in zip(temp_strindex["original"], temp_strindex["pointers"]):
			if pointers:
				strindex.strings.append(string)
				strindex.pointers.append(pointers)
				strindex.type_order.append("overwrite")

		Print.debug(f"Found pointers for {len(strindex.strings)} / {len(temp_strindex['original'])} strings.")

		return strindex

	def patch_pointers_macro(self, strindex: Strindex, original_bytes_from_offset: Callable[[int], bytes], replaced_bytes_from_offset: Callable[[int], bytes], data_from_string: Callable[[str], bytearray]) -> bytearray:
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

		for index, offset in enumerate(self.strings_search_ordered(strindex_original)):
			if offset is None:
				Print.warning(f'String #{index} not found: "{strindex_original[index]}"')
				continue

			update_dict["original_bytes"].append(original_bytes_from_offset(offset))
			update_dict["replaced_bytes"].append(replaced_bytes_from_offset(len(new_data)))
			update_dict["switches"].append(strindex_switches[index])
			new_data += data_from_string(strindex.settings.patch_replace_string(strindex_replace[index]))

		update_dict["pointers"] = self.strings_search(update_dict["original_bytes"], strindex.settings.prefix_bytes, strindex.settings.suffix_bytes)

		self.update_references(update_dict["pointers"], update_dict["replaced_bytes"], update_dict["switches"])

		update_dict = {
			"replaced_bytes": []
		}

		for overwrite in strindex.get_overwrite:
			update_dict["replaced_bytes"].append(replaced_bytes_from_offset(len(new_data)))
			new_data += data_from_string(strindex.settings.patch_replace_string(overwrite))

		self.update_references(strindex.get_offsets, update_dict["replaced_bytes"])

		return new_data

	def update_references(self, pointers: list[list[int]], replaced_bytes: list[bytes], switches: list[list[bool]] = None):
		if switches is None:
			switches = [[True] * len(pointer) for pointer in pointers]

		for index, (pointers, replaced_bytes, switches) in enumerate(zip(pointers, replaced_bytes, switches)):
			if pointers:
				for pointer, switch in zip(pointers, switches):
					if switch:
						self[pointer:pointer + self.byte_length] = replaced_bytes
			else:
				Print.warning(f"No pointers found for string #{index}")

	@property
	def md5(self) -> str:
		return hashlib.md5(self).hexdigest()

	@property
	def md5_backup_suffix(self) -> str:
		MD5_SLICE_LENGTH = 8
		return "_" + self.md5[:MD5_SLICE_LENGTH] + ".bak"
