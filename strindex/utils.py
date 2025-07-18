import json
import re
import gzip
import hashlib
import time
import ahocorasick_rs
from typing import Generator, Callable


class PrintProgress():
	"""
	Extremely fast class to print progress percentage.
	Only takes ~0.1 seconds every 1'000'000 calls,
	or half of that if "iteration >= self.limit" is checked within the loop.
	"""

	total: int
	limit: int
	delta: int
	round: int
	percent: float

	def __init__(self, total: int, round: int = 0):
		self.total = total
		self.limit = 0
		self.delta = total // (10 ** (round + 2))
		self.round = None if round == 0 else round
		self.percent = 0
		self.start = time.time()
		self(0)

	def progress_bar_str(self, iteration: int, bar_length: int = 30) -> str:
		""" Returns a string with the progress bar. """
		progress = round(iteration / self.total * bar_length)
		return f"\r[{'#' * progress}{'-' * (bar_length - progress)}] {self.percent}% "

	def __call__(self, iteration: int):
		if iteration >= self.limit and self.percent < 100:
			self.limit += self.delta
			self.percent = round(iteration / self.total * 100, self.round)
			if callable(PrintProgress.callback):
				PrintProgress.callback(self)
			print(self.progress_bar_str(iteration), end="")
			if self.percent >= 100:
				print(f"({time.time() - self.start:.2f}s)")

	@property
	def callback() -> Callable[["PrintProgress"], None]:
		return globals().get("__print_progress_callback__")


class StrindexSettings():
	# These are really limited, so I would really like if you added your language's characters here and open a pull request <3
	CHARACTER_CLASSES = {
		"default": """\t\n !"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~… """,
		"latin": """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz""",
		"spanish": """¡¿ÁÉÍÓÚÜÑáéíóúüñã""",
		"italian": """ÀÈÉÌÒÓÙàèéìòóù""",
		"cyrillic": """ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂҃҄҅҆҇҈҉ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽӾ""",
	}

	md5: str
	whitelist: set[str]
	force_mode: bool
	min_length: int
	prefix_bytes: list[bytes]
	suffix_bytes: list[bytes]
	patch_replace: dict[str, str]
	clean_pattern: str
	source_language: str
	target_language: str
	among_languages: list[str]

	def __init__(self, **kwargs):
		self.md5 = kwargs.get("md5")
		self.whitelist = StrindexSettings.handle_whitelist(kwargs.get("whitelist") or "")
		self.force_mode = kwargs.get("force_mode") or False
		self.min_length = int(kwargs.get("min_length") or 1)
		self.prefix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("prefix_bytes") or [])
		self.suffix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("suffix_bytes") or [])
		self.patch_replace = kwargs.get("patch_replace") or {}
		self.clean_pattern = kwargs.get("clean_pattern") or ""
		self.source_language = kwargs.get("source_language")
		self.target_language = kwargs.get("target_language")
		self.among_languages = kwargs.get("among_languages") or []

	@staticmethod
	def handle_whitelist(whitelist: str) -> set[str]:
		return set(''.join([StrindexSettings.CHARACTER_CLASSES.get(whitelist, whitelist) for whitelist in (whitelist + ["default"])])) if whitelist else set()

	@staticmethod
	def handle_bytes_list(bytes_list: list[bytes]) -> list[bytes]:
		return [bytes.fromhex(prefix) for prefix in (bytes_list or [''])]

	def clean_string(self, string: str) -> str:
		return re.sub(self.clean_pattern, "", string)

	def patch_replace_string(self, string: str) -> str:
		""" Replaces the strings in the patch with the new strings. """
		for key, value in self.patch_replace.items():
			string = string.replace(key, value)
		return string


class Strindex():
	""" A class to parse and create strindex files. """

	HEADER = "You can freely create & delete informational lines in the header like this one.\n\n{}\n\n"
	INFO = f"//{'=' * 78}/pointer(s)/\n"
	COMPATIBLE_INFO = f"//{'=' * 78}| reallocate pointer(s) if 1 |\n// replace this string...\n//{'-' * 78}\n// ...with this string!\n"
	ORIGINAL_DEL = '=' * 80
	REPLACE_DEL = '-' * 80
	POINTERS_DEL = '/'
	POINTERS_SWITCHES_DEL = '|'

	full_header: str
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
	def get_strings_flat_original(self) -> list[str]:
		return [(string[0] if type == "compatible" else string) for string, type in zip(self.strings, self.type_order)]

	@property
	def get_strings_flat_replace(self) -> list[str]:
		return [(string[1] if type == "compatible" else string) for string, type in zip(self.strings, self.type_order)]

	def __init__(self):
		""" Parses a strindex file and returns a dictionary with the data. """

		self.full_header = ""
		self.settings = StrindexSettings()

		self.strings = []
		self.pointers = []
		self.type_order = []

	@classmethod
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
				previous_line_pos = 0
				while line := f.readline():
					if line.lstrip().startswith("{"):
						strindex_settings_lines = line
						strindex.full_header += line
						while True:
							try:
								strindex.settings = StrindexSettings(**json.loads(strindex_settings_lines))
							except json.JSONDecodeError as e:
								line = f.readline()
								if not line:
									raise ValueError("Error parsing Strindex settings.") from e
								strindex.full_header += line
								if line.lstrip().startswith("//"):
									continue
								if line.startswith(Strindex.ORIGINAL_DEL):
									raise ValueError("Error parsing Strindex settings: " + str(e)) from e
								strindex_settings_lines += line
							else:
								break
					elif line.startswith(Strindex.ORIGINAL_DEL):
						f.seek(previous_line_pos)
						break
					else:
						previous_line_pos = f.tell()
						strindex.full_header += line

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

	def write(self, filepath: str):
		""" Saves the strindex data to a file. """
		HEX_RJUST = 8

		self.assert_data()

		diff_settings = {k: v for k, v in self.settings.__dict__.items() if Strindex().settings.__dict__.get(k) != v}

		with open(filepath, 'w', encoding='utf-8') as f:
			if self.full_header:
				f.write(self.full_header)
			else:
				f.write(Strindex.HEADER.format(json.dumps(diff_settings, indent=4, default=lambda x: x.hex() if isinstance(x, bytes) else str(x))))

				if len(self.type_order) > 0:
					f.write(Strindex.COMPATIBLE_INFO if self.type_order[0] == "compatible" else Strindex.INFO)

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
						Strindex.POINTERS_DEL.join(hex(p or 0).lstrip("0x").rjust(HEX_RJUST, '0') for p in pointers) +
						Strindex.POINTERS_DEL + "\n" +
						strings + "\n"
					)

			f.seek(f.tell() - 1)
			f.truncate()

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
	def read(cls, filepath: str):
		with open(filepath, 'rb') as f:
			return cls(f.read())

	def write(self, filepath: str):
		with open(filepath, 'wb') as f:
			f.write(self)

	# Algorithms
	def yield_strings(self, sep: bytes = b'\x00', min_length: int = 1) -> Generator[tuple[str, int, int], None, None]:
		"""
		Yields all strings in a bytearray, separated by a given separator. Extremely fast.
		Skips strings that contain control characters and ones that are not valid UTF-8.
		"""
		SEP_LENGTH = len(sep)
		CONTROL_CHARS = set(bytes([*range(1, 9), *range(11, 32), 127]).replace(sep, b''))

		offset = 0
		print_progress = PrintProgress(len(self))
		for string in self.split(sep):
			if len(string) >= min_length and not any(ch in CONTROL_CHARS for ch in string):
				try:
					string_decoded = string.decode('utf-8')
				except UnicodeDecodeError:
					pass
				else:
					yield string_decoded, offset, offset + len(string)
					print_progress(offset)
			offset += len(string) + SEP_LENGTH
		print_progress(len(self))

	def strings_search_ordered(self, search_lst: list[bytes], prefix: bytes = b"\x00", suffix: bytes = b"\x00") -> list[int]:
		"""
		Returns the index of the first occurrence of every search list string in a bytearray.
		Extremely fast, but can only can work for search lists that are ordered by occurrence order.
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

	def strings_search(self, search_lst: list[bytes], prefixes: list[bytes] = [b""], suffixes: list[bytes] = [b""]) -> list[list[int]]:
		"""
		Returns a list containing the indexes of each occurrence of every search list string in the bytearray.
		Extremely fast, uses Aho-Corasick algorithm.
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

		ac = ahocorasick_rs.BytesAhoCorasick(search_lst_full)

		for index, start, _ in ac.find_matches_as_indexes(self):
			search_lst_indices[index].append(start + search_lst_prefix_length[index])

		return search_lst_indices[::len(prefixes) * len(suffixes)]

	# Shorthands
	def get(self, byte_length: int = None) -> bytes:
		byte_slice = self[self.cursor:self.cursor + (byte_length or self.byte_length)]
		self.cursor += byte_length or self.byte_length
		return bytes(byte_slice)

	def get_del(self, delimiter: bytes = b'\x00') -> bytes:
		byte_string = b''
		while (char := self.get(1)) != delimiter:
			byte_string += char
		return byte_string

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
			print(f'Warning: Replace string "{replace}" at {hex(self.cursor)} is longer than the original string ({len(replace_bytes)} > {original_length}). Truncating.')
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

		for string, start_offset, _ in self.yield_strings(min_length=settings.min_length):
			if original_bytes := original_bytes_from_offset(start_offset):
				temp_strindex["original"].append(string)
				temp_strindex["original_bytes"].append(original_bytes)

		if not temp_strindex["original"]:
			raise ValueError("No strings found in the file.")
		print(f"Created search dictionary with {len(temp_strindex['original_bytes'])} strings.")

		temp_strindex["pointers"] = self.strings_search(temp_strindex["original_bytes"], settings.prefix_bytes, settings.suffix_bytes)

		strindex = Strindex()
		for string, pointers in zip(temp_strindex["original"], temp_strindex["pointers"]):
			if pointers:
				strindex.strings.append(string)
				strindex.pointers.append(pointers)
				strindex.type_order.append("overwrite")

		print(f"Found pointers for {len(strindex.strings)} / {len(temp_strindex['original'])} strings.")

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
				print(f'String #{index} not found: "{strindex_original[index]}"')
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
				print(f"No pointers found for string #{index}")

	@property
	def md5(self) -> str:
		return hashlib.md5(self).hexdigest()
