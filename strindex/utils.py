import json, re
from typing import Generator


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
	print_end: str

	def __init__(self, total: int, round: int = 0):
		self.total = total
		self.limit = 0
		self.delta = total // (10 ** (round + 2))
		self.round = None if round == 0 else round
		self.percent = 0
		self.print_end = "%" + " " * (round + 3) + "\r"
		self(0)

	def __call__(self, iteration: int):
		if iteration >= self.limit:
			self.limit += self.delta
			self.percent = round(iteration / self.total * 100, self.round)
			if callable(PrintProgress.callback):
				PrintProgress.callback(self)
			else:
				print(self.percent, end=self.print_end)

	@property
	def callback():
		return globals().get("__print_progress_callback__")

class StrindexSettings():
	# These are really limited, so I would really like if you added your language's characters here and open a pull request <3
	CHARACTER_CLASSES = {
		"default": """\t\n !"#$%&'()*+,-./0123456789:;<=>?@[\]^_`{|}~… """,
		"latin": """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz""",
		"spanish": """¡¿ÁÉÍÓÚÜÑáéíóúüñã""",
		"cyrillic": """ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂҃҄҅҆҇҈҉ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽӾ""",
	}

	md5: str
	whitelist: set[str]
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
		self.whitelist = StrindexSettings.handle_whitelist(kwargs.get("whitelist"))
		self.min_length = kwargs.get("min_length") or 1
		self.prefix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("prefix_bytes"))
		self.suffix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("suffix_bytes"))
		self.patch_replace = kwargs.get("patch_replace") or {}
		self.clean_pattern = kwargs.get("clean_pattern") or ""
		self.source_language = kwargs.get("source_language")
		self.target_language = kwargs.get("target_language")
		self.among_languages = kwargs.get("among_languages") or []

	@staticmethod
	def handle_whitelist(whitelist: str):
		return set(''.join([StrindexSettings.CHARACTER_CLASSES.get(whitelist, whitelist) for whitelist in (whitelist + ["default"])])) if whitelist else None

	@staticmethod
	def handle_bytes_list(bytes_list: list[bytes]):
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

	DELIMITERS = (f"{'=' * 80}", f"{'-' * 80}", f'/', f'-')
	HEADER = f"You can freely delete informational lines in the header like this one.\n\n{{}}\n\n"
	INFO = f"//{'=' * 78}/ offset / offset(s)-of-rva-pointer(s) /\n"
	COMPATIBLE_INFO = f"//{'=' * 78}[reallocate pointer(s) if 1]\n// replace this string...\n//{'-' * 78}\n// ...with this string!\n"

	full_header: str
	settings: StrindexSettings
	type_order: list[str]
	rva_bytes_length: int

	overwrite: list[str]
	pointers: list[list[int]]
	offsets: list[int]

	original: list[str]
	replace: list[str]
	pointers_switches: list[list[bool]]

	def __init__(self):
		""" Parses a strindex file and returns a dictionary with the data. """

		self.full_header = ""
		self.settings = StrindexSettings()
		self.type_order = []

		self.overwrite = []
		self.pointers = []
		self.offsets = []

		self.original = []
		self.replace = []
		self.pointers_switches = []


	@staticmethod
	def read(filepath: str):
		""" Parses a strindex file and returns a dictionary with the data. """

		strindex = Strindex()

		with open(filepath, 'r', encoding='utf-8') as f:
			while line := f.readline():
				if line.startswith("{"):
					strindex_settings_lines = line
					strindex.full_header += line
					while True:
						try:
							strindex.settings = StrindexSettings(**json.loads(strindex_settings_lines))
						except json.JSONDecodeError as e:
							line = f.readline()
							strindex.full_header += line
							if line.lstrip().startswith("//"):
								continue
							if line.startswith(Strindex.DELIMITERS[0]):
								raise ValueError("Error parsing Strindex settings: " + str(e))
							strindex_settings_lines += line
						else:
							break
				elif line.startswith(Strindex.DELIMITERS[0]):
					f.seek(f.tell() - len(line))
					break
				else:
					strindex.full_header += line

			next_lst = ""
			is_start = True
			while line := f.readline():
				line = line.rstrip('\n')
				if line.startswith(Strindex.DELIMITERS[0]):
					is_start = True
					line = line.lstrip(Strindex.DELIMITERS[0])

					if next_lst == "original":
						strindex.replace[-1] = strindex.original[-1]

					if Strindex.DELIMITERS[2] in line:
						next_lst = "overwrite"
						strindex.type_order.append("overwrite")
						strindex.overwrite.append('')

						needles = [[int(p, 16) if p else None for p in hex.split(Strindex.DELIMITERS[3])] for hex in line.split(Strindex.DELIMITERS[2])[1:-1]]
						strindex.pointers.append(needles[-1] if len(needles) >= 1 and any(needles[-1]) else [])
						strindex.offsets.append(needles[-2][0] if len(needles) >= 2 else None)
					else:
						next_lst = "original"
						strindex.type_order.append("compatible")
						strindex.original.append('')
						strindex.replace.append('')

						strindex.pointers_switches.append([bool(int(p)) for p in line])
				elif line == Strindex.DELIMITERS[1] and next_lst == "original":
					is_start = True
					next_lst = "replace"
				else:
					if not is_start:
						line = "\n" + line
					is_start = False

					getattr(strindex, next_lst)[-1] += line

		strindex.assert_data()

		return strindex

	def write(self, filepath: str):
		""" Saves the strindex data to a file. """
		self.assert_data()

		diff_settings = {k: v for k, v in self.settings.__dict__.items() if Strindex().settings.__dict__.get(k) != v}

		with open(filepath, 'w', encoding='utf-8') as f:
			if self.full_header:
				f.write(self.full_header)
			else:
				f.write(Strindex.HEADER.format(json.dumps(diff_settings, indent=4, default=lambda x: x.hex() if isinstance(x, bytes) else str(x))))
				f.write(Strindex.COMPATIBLE_INFO if self.type_order[0] == "compatible" else Strindex.INFO)

			for index, type in self.iterate_type_count():
				if type == "compatible":
					f.write(
						Strindex.DELIMITERS[0] +
						"".join([str(int(bool(p))) for p in self.pointers_switches[index]]) + "\n" +
						self.original[index] + "\n" +
						Strindex.DELIMITERS[1] + "\n" +
						self.replace[index] + "\n"
					)
				else:
					f.write(
						Strindex.DELIMITERS[0] + Strindex.DELIMITERS[2] +
						hex(self.offsets[index] or 0).lstrip("0x").rjust(8, '0') + Strindex.DELIMITERS[2] +
						Strindex.DELIMITERS[3].join([hex(p or 0).lstrip("0x").rjust(8, '0') for p in self.pointers[index]]) +
						Strindex.DELIMITERS[2] + "\n" +
						self.overwrite[index] + "\n"
					)

			f.seek(f.tell() - 1)
			f.truncate()


	def iterate_type_count(self):
		types = {}
		for type in self.type_order:
			types[type] = (types[type] + 1) if type in types else 0
			yield types[type], type

	def append_to_strindex(self, strindex, type: str, index: int):
		if type == "compatible":
			strindex.original.append(self.original[index])
			strindex.replace.append(self.replace[index])
			strindex.pointers_switches.append(self.pointers_switches[index])
		else:
			strindex.overwrite.append(self.overwrite[index])
			strindex.pointers.append(self.pointers[index])
			strindex.offsets.append(self.offsets[index])

		strindex.type_order.append(type)


	def assert_data(self):
		assert len(self.overwrite) == len(self.pointers), f"Overwrite and pointers lists are not the same length ({len(self.overwrite)} != {len(self.pointers)})."
		assert len(self.original) == len(self.replace) == len(self.pointers_switches), f"Original, replace and pointers_switches lists are not the same length ({len(self.original)} != {len(self.replace)} != {len(self.pointers_switches)})."
		assert len(self.type_order) == len(self.overwrite) + len(self.original), f"Type order list is not the same length ({len(self.type_order)} != {len(self.overwrite) + len(self.original)})."

class FileBytearray(bytearray):
	""" A class to handle bytearrays with additional methods. """

	def yield_strings(self, sep=b'\x00') -> Generator[tuple[str, int], None, None]:
		print_progress = PrintProgress(len(self))
		byte_string = b''
		for offset, char in enumerate(self):
			char = bytes([char])
			if char == sep:
				try:
					string = byte_string.decode('utf-8')
				except UnicodeDecodeError:
					continue
				else:
					yield string, offset - len(byte_string)
				finally:
					byte_string = b''
					print_progress(offset)
			else:
				byte_string += char

	def get_indices_ordered(self, search_lst: list[bytes], prefix: bytes = b"", suffix: bytes = b"") -> list[int]:
		"""
		Returns the index of the first occurrence of every search list string in a bytearray.
		Extremely fast, but can only can work for search lists that are ordered by occurrence order.
		"""
		search_lst = [bytes(search, 'utf-8') if isinstance(search, str) else search for search in search_lst]
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

	def get_indices_fixed(self, search_lst: list[bytes], prefixes: list[bytes] = [b""], suffixes: list[bytes] = [b""]) -> list[list[int]]:
		"""
		Returns a list containing the indexes of each occurrence of every search list string in a bytearray.
		Extremely fast, but can only can work for unique search strings of fixed length (length is taken from 1st element).
		"""
		if not search_lst:
			return []

		search_lst_safe = [s for s in search_lst if s is not None]

		assert len(search_lst_safe) == len(set(search_lst_safe)), "Search list is not unique."
		assert all(len(search) == len(search_lst_safe[0]) for search in search_lst_safe), "Search list is not fixed length."
		assert all(len(prefix) == len(prefixes[0]) for prefix in prefixes), "Prefix list is not fixed length."

		fixed_prefix_length = len(prefixes[0])
		fixed_length = fixed_prefix_length + len(search_lst_safe[0]) + len(suffixes[0])

		indices_dict = {}
		for search_string in search_lst_safe:
			lst = []
			for prefix in prefixes:
				for suffix in suffixes:
					indices_dict[prefix + search_string + suffix] = lst

		print_progress = PrintProgress(len(self))
		for offset in range(len(self)):
			cur_bytes = bytes(self[offset:offset + fixed_length])
			if cur_bytes in indices_dict:
				indices_dict[cur_bytes].append(offset + fixed_prefix_length)
			if offset >= print_progress.limit:
				print_progress(offset)

		indices = list(indices_dict.values())[::len(prefixes) * len(suffixes)]
		for search_index, search_string in enumerate(search_lst):
			if search_string is None:
				indices.insert(search_index, search_string)

		return indices
