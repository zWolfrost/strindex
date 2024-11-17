import json
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

class Strindex():
	""" A class to parse and create strindex files. """

	CHARACTER_CLASSES = { # Please add your language's characters here and open a pull request <3
		"default": """\t\n !"#$%&'()*+,-./0123456789:;<=>?@[\]^_`{|}~… """,
		"latin": """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz""",
		"spanish": """¡¿ÁÉÍÓÚÜÑáéíóúüñã""",
		"cyrillic": """ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂҃҄҅҆҇҈҉ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽӾ""",
	}

	DELIMITERS = (f"{'=' * 80}", f"{'-' * 80}", f'/', f'-')
	HEADER = f"You can freely delete informational lines in the header like this one.\n\n{{}}\n\n"
	INFO = f"#{'=' * 79}/ offset /  rva   / offset(s)-of-rva-pointer(s) /\n"
	COMPATIBLE_INFO = f"#{'=' * 79}[reallocate pointer(s) if 1]\n# replace this string...\n#{'-' * 79}\n# ...with this string!\n"

	full_header: str
	settings: dict
	type_order: list[str]
	rva_bytes_length: int

	overwrite: list[str]
	pointers: list[list[int]]
	rvas: list[int]
	offsets: list[int]

	original: list[str]
	replace: list[str]
	pointers_switches: list[list[bool]]

	def __init__(self):
		""" Parses a strindex file and returns a dictionary with the data. """

		self.full_header = ""
		self.settings = {
			"md5": None,
			"whitelist": None,
			"min_length": 0,
			"prefix_bytes": [''],
			"suffix_bytes": [''],
			"patch_replace": {},
			"clean_pattern": "",
			"source_language": None,
			"target_language": None,
			"among_languages": [],
		}
		self.type_order = []

		self.overwrite = []
		self.pointers = []
		self.offsets = []

		self.original = []
		self.replace = []
		self.pointers_switches = []

	@staticmethod
	def from_file(filepath: str):
		""" Parses a strindex file and returns a dictionary with the data. """

		strindex = Strindex()

		with open(filepath, 'r', encoding='utf-8') as f:
			while line := f.readline():
				if line.startswith("{"):
					strindex_settings_lines = line
					strindex.full_header += line
					while True:
						try:
							strindex.settings |= json.loads(strindex_settings_lines)
						except json.JSONDecodeError as e:
							line = f.readline()
							if line.startswith(Strindex.DELIMITERS[0]):
								raise ValueError("Error parsing Strindex settings.")
							strindex_settings_lines += line
							strindex.full_header += line
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
						strindex.pointers.append(needles[-1] if any(needles[-1]) else [])
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

		strindex.settings["prefix_bytes"] = [bytes.fromhex(prefix) for prefix in strindex.settings["prefix_bytes"]]
		strindex.settings["suffix_bytes"] = [bytes.fromhex(suffix) for suffix in strindex.settings["suffix_bytes"]]
		strindex.settings["whitelist"] = set(''.join([Strindex.CHARACTER_CLASSES.get(whitelist, whitelist) for whitelist in (strindex.settings["whitelist"] + ["default"])])) if strindex.settings["whitelist"] else None

		strindex.assert_data()

		return strindex

	def save(self, filepath: str):
		""" Saves the strindex data to a file. """
		self.assert_data()

		diff_settings = {k: v for k, v in self.settings.items() if Strindex().settings.get(k) != v}

		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(Strindex.HEADER.format(json.dumps(diff_settings, indent=4)))
			f.write(Strindex.COMPATIBLE_INFO if self.type_order[0] == "compatible" else Strindex.INFO)

			for index, type_wanted in enumerate(self.type_order):
				if type_wanted == "compatible":
					f.write(Strindex.create_compatible_raw_from_args(self.original[index], self.replace[index], self.pointers_switches[index]))
				else:
					f.write(Strindex.create_raw_from_args(self.overwrite[index], self.offsets[index], self.pointers[index]))

			truncate_prev_char(f)


	def patch_replace_string(self, string: str) -> str:
		""" Replaces the strings in the patch with the new strings. """
		for key, value in self.settings["patch_replace"].items():
			string = string.replace(key, value)
		return string


	def get_ordered_strings(self, override=None) -> list[str]:
		ordered_strings = []
		types = {}
		for type in self.type_order:
			if override:
				type = override(type)
			types[type] = (types[type] + 1) if type in types else 0
			ordered_strings.append(getattr(self, type)[types[type]])
		return ordered_strings

	def create_raw_from_index(self, index: int) -> str:
		type_wanted = self.type_order[index]
		type_index = self.type_order[:index].count(type_wanted)

		if type_wanted == "overwrite":
			return Strindex.create_raw_from_args(
				self.overwrite[type_index],
				self.offsets[type_index],
				self.pointers[type_index]
			)
		elif type_wanted == "compatible":
			return Strindex.create_compatible_raw_from_args(
				self.original[type_index],
				self.replace[type_index],
				self.pointers_switches[type_index]
			)

	@staticmethod
	def create_raw_from_args(overwrite, offset, pointers) -> str:
		return (
			Strindex.DELIMITERS[0] + Strindex.DELIMITERS[2] +
			hex(offset or 0).lstrip("0x").rjust(8, '0') + Strindex.DELIMITERS[2] +
			Strindex.DELIMITERS[3].join([hex(p or 0).lstrip("0x").rjust(8, '0') for p in pointers]) +
			Strindex.DELIMITERS[2] + "\n" +
			overwrite + "\n"
		)

	@staticmethod
	def create_compatible_raw_from_args(original, replace, pointers_switches) -> str:
		return (
			Strindex.DELIMITERS[0] +
			"".join([str(int(bool(p))) for p in pointers_switches]) + "\n" +
			original + "\n" +
			Strindex.DELIMITERS[1] + "\n" +
			replace + "\n"
		)


	def assert_data(self):
		assert len(self.overwrite) == len(self.pointers), "Overwrite and pointers lists are not the same length."
		assert len(self.original) == len(self.replace) == len(self.pointers_switches), "Original, replace and pointers_switches lists are not the same length."
		assert len(self.type_order) <= len(self.overwrite) + len(self.original), "Type order list is not the same length."

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

		print_progress = PrintProgress(len(self))
		fixed_prefix_length = len(prefixes[0])
		fixed_length = fixed_prefix_length + len(search_lst_safe[0]) + len(suffixes[0])

		indices_dict = {}
		for search_string in search_lst_safe:
			lst = []
			for prefix in prefixes:
				for suffix in suffixes:
					indices_dict[prefix + search_string + suffix] = lst

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


def truncate_prev_char(file):
	""" Truncates the last character of a file. """
	file.seek(file.tell() - 1)
	file.truncate()
