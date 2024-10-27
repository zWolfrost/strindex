import os, sys, argparse, json, pefile, re, time
from hashlib import md5


SECTION_NAME = b".strdex"


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
		global global_progress
		global_progress = self
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

	def __init__(self, filepath: str):
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
		self.rvas = []
		self.offsets = []

		self.original = []
		self.replace = []
		self.pointers_switches = []

		with open(filepath, 'r', encoding='utf-8') as f:
			while line := f.readline():
				if line.startswith("{"):
					strindex_settings_lines = line
					self.full_header += line
					while True:
						try:
							self.settings |= json.loads(strindex_settings_lines)
						except json.JSONDecodeError as e:
							line = f.readline()
							if line.startswith(Strindex.DELIMITERS[0]):
								raise ValueError("Error parsing Strindex settings.")
							strindex_settings_lines += line
							self.full_header += line
						else:
							break
				elif line.startswith(Strindex.DELIMITERS[0]):
					f.seek(f.tell() - len(line))
					break
				else:
					self.full_header += line

			next_lst = ""
			is_start = True
			while line := f.readline():
				line = line.rstrip('\n')
				if line.startswith(Strindex.DELIMITERS[0]):
					is_start = True
					line = line.lstrip(Strindex.DELIMITERS[0])

					if next_lst == "original":
						self.replace[-1] = self.original[-1]

					if Strindex.DELIMITERS[2] in line:
						next_lst = "overwrite"
						self.type_order.append("overwrite")
						self.overwrite.append('')

						needles = [[int(p, 16) if p else None for p in hex.split(Strindex.DELIMITERS[3])] for hex in line.split(Strindex.DELIMITERS[2])[1:-1]]
						self.pointers.append(needles[-1] if any(needles[-1]) else [])
						self.rvas.append(needles[-2][0] if len(needles) >= 2 else None)
						self.offsets.append(needles[-3][0] if len(needles) >= 3 else None)
					else:
						next_lst = "original"
						self.type_order.append("compatible")
						self.original.append('')
						self.replace.append('')

						self.pointers_switches.append([bool(int(p)) for p in line])
				elif line == Strindex.DELIMITERS[1] and next_lst == "original":
					is_start = True
					next_lst = "replace"
				else:
					if not is_start:
						line = "\n" + line
					is_start = False

					getattr(self, next_lst)[-1] += line

		self.settings["prefix_bytes"] = [bytes.fromhex(prefix) for prefix in self.settings["prefix_bytes"]]
		self.settings["suffix_bytes"] = [bytes.fromhex(suffix) for suffix in self.settings["suffix_bytes"]]
		self.settings["whitelist"] = set(''.join([Strindex.CHARACTER_CLASSES.get(whitelist, whitelist) for whitelist in (self.settings["whitelist"] + ["default"])])) if self.settings["whitelist"] else None
		self.rva_bytes_length = (-((len(hex(max([r for r in self.rvas if r is not None] + [0]))) - 2) // -8)) * 4

		assert len(self.overwrite) == len(self.pointers), "Overwrite and pointers lists are not the same length."
		assert len(self.original) == len(self.replace) == len(self.pointers_switches), "Original, replace and pointers_switches lists are not the same length."
		assert len(self.type_order) == len(self.overwrite) + len(self.original), "Type order list is not the same length."

	def get_ordered_lines(self, override = None) -> list[str]:
		ordered_lines = []
		types = {}
		for type in self.type_order:
			if override:
				type = override(type)
			types[type] = (types[type] + 1) if type in types else 0
			ordered_lines.append(getattr(self, type)[types[type]])
		return ordered_lines

	def create_raw_from_index(self, index: int) -> str:
		type_wanted = self.type_order[index]
		type_index = self.type_order[:index].count(type_wanted)

		if type_wanted == "overwrite":
			return Strindex.create_raw_from_args(
				self.offsets[type_index],
				self.rvas[type_index],
				self.pointers[type_index],
				self.overwrite[type_index],
				self.rva_bytes_length
			)
		elif type_wanted == "compatible":
			return Strindex.create_compatible_raw_from_args(
				self.pointers_switches[type_index],
				self.original[type_index],
				self.replace[type_index]
			)

	@staticmethod
	def create_raw_from_args(offset, rva, pointers, overwrite, rva_byte_length) -> str:
		return (
			Strindex.DELIMITERS[0] + Strindex.DELIMITERS[2] +
			hex(offset or 0).lstrip("0x").rjust(8, '0') + Strindex.DELIMITERS[2] +
			hex(rva or 0).lstrip("0x").rjust(rva_byte_length*2, '0') + Strindex.DELIMITERS[2] +
			Strindex.DELIMITERS[3].join([hex(p or 0).lstrip("0x").rjust(8, '0') for p in pointers]) +
			Strindex.DELIMITERS[2] + "\n" +
			overwrite + "\n"
		)

	@staticmethod
	def create_compatible_raw_from_args(pointers_switches, original, replace) -> str:
		return (
			Strindex.DELIMITERS[0] +
			"".join([str(int(bool(p))) for p in pointers_switches]) + "\n" +
			original + "\n" +
			Strindex.DELIMITERS[1] + "\n" +
			replace + "\n"
		)



def pe_adjust_optional_header(pe: pefile.PE) -> pefile.PE:
	"""
		Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
		SizeOfUninitializedData of the optional header.
	"""

	# SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
	pe.OPTIONAL_HEADER.SizeOfImage = pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize

	pe.OPTIONAL_HEADER.SizeOfCode = 0
	pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
	pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0

	# Recalculating the sizes by iterating over every section and checking if
	# the appropriate characteristics are set.
	for section in pe.sections:
		if section.Characteristics & 0x00000020:
			# Section contains code.
			pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
		if section.Characteristics & 0x00000040:
			# Section contains initialized data.
			pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
		if section.Characteristics & 0x00000080:
			# Section contains uninitialized data.
			pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

	return pe

def pe_add_header_space(pe: pefile.PE) -> pefile.PE:
	"""
		To make space for a new section header a buffer filled with nulls is added at the
		end of the headers. The buffer has the size of one file alignment.
		The data between the last section header and the end of the headers is copied to
		the new space (everything moved by the size of one file alignment).
		If any data directory entry points to the moved data the pointer is adjusted.
	"""

	FileAlignment = pe.OPTIONAL_HEADER.FileAlignment
	SizeOfHeaders = pe.OPTIONAL_HEADER.SizeOfHeaders

	data = b'\x00' * FileAlignment

	# Adding the null buffer.
	pe.__data__ = pe.__data__[:SizeOfHeaders] + data + pe.__data__[SizeOfHeaders:]

	section_table_offset = (
		pe.DOS_HEADER.e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
	)

	# Copying the data between the last section header and SizeOfHeaders to the newly allocated
	# space.
	new_section_offset = section_table_offset + pe.FILE_HEADER.NumberOfSections*0x28
	size = SizeOfHeaders - new_section_offset
	data = pe.get_data(new_section_offset, size)
	pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)

	# Filling the space, from which the data was copied from, with NULLs.
	pe.set_bytes_at_offset(new_section_offset, b'\x00' * FileAlignment)

	data_directory_offset = section_table_offset - pe.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8

	# Checking data directories if anything points to the space between the last section header
	# and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
	for data_offset in range(data_directory_offset, section_table_offset, 0x8):
		data_rva = pe.get_dword_from_offset(data_offset)

		if new_section_offset <= data_rva and data_rva < SizeOfHeaders:
			pe.set_dword_at_offset(data_offset, data_rva + FileAlignment)

	SizeOfHeaders_offset = pe.DOS_HEADER.e_lfanew + 4 + pe.FILE_HEADER.sizeof() + 0x3C

	# Adjusting the SizeOfHeaders value.
	pe.set_dword_at_offset(SizeOfHeaders_offset, SizeOfHeaders + FileAlignment)

	section_raw_address_offset = section_table_offset + 0x14

	# The raw addresses of the sections are adjusted.
	for section in pe.sections:
		if section.PointerToRawData != 0:
			pe.set_dword_at_offset(section_raw_address_offset, section.PointerToRawData+FileAlignment)

		section_raw_address_offset += 0x28

	# All changes in this method were made to the raw data (__data__). To make these changes
	# accessbile in pe __data__ has to be parsed again. Since a new pefile is parsed during
	# the init method, the easiest way is to replace pe with a new pefile based on __data__
	# of the old pe.
	pe = pefile.PE(data=pe.__data__)

	return pe

def pe_add_section(pe: pefile.PE, Name: str, Data: str, Characteristics=0xE00000E0, VirtualSize=0x00000000, VirtualAddress=0x00000000, RawSize=0x00000000, RawAddress=0x00000000) -> pefile.PE:
	"""
		Tested with pefile 1.2.10-123 on 32bit PE executable files.
		An implementation to push a section header to the section table of a PE file.
		by n0p

		Adds the section, specified by the functions parameters, at the end of the section table.
		If the space to add an additional section header is insufficient, a buffer is inserted
		after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
		is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.

		If a RawSize > 0 is set or Data is given the data gets aligned to the FileAlignment and
		is attached at the end of the file.
	"""

	if pe.FILE_HEADER.NumberOfSections == len(pe.sections):

		FileAlignment = pe.OPTIONAL_HEADER.FileAlignment
		SectionAlignment = pe.OPTIONAL_HEADER.SectionAlignment

		if len(Name) > 8:
			raise ValueError("The name is too long for a section.")

		if (
			VirtualAddress < (pe.sections[-1].Misc_VirtualSize + pe.sections[-1].VirtualAddress)
			or VirtualAddress % SectionAlignment != 0
		):
			if (pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
				VirtualAddress = (
					pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize -
					(pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment
				)
			else:
				VirtualAddress = pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize

		if VirtualSize < len(Data):
			VirtualSize = len(Data)

		if (len(Data) % FileAlignment) != 0:
			# Padding the data of the section.
			Data += b'\x00' * (FileAlignment - (len(Data) % FileAlignment))

		if RawSize != len(Data):
			if RawSize > len(Data) and (RawSize % FileAlignment) == 0:
				Data += b'\x00' * (RawSize - (len(Data) % RawSize))
			else:
				RawSize = len(Data)


		section_table_offset = (
			pe.DOS_HEADER.e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
		)

		# If the new section header exceeds the SizeOfHeaders there won't be enough space
		# for an additional section header. Besides that it's checked if the 0x28 bytes
		# (size of one section header) after the last current section header are filled
		# with nulls/ are free to use.
		if (
			pe.OPTIONAL_HEADER.SizeOfHeaders < section_table_offset + (pe.FILE_HEADER.NumberOfSections+1)*0x28
			or not all(char == b'\x00' for char in pe.get_data(section_table_offset + (pe.FILE_HEADER.NumberOfSections)*0x28, 0x28))
		):
			# Checking if more space can be added.
			if pe.OPTIONAL_HEADER.SizeOfHeaders < pe.sections[0].VirtualAddress:
				pe = pe_add_header_space(pe)
				# print("Additional space to add a new section header was allocated.")
			else:
				raise ValueError("No more space can be added for the section header.")


		# The validity check of RawAddress is done after space for a new section header may
		# have been added because if space had been added the PointerToRawData of the previous
		# section would have changed.
		if RawAddress != pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData:
			RawAddress = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData


		# Appending the data of the new section to the file.
		if len(Data) > 0:
			pe.__data__ = pe.__data__[:RawAddress] + Data + pe.__data__[RawAddress:]

		section_offset = section_table_offset + pe.FILE_HEADER.NumberOfSections*0x28

		# Manually writing the data of the section header to the file.
		pe.set_bytes_at_offset(section_offset, Name)
		pe.set_dword_at_offset(section_offset+0x08, VirtualSize)
		pe.set_dword_at_offset(section_offset+0x0C, VirtualAddress)
		pe.set_dword_at_offset(section_offset+0x10, RawSize)
		pe.set_dword_at_offset(section_offset+0x14, RawAddress)
		pe.set_dword_at_offset(section_offset+0x18, 0x00000000)
		pe.set_dword_at_offset(section_offset+0x1C, 0x00000000)
		pe.set_word_at_offset(section_offset+0x20, 0x0000)
		pe.set_word_at_offset(section_offset+0x22, 0x0000)
		pe.set_dword_at_offset(section_offset+0x24, Characteristics)

		pe.FILE_HEADER.NumberOfSections += 1

		# Parsing the section table of the file again to add the new section to the sections
		# list of pefile.
		pe.parse_sections(section_table_offset)

		pe = pe_adjust_optional_header(pe)
	else:
		raise ValueError(
			"The NumberOfSections specified in the file header and the size of the sections list of pefile don't match."
		)

	return pe

def pe_get_new_section_base_rva(pe: pefile.PE) -> int:
	""" Returns the base rva for a possibly new PE section. """
	new_section_base_rva = pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize
	if new_section_base_rva % pe.OPTIONAL_HEADER.SectionAlignment:
		new_section_base_rva += pe.OPTIONAL_HEADER.SectionAlignment - (new_section_base_rva % pe.OPTIONAL_HEADER.SectionAlignment)
	new_section_base_rva += pe.OPTIONAL_HEADER.ImageBase
	return new_section_base_rva

def pe_section_exists(pe: pefile.PE, section_name: str) -> bool:
	""" Checks if a section with the specified name exists. """
	return any(sect.Name == section_name.ljust(8, b'\x00') for sect in pe.sections)



def mmap_indices_ordered(mm: bytearray, search_lst: list[bytes], prefix: bytes = b"", suffix: bytes = b"") -> list[int]:
	"""
	Returns the index of the first occurrence of every search list string in a mmap.
	Extremely fast, but can only can work for search lists that are ordered by occurrence order.
	"""
	search_lst = [bytes(search, 'utf-8') if isinstance(search, str) else search for search in search_lst]
	indices = []
	prefix_length = len(prefix)
	start_index = 0
	for search_index in range(len(search_lst)):
		index = mm.find(prefix + search_lst[search_index] + suffix, start_index)
		if index == -1:
			indices.append(None)
			continue
		start_index = index + prefix_length + len(search_lst[search_index])
		indices.append(index + prefix_length)
	return indices

def mmap_indices_fixed(mm: bytearray, search_lst: list[bytes], prefixes: list[bytes] = [b""], suffixes: list[bytes] = [b""]) -> list[list[int]]:
	"""
	Returns a list containing the indexes of each occurrence of every search list string in a mmap.
	Extremely fast, but can only can work for unique search strings of fixed length (length is taken from 1st element).
	"""
	if not search_lst:
		return []

	search_lst_safe = [s for s in search_lst if s is not None]

	assert len(search_lst_safe) == len(set(search_lst_safe)), "Search list is not unique."
	assert all(len(search) == len(search_lst_safe[0]) for search in search_lst_safe), "Search list is not fixed length."
	assert all(len(prefix) == len(prefixes[0]) for prefix in prefixes), "Prefix list is not fixed length."

	print_progress = PrintProgress(len(mm))
	fixed_prefix_length = len(prefixes[0])
	fixed_length = fixed_prefix_length + len(search_lst_safe[0]) + len(suffixes[0])

	indices_dict = {}
	for search_string in search_lst_safe:
		lst = []
		for prefix in prefixes:
			for suffix in suffixes:
				indices_dict[prefix + search_string + suffix] = lst

	for mm_index in range(len(mm)):
		cur_bytes = mm[mm_index:mm_index + fixed_length]
		if cur_bytes in indices_dict:
			indices_dict[cur_bytes].append(mm_index + fixed_prefix_length)
		if mm_index >= print_progress.limit:
			print_progress(mm_index)

	indices = list(indices_dict.values())[::len(prefixes) * len(suffixes)]
	for search_index, search_string in enumerate(search_lst):
		if search_string is None:
			indices.insert(search_index, search_string)

	return indices

def replace_with_table(string: str, table: dict[str, str]) -> str:
	""" Replaces all occurrences of keys in a string with their corresponding table values. """
	for key, value in table.items():
		string = string.replace(key, value)
	return string

def truncate_prev_char(file):
	""" Truncates the last character of a file. """
	file.seek(file.tell() - 1)
	file.truncate()



def create(file_filepath: str, strindex_filepath: str, compatible: bool, min_length, prefixes: list[bytes]):
	"""
		Creates a strindex file from a PE file.

		It works by creating a dictionary with the strings
		and their rva found in the PE file, that meet the filter criteria.
		Then it finds the pointers (the assembly instructions' offsets)
		for the rvas in the dictionary, by only looping the file once.
	"""

	pefile.fast_load = True
	pe = pefile.PE(file_filepath)

	if pe_section_exists(pe, SECTION_NAME):
		print(f"This file contains a '{SECTION_NAME.decode('utf-8')}' section. You might not want this.")

	BYTE_LENGTH = 4 if pe.OPTIONAL_HEADER.Magic == 0x10b else 8

	temp_strindex = {
		"original": [],
		"offsets": [],
		"rva": [],
		"rva_bytes": [],
		"pointers": []
	}

	print_progress = PrintProgress(len(pe.__data__))
	byte_string = b''
	for offset, char in enumerate(pe.__data__):
		if char == b'\x00':
			try:
				string = byte_string.decode('utf-8')
			except UnicodeDecodeError:
				continue
			else:
				if len(string) < min_length:
					continue
				offset -= len(byte_string)
				rva = pe.get_rva_from_offset(offset)
				if not rva:
					continue
				rva += pe.OPTIONAL_HEADER.ImageBase
				temp_strindex["original"].append(string)
				temp_strindex["offsets"].append(offset)
				temp_strindex["rva"].append(rva)
				temp_strindex["rva_bytes"].append(rva.to_bytes(BYTE_LENGTH, 'little'))
			finally:
				byte_string = b''
				print_progress(offset)
		else:
			byte_string += char

	if not temp_strindex["original"]:
		raise ValueError("No strings found in the file.")
	print(f"(1/3) Created search dictionary with {len(temp_strindex['original'])} strings.")

	temp_strindex["pointers"] = mmap_indices_fixed(pe.__data__, temp_strindex["rva_bytes"], prefixes)
	print(f"(2/3) Found pointers for {len([p for p in temp_strindex['pointers'] if p])} / {len(temp_strindex['original'])} strings.")

	with open(strindex_filepath, 'w', encoding='utf-8') as f:
		SETTINGS = {
			"md5": md5(pe.__data__).hexdigest()
		}
		if prefixes != [b'']:
			SETTINGS["prefix_bytes"] = [prefix.hex() for prefix in prefixes]

		f.write(
			Strindex.HEADER.format(json.dumps(SETTINGS, indent=4)) +
			(Strindex.COMPATIBLE_INFO if compatible else Strindex.INFO)
		)

		for string, offset, rva, _, pointers in zip(*temp_strindex.values()):
			if pointers:
				if compatible:
					f.write(Strindex.create_compatible_raw_from_args(pointers, string, string))
				else:
					f.write(Strindex.create_raw_from_args(offset, rva, pointers, string, BYTE_LENGTH))

		truncate_prev_char(f)
	print("(3/3) Created strindex file.")

def patch(file_filepath: str, strindex_filepath: str, file_patched_filepath: str):
	"""
		Patches a PE file with a strindex file.
		It works by creating a new section with the strings from the strindex file,
		and reallocating the original pointers with the new section's rva.
		For "compatible" strindex files, the re-finding of strings works similarly to the "create" action.
	"""

	file_filepath_bak = file_filepath + '.bak'

	pefile.fast_load = True
	pe = pefile.PE(file_filepath_bak if os.path.exists(file_filepath_bak) else file_filepath)

	if pe_section_exists(pe, SECTION_NAME):
		raise ValueError(f"This file already contains a '{SECTION_NAME.decode('utf-8')}' section.")

	if not file_patched_filepath and not os.path.exists(file_filepath_bak):
		pe.write(file_filepath_bak)


	BYTE_LENGTH = 4 if pe.OPTIONAL_HEADER.Magic == 0x10b else 8
	STRDEX_SECTION_BASE_RVA = pe_get_new_section_base_rva(pe)
	STRINDEX = Strindex(strindex_filepath)

	if STRINDEX.settings["md5"] and STRINDEX.settings["md5"] != md5(pe.__data__).hexdigest():
		print("MD5 hash does not match the one the strindex was created for. You might encounter issues.")


	new_section_data = bytearray()
	get_original_rva = lambda offset: (pe.get_rva_from_offset(offset) + pe.OPTIONAL_HEADER.ImageBase).to_bytes(BYTE_LENGTH, 'little')
	get_replaced_rva = lambda: (STRDEX_SECTION_BASE_RVA + len(new_section_data)).to_bytes(BYTE_LENGTH, 'little')
	new_section_string = lambda string: bytearray(replace_with_table(string, STRINDEX.settings["patch_replace"]), 'utf-8') + b'\x00'

	temp_strindex = {
		"original_rva": [],
		"replaced_rva": [],
		"pointers": [],
		"pointers_switches": []
	}

	# Deal with compatible strings
	for strindex_index, offset in enumerate(mmap_indices_ordered(pe.__data__, STRINDEX.original, b"\x00", b"\x00")):
		if offset is None:
			print(f'String not found: "{STRINDEX.original[strindex_index]}"')
			continue

		temp_strindex["original_rva"].append(get_original_rva(offset))
		temp_strindex["replaced_rva"].append(get_replaced_rva())
		temp_strindex["pointers_switches"].append(STRINDEX.pointers_switches[strindex_index])

		new_section_data += new_section_string(STRINDEX.replace[strindex_index])

	temp_strindex["pointers"] = mmap_indices_fixed(pe.__data__, temp_strindex["original_rva"], STRINDEX.settings["prefix_bytes"], STRINDEX.settings["suffix_bytes"])

	for original_rva, replaced_rva, pointers, pointers_switches in zip(*temp_strindex.values()):
		if pointers:
			for pointer, switch in zip(pointers, pointers_switches):
				if switch:
					pe.set_bytes_at_offset(pointer, replaced_rva)
		else:
			print("No pointers found for rva: " + original_rva.hex())

	# Deal with pointers strings
	for strindex_index in range(len(STRINDEX.overwrite)):
		replaced_rva = get_replaced_rva()
		new_section_data += new_section_string(STRINDEX.overwrite[strindex_index])

		for pointer in STRINDEX.pointers[strindex_index]:
			if pointer:
				pe.set_bytes_at_offset(pointer, replaced_rva)
			else:
				print("No pointers found for string: " + STRINDEX.overwrite[strindex_index])
	print("(1/3) Created section data & relocated pointers.")


	pe = pe_add_section(pe, Name=SECTION_NAME, Data=new_section_data, Characteristics=0xF0000040)
	print(f"(2/3) Added '{SECTION_NAME.decode('utf-8')}' section.")


	pe.write(file_patched_filepath or file_filepath)
	print("(3/3) File was patched successfully.")

def filter(strindex_filepath: str, strindex_filter_filepath: str):
	"""
		Filters a strindex file with a PE file with respect to length, whitelist and source language.
	"""

	STRINDEX = Strindex(strindex_filepath)
	STRINDEX_LINES = STRINDEX.get_ordered_lines(lambda t: "original" if t == "compatible" else t)

	if STRINDEX.settings["source_language"]:
		try:
			from lingua import IsoCode639_1, LanguageDetectorBuilder
		except ImportError:
			raise ImportError(
				"Please install the 'lingua' package (pip install lingua) to filter by language."
			)

		ALL_LANGUAGES = [code for code in IsoCode639_1.__dict__.values() if isinstance(code, IsoCode639_1)]
		SETTINGS_LANGUAGES = [getattr(IsoCode639_1, code.upper()) for code in STRINDEX.settings["among_languages"]]

		detector = LanguageDetectorBuilder.from_iso_codes_639_1(*(SETTINGS_LANGUAGES or ALL_LANGUAGES)).build()

	def is_source_language(string: str) -> bool:
		line_clean = re.sub(STRINDEX.settings["clean_pattern"], "", string)
		confidence = detector.compute_language_confidence_values(line_clean)[0]
		return confidence.language.iso_code_639_1 == getattr(IsoCode639_1, STRINDEX.settings["source_language"].upper()) and confidence.value > 0.5

	print_progress = PrintProgress(len(STRINDEX_LINES))
	with open(strindex_filter_filepath, 'w', encoding='utf-8') as f:
		f.write(STRINDEX.full_header)

		for strindex_index, line in enumerate(STRINDEX_LINES):
			if (
				(not STRINDEX.settings["source_language"] or is_source_language(line)) and
				(len(line) >= STRINDEX.settings["min_length"]) and
				(not STRINDEX.settings.get("whitelist") or not any(ch not in STRINDEX.settings["whitelist"] for ch in line))
			):
				f.write(STRINDEX.create_raw_from_index(strindex_index))

			print_progress(strindex_index)

		truncate_prev_char(f)
	print("(1/1) Created filtered strindex file.")

def update(file_filepath: str, strindex_filepath: str, strindex_update_filepath: str):
	"""
		Updates a compatible strindex file with the new pointers numbers.
	"""

	pefile.fast_load = True
	pe = pefile.PE(file_filepath)

	if pe_section_exists(pe, SECTION_NAME):
		print(f"This file contains a '{SECTION_NAME.decode('utf-8')}' section. You might not want this.")

	BYTE_LENGTH = 4 if pe.OPTIONAL_HEADER.Magic == 0x10b else 8

	STRINDEX = Strindex(strindex_filepath)
	STRINDEX_LINES = STRINDEX.get_ordered_lines(lambda t: "original" if t == "compatible" else t)

	temp_strindex = {
		"rva_bytes": [],
		"pointers": []
	}
	for strindex_index, offset in enumerate(mmap_indices_ordered(pe.__data__, STRINDEX_LINES, b"\x00", b"\x00")):
		if offset is None:
			print(f'String not found: "{STRINDEX_LINES[strindex_index]}"')
			temp_strindex["rva_bytes"].append(None)
			continue

		temp_strindex["rva_bytes"].append((pe.get_rva_from_offset(offset) + pe.OPTIONAL_HEADER.ImageBase).to_bytes(BYTE_LENGTH, 'little'))

	temp_strindex["pointers"] = mmap_indices_fixed(pe.__data__, temp_strindex["rva_bytes"], STRINDEX.settings["prefix_bytes"], STRINDEX.settings["suffix_bytes"])

	with open(strindex_update_filepath, 'w', encoding='utf-8') as f:
		f.write(STRINDEX.full_header)

		for strindex_index, pointers in enumerate([p for p, t in zip(temp_strindex["pointers"], STRINDEX.type_order) if t == "compatible"]):
			STRINDEX.pointers_switches[strindex_index] = [True] * len(pointers or [])

		for strindex_index, pointers in enumerate([p for p, t in zip(temp_strindex["pointers"], STRINDEX.type_order) if t == "overwrite"]):
			STRINDEX.pointers[strindex_index] = pointers or []

		for strindex_index, pointers in enumerate(temp_strindex["pointers"]):
			if pointers:
				f.write(STRINDEX.create_raw_from_index(strindex_index))

		truncate_prev_char(f)
	print("(1/1) Created updated strindex file.")

def delta(strindex_full_filepath: str, strindex_diff_filepath: str, strindex_delta_filepath: str):
	"""
		Filters a full strindex file with a delta strindex file.
	"""

	STRINDEX_FULL = Strindex(strindex_full_filepath)
	STRINDEX_DIFF = Strindex(strindex_diff_filepath)

	STRINDEX_FULL_LINES = STRINDEX_FULL.get_ordered_lines(lambda t: "original" if t == "compatible" else t)
	STRINDEX_DIFF_LINES = STRINDEX_DIFF.get_ordered_lines(lambda t: "original" if t == "compatible" else t)

	with open(strindex_delta_filepath, 'w', encoding='utf-8') as f:
		f.write(STRINDEX_FULL.full_header)

		diff_index = 0
		for full_index in range(len(STRINDEX_FULL.type_order)):
			try:
				diff_index = STRINDEX_DIFF_LINES.index(STRINDEX_FULL_LINES[full_index], diff_index)
			except ValueError:
				f.write(STRINDEX_FULL.create_raw_from_index(full_index))

		truncate_prev_char(f)

	print("(1/1) Created delta strindex file.")

def spellcheck(strindex_filepath: str, strindex_spellcheck_filepath: str):
	"""
		Creates a spellcheck file from a strindex file, for the specified language.
	"""

	try:
		from language_tool_python import LanguageTool
	except ImportError:
		raise ImportError("Please install the 'language-tool-python' package (pip install language-tool-python) to use this feature.")

	STRINDEX = Strindex(strindex_filepath)
	STRINDEX_LINES = STRINDEX.get_ordered_lines(lambda t: "replace" if t == "original" else t)

	if not STRINDEX.settings["target_language"]:
		raise ValueError("Please specify the target language to spellcheck in the strindex file ('target_language').")

	lang = LanguageTool(STRINDEX.settings["target_language"])
	print("(1/2) Created language tool.")

	with open(strindex_spellcheck_filepath, 'w', encoding='utf-8') as f:
		print_progress = PrintProgress(len(STRINDEX_LINES))
		for strindex_index, line in enumerate(STRINDEX_LINES):
			line_clean = re.sub(STRINDEX.settings["clean_pattern"], "", line)
			for error in lang.check(line_clean):
				f.write('\n'.join(str(error).split('\n')[-3:]) + '\n')

			print_progress(strindex_index)
	print("(2/2) Spellchecked strindex file.")



def patch_gui():
	try:
		from PySide6 import QtCore, QtWidgets, QtGui
	except ImportError:
		raise ImportError("Please install the 'PySide6' package (pip install PySide6) to use this feature.")

	class PatchGUI(QtWidgets.QWidget):
		def __init__(self):
			super().__init__()

			# file selection
			self.pefile_line = QtWidgets.QLineEdit()
			self.pefile_line.setPlaceholderText("Select a PE file")
			self.pefile_line.textChanged.connect(self.update)
			self.pefile_line.textChanged.connect(lambda: self.pefile_line.setStyleSheet(self.pefile_line.styleSheet()))
			self.pefile_line.setFont(QtGui.QFont("monospace"))
			self.pefile_button = QtWidgets.QPushButton("Browse PE Files")
			self.pefile_button.clicked.connect(lambda: self.browse(self.pefile_line, "Open File", "Executable Files (*.exe)"))

			# strindex selection
			self.strindex_line = QtWidgets.QLineEdit()
			self.strindex_line.setPlaceholderText("Select a Strindex file")
			self.strindex_line.textChanged.connect(self.update)
			self.strindex_line.textChanged.connect(lambda: self.strindex_line.setStyleSheet(self.strindex_line.styleSheet()))
			self.strindex_line.setFont(QtGui.QFont("monospace"))
			self.strindex_button = QtWidgets.QPushButton("Browse Strindex")
			self.strindex_button.clicked.connect(lambda: self.browse(self.strindex_line, "Open Strindex", "Text Files (*.txt)"))

			# patch button
			self.patch_button = QtWidgets.QPushButton("Patch")
			self.patch_button.clicked.connect(self.patch)
			self.patch_button.setEnabled(False)

			# add widgets to layout
			layout = QtWidgets.QGridLayout()
			layout.addWidget(self.pefile_line, 0, 0)
			layout.addWidget(self.pefile_button, 0, 1)
			layout.addWidget(self.strindex_line, 1, 0)
			layout.addWidget(self.strindex_button, 1, 1)
			layout.addWidget(self.patch_button, 2, 0, 1, 2)
			layout.setSpacing(10)
			layout.setColumnStretch(0, 1)
			layout.setColumnMinimumWidth(0, 200)
			self.setLayout(layout)

			# set window properties
			WINDOWS_STYLESHEET = f""""""
			UNIX_STYLESHEET = f"""QLineEdit[text=""]{{color: {self.palette().windowText().color().name()};}}"""
			self.setWindowTitle("Strindex Patch")
			self.setStyleSheet(WINDOWS_STYLESHEET if sys.platform == "win32" else UNIX_STYLESHEET)
			self.setWindowFlag(QtCore.Qt.WindowType.WindowMaximizeButtonHint, False)
			self.setMaximumSize(1400, 0)
			self.resize(800, 0)
			self.center()

		def browse(self, line: QtWidgets.QLineEdit, caption, filter):
			if filepath := QtWidgets.QFileDialog.getOpenFileName(self, caption, "", filter)[0]:
				line.setText(filepath)

		def update(self):
			path_exists = os.path.isfile(self.pefile_line.text()) and os.path.isfile(self.strindex_line.text())
			self.patch_button.setEnabled(path_exists)

		def patch(self):
			self.setEnabled(False)

			def update(progress: PrintProgress):
				self.patch_button.setText(f"Patching... {progress.percent}%")
				QtWidgets.QApplication.processEvents()

			self.patch_button.setText("Patching...")
			QtWidgets.QApplication.processEvents()

			PrintProgress.callback = update

			try:
				patch(self.pefile_line.text(), self.strindex_line.text(), None)
			except BaseException as e:
				self.message(str(e), QtWidgets.QMessageBox.Critical)
			else:
				self.message("File patched successfully.", QtWidgets.QMessageBox.Information)
			finally:
				del PrintProgress.callback
				self.patch_button.setText("Patch")
				self.setEnabled(True)

		def center(self):
			res = QtGui.QGuiApplication.primaryScreen().availableGeometry()
			self.move((res.width() - self.width()) // 2, (res.height() - self.height()) // 2)

		def message(self, text: str, icon):
			msg = QtWidgets.QMessageBox(self)
			msg.setWindowTitle(self.windowTitle())
			msg.setIcon(icon)
			msg.setText(text)
			msg.setStandardButtons(QtWidgets.QMessageBox.Ok.Ok)
			msg.exec()
			return msg

	app = QtWidgets.QApplication([])
	gui = PatchGUI()
	gui.show()
	sys.exit(app.exec())



def main():
	if "__compiled__" in globals():
		patch_gui()
		return

	try:
		args = argparse.ArgumentParser(prog="strindex", description="Command line string replacement tool for games.")

		args.add_argument("action", type=str, choices=["create", "patch", "patch_gui", "update", "filter", "delta", "spellcheck"], help="Action to perform.")
		args.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE, help="One or more files to process.")
		args.add_argument("-o", "--output", type=str, help="Output file.")

		# create arguments
		args.add_argument("-c", "--compatible", action="store_true", help="Whether to create a strindex file compatible with the previous versions of a program.")
		args.add_argument("-m", "--min-length", type=int, default=3, help="Minimum length of the strings to be included.")
		args.add_argument("-p", "--prefix-bytes", type=str, action="append", default=[], help="Prefix bytes to add to the rva in the strindex file.")

		args = args.parse_args()

		if not all([os.path.isfile(file) for file in args.files]):
			raise FileNotFoundError("One or more files do not exist.")

		args.prefix_bytes = [bytes.fromhex(prefix) for prefix in (args.prefix_bytes or [''])]

		match args.action:
			case "create":
				create(*args.files, (args.output or "strindex.txt"), args.compatible, args.min_length, args.prefix_bytes)
			case "patch":
				patch(*args.files, args.output)
			case "patch_gui":
				patch_gui()
			case "filter":
				filter(*args.files, (args.output or "strindex_filter.txt"))
			case "update":
				update(*args.files, (args.output or "strindex_update.txt"))
			case "delta":
				delta(*args.files, (args.output or "strindex_delta.txt"))
			case "spellcheck":
				spellcheck(*args.files, (args.output or "strindex_spellcheck.txt"))
	except KeyboardInterrupt:
		print("Interrupted by user.")
	except BaseException as e:
		print(e)

if __name__ == "__main__":
	main()
