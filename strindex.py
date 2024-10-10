import os, sys, re, json, argparse, pefile, time, hashlib
pefile.fast_load = True



STRINDEX_DELIMITERS = ('_' * 80, '↓' * 80, '/', '-')
STRINDEX_HEADER = "You can freely delete informational lines like this one.\n\n{}\n\n"
STRINDEX_INFO = "-" * 79 + "/ offset /  rva   / offsets of rva pointers /\n"
STRINDEX_FORMAT = f"{STRINDEX_DELIMITERS[0]}{{}}{STRINDEX_DELIMITERS[2]}{{}}{STRINDEX_DELIMITERS[2]}{{}}\n{{}}\n"
STRINDEX_COMPATIBLE_FORMAT = f"{STRINDEX_DELIMITERS[0]}{{}}\n{{}}\n{STRINDEX_DELIMITERS[1]}\n{{}}\n"



class PrintProgress():
	"""
	Extremely fast class to print progress percentage.
	Only wastes ~0.1 seconds every 1'000'000 calls,
	or half of that if "iteration >= self.limit" is checked within the loop.
	"""

	def __init__(self, total: int, precision: int = 0):
		self.total = total
		self.limit = 0
		self.delta = total // (10 ** (precision + 2))
		self.round = precision if precision > 0 else None
		self.end = "%" + " " * (precision + 3) + "\r"
		self.__call__(0)

	def __call__(self, iteration: int):
		if iteration >= self.limit:
			self.limit += self.delta
			print(round(iteration / self.total * 100, self.round), end=self.end)



def pe_adjust_optional_header(pe: pefile.PE) -> pefile.PE:
	""" Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
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
	""" To make space for a new section header a buffer filled with nulls is added at the
		end of the headers. The buffer has the size of one file alignment.
		The data between the last section header and the end of the headers is copied to
		the new space (everything moved by the size of one file alignment). If any data
		directory entry points to the moved data the pointer is adjusted.
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

def pe_add_section(
	pe: pefile.PE, Name=".NewSec", Data="", Characteristics=0xE00000E0,
	VirtualSize=0x00000000, VirtualAddress=0x00000000,
	RawSize=0x00000000, RawAddress=0x00000000
) -> pefile.PE:
	"""
		Tested with pefile 1.2.10-123 on 32bit PE executable files.
		An implementation to push a section header to the section table of a PE file.
		For further information refer to the docstrings of pop_back/push_back.
		by n0p (updated by zWolfrost)

		Adds the section, specified by the functions parameters, at the end of the section
		table.
		If the space to add an additional section header is insufficient, a buffer is inserted
		after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
		is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.

		A call with no parameters creates the same section header as LordPE does. But for the
		binary to be executable without errors a VirtualSize > 0 has to be set.

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



def parse_strindex(filepath: str):
	strindex = {
		"raw_header": "",
		"original": [],
		"replace": [],
		"raw_pointers": [],
		"pointers": [],
		"settings": {},
		"type": None,
	}

	with open(filepath, 'r', encoding='utf-8') as f:
		for line in f:
			if line.startswith("{"):
				strindex_settings_lines = line
				strindex["raw_header"] += line
				while True:
					try:
						strindex["settings"] = json.loads(strindex_settings_lines)
					except json.JSONDecodeError as e:
						line = f.readline()
						if line.startswith(STRINDEX_DELIMITERS[0]):
							print("Error parsing settings:", e)
							exit(1)
						strindex_settings_lines += line
						strindex["raw_header"] += line
					else:
						break
			elif line.startswith(STRINDEX_DELIMITERS[0]):
				strindex["type"] = "default" if STRINDEX_DELIMITERS[2] in line else "compatible"

				strindex["replace"].append('')
				if strindex["type"] == "compatible":
					strindex["original"].append('')
					get_pointers = lambda line: [bool(int(p)) for p in line.rstrip('\n').lstrip(STRINDEX_DELIMITERS[0])]
				else:
					get_pointers = lambda line: [int(p, 16) for p in line.rstrip('\n').rsplit(STRINDEX_DELIMITERS[2], 1)[1].split(STRINDEX_DELIMITERS[3])]

				strindex["raw_pointers"].append(line)
				strindex["pointers"].append(get_pointers(line))
				break
			else:
				strindex["raw_header"] += line

		is_original = strindex["type"] == "compatible"
		is_start = True
		for line in f:
			if line.startswith(STRINDEX_DELIMITERS[0]):
				is_start = True
				is_original = strindex["type"] == "compatible"
				if strindex["type"] == "compatible":
					strindex["original"].append('')
				strindex["replace"].append('')
				strindex["raw_pointers"].append(line)
				strindex["pointers"].append(get_pointers(line))
				continue
			elif line.startswith(STRINDEX_DELIMITERS[1]):
				is_start = True
				is_original = False
				continue

			line = line.rstrip('\n')
			if is_start:
				is_start = False
			else:
				line = "\n" + line

			if is_original:
				strindex["original"][-1] += line
			else:
				strindex["replace"][-1] += line

	return strindex

def mmap_by_nulls(mm: bytearray):
	"""
	Yields every string contained in a mmap, separated by a null byte, along with its offset.
	"""
	string = b''
	char_count = 0
	for char in mm:
		if char == b'\x00':
			yield string, char_count - len(string)
			string = b''
		else:
			string += char
		char_count += 1

	yield string, char_count - len(string)

def mmap_indices_ordered(mm: bytearray, search_lst: list[bytes]) -> list[list[int]]:
	"""
	Returns the index of the first occurrence of every search list string in a mmap.
	Extremely fast, but can only can work for search lists that are ordered by occurrence order.
	"""
	indices = []
	start_index = 0
	for search_index in range(len(search_lst)):
		index = mm.find(search_lst[search_index], start_index)
		if index != -1:
			start_index = index + 1

		indices.append(index)
	return indices

def mmap_indices_fixed(mm: bytearray, search_lst: list[bytes]) -> list[list[int]]:
	"""
	Returns a list containing the indexes of each occurrence of every search list string in a mmap.
	Extremely fast, but can only can work for unique search strings of fixed length (length is taken from 1st element).
	"""
	assert len(search_lst) == len(set(search_lst)), "Search list is not unique."
	print_progress = PrintProgress(len(mm))
	fixed_length = len(search_lst[0])
	indices = {s: [] for s in search_lst}
	search_index = 0
	while search_index < len(mm):
		cur_bytes = mm[search_index:search_index + fixed_length]
		if cur_bytes in indices:
			indices[cur_bytes].append(search_index)
		search_index += 1
		if search_index >= print_progress.limit:
			print_progress(search_index)
	return list(indices.values())

def replace_with_table(string: str, table: dict[str, str]) -> str:
	for key, value in table.items():
		string = string.replace(key, value)
	return string



def create(file_filepath: str, strindex_filepath: str, compatible: bool, whitelist: str, min_length: int):
	pe = pefile.PE(file_filepath)

	BYTE_LENGTH = 4 if pe.OPTIONAL_HEADER.Magic == 0x10b else 8

	temp_strindex = {
		"original": [],
		"offsets": [],
		"rva": [],
		"rva_bytes": []
	}

	print_progress = PrintProgress(len(pe.__data__))
	for string, offset in mmap_by_nulls(pe.__data__):
		try:
			string = string.decode('utf-8')
		except UnicodeDecodeError:
			continue

		if (len(string) >= min_length) and (not whitelist or all(x in whitelist for x in string)):
			rva = pe.get_rva_from_offset(offset)
			if rva:
				rva += pe.OPTIONAL_HEADER.ImageBase
				temp_strindex["original"].append(string)
				temp_strindex["offsets"].append(offset)
				temp_strindex["rva"].append(rva)
				temp_strindex["rva_bytes"].append(rva.to_bytes(BYTE_LENGTH, 'little'))

		print_progress(offset)
	print(f"(1/3) Created search dictionary with {len(temp_strindex['original'])} strings.")

	temp_strindex["pointers"] = mmap_indices_fixed(pe.__data__, temp_strindex["rva_bytes"])
	print("(2/3) Found string pointers.")

	with open(strindex_filepath, 'w', encoding='utf-8') as f:
		SETTINGS = {
			"md5": hashlib.md5(pe.__data__).hexdigest()
		}
		f.write(STRINDEX_HEADER.format(json.dumps(SETTINGS, indent=4)))

		if not compatible:
			f.write(STRINDEX_INFO)

		for string, offset, rva, pointer in zip(temp_strindex["original"], temp_strindex["offsets"], temp_strindex["rva"], temp_strindex["pointers"]):
			if pointer:
				if compatible:
					f.write(STRINDEX_COMPATIBLE_FORMAT.format(len(pointer) * "1", string, string))
				else:
					hex_offset = hex(offset).lstrip("0x").rjust(8, '0')
					hex_rva = hex(rva).lstrip("0x").rjust(2 * BYTE_LENGTH, '0')
					hex_rva_pointers = STRINDEX_DELIMITERS[3].join([hex(offset).lstrip("0x").rjust(8, '0') for offset in pointer])
					f.write(STRINDEX_FORMAT.format(hex_offset, hex_rva, hex_rva_pointers, string))

		f.seek(f.tell() - 1)
		f.truncate()
	print("(3/3) Created strindex file.")

def patch(file_filepath: str, strindex_filepath: str):
	file_filepath_bak = file_filepath + '.bak'

	COPY_COMMAND = "copy" if sys.platform == "win32" else "cp"
	DEV_NULL = "> NUL" if sys.platform == "win32" else "> /dev/null"
	if os.path.exists(file_filepath_bak):
		os.system(f'{COPY_COMMAND} "{file_filepath_bak}" "{file_filepath}" {DEV_NULL}')
		print("(1/5) Restored from backup.")
	else:
		os.system(f'{COPY_COMMAND} "{file_filepath}" "{file_filepath_bak}" {DEV_NULL}')
		print("(1/5) Created backup.")


	pe = pefile.PE(file_filepath_bak)

	if any(sect.Name == b".strdex\0" for sect in pe.sections):
		raise ValueError("The file already contains a .strdex section.")


	BYTE_LENGTH = 4 if pe.OPTIONAL_HEADER.Magic == 0x10b else 8

	STRDEX_SECTION_BASE_RVA = pe_get_new_section_base_rva(pe)

	new_section_data = b''
	STRINDEX = parse_strindex(strindex_filepath)

	if STRINDEX["settings"].get("md5") and STRINDEX["settings"]["md5"] != hashlib.md5(pe.__data__).hexdigest():
		print("MD5 hash does not match the one the strindex was created for. You might encounter issues.")


	if STRINDEX["type"] == "compatible":
		temp_strindex = {
			"original_rva": [],
			"replaced_rva": []
		}
		for strindex_index, offset in enumerate(mmap_indices_ordered(pe.__data__, [bytes(l, 'utf-8') for l in STRINDEX["original"]])):
			if offset == -1:
				print("String not found (skipping):\n" + STRINDEX["original"][strindex_index])
				continue

			# sect = pe.get_section_by_offset(offset)
			# if sect.VirtualAddress - sect.PointerToRawData + offset != pe.get_rva_from_offset(offset):
			# 	print("RVA calculation is somehow different from the PE method. Keep an eye on this.")

			temp_strindex["original_rva"].append((pe.get_rva_from_offset(offset) + pe.OPTIONAL_HEADER.ImageBase).to_bytes(BYTE_LENGTH, 'little'))
			temp_strindex["replaced_rva"].append((STRDEX_SECTION_BASE_RVA + len(new_section_data)).to_bytes(BYTE_LENGTH, 'little'))

			replaced_string = replace_with_table(STRINDEX["replace"][strindex_index], STRINDEX["settings"].get("replace", {}))
			new_section_data += bytes(replaced_string, 'utf-8') + b'\x00'
		print(f"(2/5) Created section data with {len(temp_strindex['original_rva'])}/{len(STRINDEX['original'])} strings found.")

		temp_strindex["pointers"] = mmap_indices_fixed(pe.__data__, temp_strindex["original_rva"])

		for pointers, replaced_rva, replace_lst in zip(temp_strindex["pointers"], temp_strindex["replaced_rva"], STRINDEX["pointers"]):
			for pointer in pointers:
				if replace_lst and replace_lst.pop(0):
					pe.set_bytes_at_offset(pointer, replaced_rva)
	else:
		print_progress = PrintProgress(len(STRINDEX["replace"]))
		for strindex_index in range(len(STRINDEX["replace"])):
			replaced_rva = (STRDEX_SECTION_BASE_RVA + len(new_section_data)).to_bytes(BYTE_LENGTH, 'little')

			replaced_string = replace_with_table(STRINDEX["replace"][strindex_index], STRINDEX["settings"].get("replace", {}))
			new_section_data += bytes(replaced_string, 'utf-8') + b'\x00'

			for pointers in STRINDEX["pointers"][strindex_index]:
				pe.set_bytes_at_offset(pointers, replaced_rva)

			print_progress(strindex_index)
		print("(2/5) Created section data.")

	print("(3/5) Relocated pointers.")


	pe = pe_add_section(pe, Name=b".strdex", Characteristics=0xF0000040, Data=new_section_data)
	print("(4/5) Added '.strdex' section.")


	pe.write(file_filepath)
	print("(5/5) File was patched & saved successfully.")


	# os.system(f'cp "{file_filepath}" "/home/zwolfrost/.steam/steam/steamapps/common/Katana ZERO/Katana ZERO.exe"') # TESTING

def update(file_filepath: str, strindex_filepath: str, strindex_update_filepath: str):
	pe = pefile.PE(file_filepath)

	BYTE_LENGTH = 4 if pe.OPTIONAL_HEADER.Magic == 0x10b else 8

	STRINDEX = parse_strindex(strindex_filepath)

	if STRINDEX["type"] != "compatible":
		raise ValueError("This strindex file is not compatible with the update feature.")

	temp_strindex = {
		"rva_bytes": []
	}
	for strindex_index, offset in enumerate(mmap_indices_ordered(pe.__data__, [bytes(l, 'utf-8') for l in STRINDEX["original"]])):
		if offset == -1:
			print("String not found (skipping):\n" + STRINDEX["original"][strindex_index])
			temp_strindex["rva_bytes"].append(strindex_index)
			continue

		temp_strindex["rva_bytes"].append((pe.get_rva_from_offset(offset) + pe.OPTIONAL_HEADER.ImageBase).to_bytes(BYTE_LENGTH, 'little'))

	temp_strindex["pointers"] = mmap_indices_fixed(pe.__data__, temp_strindex["rva_bytes"])

	with open(strindex_update_filepath, 'w', encoding='utf-8') as f:
		f.write(STRINDEX["raw_header"])

		for original, replace, pointers in zip(STRINDEX["original"], STRINDEX["replace"], temp_strindex["pointers"]):
			f.write(STRINDEX_COMPATIBLE_FORMAT.format(len(pointers) * "1", original, replace))

		f.seek(f.tell() - 1)
		f.truncate()
	print("(1/1) Created updated strindex file.")

def filter(strindex_full_filepath: str, strindex_delta_filepath: str, strindex_filtered_filepath: str):
	STRINDEX_FULL = parse_strindex(strindex_full_filepath)
	STRINDEX_DELTA = parse_strindex(strindex_delta_filepath)

	if STRINDEX_DELTA["settings"].get("source_language"):
		try:
			from lingua import IsoCode639_1, LanguageDetectorBuilder
		except ImportError:
			raise ImportError(
				"Please install the 'lingua' package (pip install lingua) to use this feature.\n\
				(Or remove the 'source_language' key from the delta strindex file.)"
			)

		LANGUAGES = [getattr(IsoCode639_1, code.upper()) for code in STRINDEX_DELTA["settings"].get("among_languages")]

		if LANGUAGES:
			detector = LanguageDetectorBuilder.from_iso_codes_639_1(*LANGUAGES).build()
		else:
			detector = LanguageDetectorBuilder.build()

	STRINDEX_FULL_CHECK = STRINDEX_FULL["original"] or STRINDEX_FULL["replace"]
	STRINDEX_DELTA_CHECK = STRINDEX_DELTA["original"] or STRINDEX_DELTA["replace"]

	with open(strindex_filtered_filepath, 'w', encoding='utf-8') as f:
		f.write(STRINDEX_FULL["raw_header"])

		print_progress = PrintProgress(len(STRINDEX_FULL_CHECK))
		strindex_delta_index = 0
		for strindex_index in range(len(STRINDEX_FULL["replace"])):
			if strindex_delta_index < len(STRINDEX_DELTA["replace"]) and STRINDEX_FULL_CHECK[strindex_index] == STRINDEX_DELTA_CHECK[strindex_delta_index]:
				strindex_delta_index += 1
			elif STRINDEX_DELTA["settings"].get("source_language"):
				line_clean = re.sub(STRINDEX_DELTA["settings"].get("filter_pattern", ""), "", STRINDEX_FULL_CHECK[strindex_index])
				confidence = detector.compute_language_confidence_values(line_clean)[0]
				if confidence.language.iso_code_639_1 == getattr(IsoCode639_1, STRINDEX_DELTA["settings"]["source_language"].upper()) and confidence.value > 0.5:
					if STRINDEX_FULL["type"] == "compatible":
						f.write(
							STRINDEX_FULL["raw_pointers"][strindex_index] +
							STRINDEX_FULL["original"][strindex_index] + '\n' +
							STRINDEX_DELIMITERS[1] + '\n' +
							STRINDEX_FULL["replace"][strindex_index] + '\n'
						)
					else:
						f.write(
							STRINDEX_FULL["raw_pointers"][strindex_index] +
							STRINDEX_FULL["replace"][strindex_index] + '\n'
						)

			print_progress(strindex_index)
	print("(1/1) Filtered strindex file.")

def spellcheck(strindex_filepath: str, strindex_spellcheck_filepath: str, target_language: str):
	try:
		from language_tool_python import LanguageTool
	except ImportError:
		raise ImportError("Please install the 'language-tool-python' package (pip install language-tool-python) to use this feature.")

	STRINDEX = parse_strindex(strindex_filepath)

	target_language = target_language or STRINDEX["settings"].get("target_language")
	if not target_language:
		raise ValueError("Please specify the target language to spellcheck in the strindex file. (Or use the --language argument.)")

	lang = LanguageTool(target_language)
	print("(1/2) Created language tool.")

	with open(strindex_spellcheck_filepath, 'w', encoding='utf-8') as f:
		print_progress = PrintProgress(len(STRINDEX["replace"]))
		for strindex_index, replace in enumerate(STRINDEX["replace"]):
			line_clean = re.sub(STRINDEX["settings"].get("filter_pattern", ""), "", replace)
			for error in lang.check(line_clean):
				f.write('\n'.join(str(error).split('\n')[-3:]) + '\n')

			print_progress(strindex_index)
	print("(2/2) Spellchecked strindex file.")



def cmd_main():
	CHARACTER_CLASSES = {
		"default": " \t\n !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~",
		"symbols": "… ",
		"latin": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"spanish": "¡¿ÁÉÍÓÚÜÑáéíóúüñã",
		"cyrillic": "ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂҃҄҅҆҇҈҉ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽӾ",
	}

	args = argparse.ArgumentParser(prog="strindex", description="Command line string replacement tool for games.")

	args.add_argument("action", type=str, choices=["create", "patch", "update", "filter", "spellcheck"], help="Action to perform.")
	args.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE, help="One or more files to process.")
	args.add_argument("-o", "--output", type=str, help="Output file.")

	# create arguments
	args.add_argument("-c", "--compatible", action="store_true", help="Whether to create a strindex file compatible with the previous versions of a program.")
	args.add_argument("-w", "--whitelist", type=str, action="append", choices=(list(CHARACTER_CLASSES.keys()) + ["disable"]), default=[], help="Character classes to whitelist. If \"disable\" is used, all characters are allowed.")
	args.add_argument("-m", "--min-length", type=int, default=3, help="Minimum length of the strings to be included.")

	# spellcheck arguments
	args.add_argument("-l", "--language", type=str, help="Language to spellcheck the strings (ISO 639-1 code).")

	args = args.parse_args()

	if not all([os.path.exists(file) for file in args.files]):
		raise FileNotFoundError("One or more files do not exist.")

	args.whitelist = None if "disable" in args.whitelist else ''.join([CHARACTER_CLASSES[whitelist] for whitelist in ((args.whitelist or ["latin"]) + ["default"])])

	start_time = time.time()

	match args.action:
		case "create":
			create(*args.files, strindex_filepath=(args.output or "strindex_full.txt"), compatible=args.compatible, whitelist=args.whitelist, min_length=args.min_length)
		case "patch":
			patch(*args.files)
		case "update":
			update(*args.files, strindex_update_filepath=(args.output or "strindex_update.txt"))
		case "filter":
			filter(*args.files, strindex_filtered_filepath=(args.output or "strindex_filtered.txt"))
		case "spellcheck":
			spellcheck(*args.files, strindex_spellcheck_filepath=(args.output or "strindex_spellcheck.txt"), target_language=args.language)

	print("Time elapsed:", round(time.time() - start_time, 1), "seconds.")

def gui_main():
	from filedialpy import openFile

	NFS = "No file selected. Press enter to exit."

	print("Select the file to patch.")
	file_filepath = openFile(title="Select the file to patch", filter="*.exe")

	if not file_filepath:
		input(NFS)
		return

	print("Select the strindex file.")
	strindex_filepath = openFile(title="Select the strindex file", filter="*.txt")

	if not strindex_filepath:
		input(NFS)
		return

	patch(file_filepath, strindex_filepath)
	input("Press enter to exit.")

def main():
	try:
		if getattr(sys, 'frozen', False):
			gui_main()
		else:
			cmd_main()
	except (TypeError, FileNotFoundError, ImportError) as e:
		print(e)
	except pefile.PEFormatError as e:
		print("Error parsing the PE file:", e)
	except KeyboardInterrupt:
		print("Interrupted by user.")

if __name__ == "__main__":
	main()
