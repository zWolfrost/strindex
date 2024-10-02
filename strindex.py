import os, sys, re, json, argparse, pefile, time



class SectionDoubleP:
	"""
	Tested with pefile 1.2.10-123 on 32bit PE executable files.
	An implementation to push or pop a section header to the section table of a PE file.
	For further information refer to the docstrings of pop_back/push_back.
	by n0p (updated by zWolfrost)
	"""

	def __init__(self, file_path=None):
		self.pe = pefile.PE(file_path)

	def __adjust_optional_header(self):
		""" Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
			SizeOfUninitializedData of the optional header.
		"""

		# SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
		self.pe.OPTIONAL_HEADER.SizeOfImage = self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize

		self.pe.OPTIONAL_HEADER.SizeOfCode = 0
		self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
		self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0

		# Recalculating the sizes by iterating over every section and checking if
		# the appropriate characteristics are set.
		for section in self.pe.sections:
			if section.Characteristics & 0x00000020:
				# Section contains code.
				self.pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
			if section.Characteristics & 0x00000040:
				# Section contains initialized data.
				self.pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
			if section.Characteristics & 0x00000080:
				# Section contains uninitialized data.
				self.pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

	def __add_header_space(self):
		""" To make space for a new section header a buffer filled with nulls is added at the
			end of the headers. The buffer has the size of one file alignment.
			The data between the last section header and the end of the headers is copied to
			the new space (everything moved by the size of one file alignment). If any data
			directory entry points to the moved data the pointer is adjusted.
		"""

		FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
		SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders

		data = b'\x00' * FileAlignment

		# Adding the null buffer.
		self.pe.__data__ = self.pe.__data__[:SizeOfHeaders] + data + self.pe.__data__[SizeOfHeaders:]

		section_table_offset = (
			self.pe.DOS_HEADER.e_lfanew + 4 + self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader
		)

		# Copying the data between the last section header and SizeOfHeaders to the newly allocated
		# space.
		new_section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections*0x28
		size = SizeOfHeaders - new_section_offset
		data = self.pe.get_data(new_section_offset, size)
		self.pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)

		# Filling the space, from which the data was copied from, with NULLs.
		self.pe.set_bytes_at_offset(new_section_offset, b'\x00' * FileAlignment)

		data_directory_offset = section_table_offset - self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8

		# Checking data directories if anything points to the space between the last section header
		# and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
		for data_offset in range(data_directory_offset, section_table_offset, 0x8):
			data_rva = self.pe.get_dword_from_offset(data_offset)

			if new_section_offset <= data_rva and data_rva < SizeOfHeaders:
				self.pe.set_dword_at_offset(data_offset, data_rva + FileAlignment)

		SizeOfHeaders_offset = self.pe.DOS_HEADER.e_lfanew + 4 + self.pe.FILE_HEADER.sizeof() + 0x3C

		# Adjusting the SizeOfHeaders value.
		self.pe.set_dword_at_offset(SizeOfHeaders_offset, SizeOfHeaders + FileAlignment)

		section_raw_address_offset = section_table_offset + 0x14

		# The raw addresses of the sections are adjusted.
		for section in self.pe.sections:
			if section.PointerToRawData != 0:
				self.pe.set_dword_at_offset(section_raw_address_offset, section.PointerToRawData+FileAlignment)

			section_raw_address_offset += 0x28

		# All changes in this method were made to the raw data (__data__). To make these changes
		# accessbile in self.pe __data__ has to be parsed again. Since a new pefile is parsed during
		# the init method, the easiest way is to replace self.pe with a new pefile based on __data__
		# of the old self.pe.
		self.pe = pefile.PE(data=self.pe.__data__)


	def pop_back(self):
		""" Removes the last section of the section table.
			Deletes the section header in the section table, the data of the section in the file,
			pops the last section in the sections list of pefile and adjusts the sizes in the
			optional header.
		"""

		# Checking if there are any sections to pop.
		if self.pe.FILE_HEADER.NumberOfSections > 0 and self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):

			# Stripping the data of the section from the file.
			if self.pe.sections[-1].SizeOfRawData != 0:
				self.pe.__data__ = (
					self.pe.__data__[:self.pe.sections[-1].PointerToRawData] +
					self.pe.__data__[self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData:]
				)

			# Overwriting the section header in the binary with nulls.
			# Getting the address of the section table and manually overwriting
			# the header with nulls unfortunally didn't work out.
			self.pe.sections[-1].Name = '\x00'*8
			self.pe.sections[-1].Misc_VirtualSize = 0x00000000
			self.pe.sections[-1].VirtualAddress = 0x00000000
			self.pe.sections[-1].SizeOfRawData = 0x00000000
			self.pe.sections[-1].PointerToRawData = 0x00000000
			self.pe.sections[-1].PointerToRelocations = 0x00000000
			self.pe.sections[-1].PointerToLinenumbers = 0x00000000
			self.pe.sections[-1].NumberOfRelocations = 0x0000
			self.pe.sections[-1].NumberOfLinenumbers = 0x0000
			self.pe.sections[-1].Characteristics = 0x00000000

			self.pe.sections.pop()

			self.pe.FILE_HEADER.NumberOfSections -= 1

			self.__adjust_optional_header()
		else:
			raise ValueError("There's no section to pop.")


	def push_back(
		self, Name=".NewSec", Data="", Characteristics=0xE00000E0,
		VirtualSize=0x00000000, VirtualAddress=0x00000000,
		RawSize=0x00000000, RawAddress=0x00000000
	):
		""" Adds the section, specified by the functions parameters, at the end of the section
			table.
			If the space to add an additional section header is insufficient, a buffer is inserted
			after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
			is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.

			A call with no parameters creates the same section header as LordPE does. But for the
			binary to be executable without errors a VirtualSize > 0 has to be set.

			If a RawSize > 0 is set or Data is given the data gets aligned to the FileAlignment and
			is attached at the end of the file.
		"""

		if self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):

			FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
			SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment

			if len(Name) > 8:
				raise ValueError("The name is too long for a section.")

			if (
				VirtualAddress < (self.pe.sections[-1].Misc_VirtualSize + self.pe.sections[-1].VirtualAddress)
				or VirtualAddress % SectionAlignment != 0
			):
				if (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
					VirtualAddress = (
						self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize -
						(self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment
					)
				else:
					VirtualAddress = self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize

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
				self.pe.DOS_HEADER.e_lfanew + 4 + self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader
			)

			# If the new section header exceeds the SizeOfHeaders there won't be enough space
			# for an additional section header. Besides that it's checked if the 0x28 bytes
			# (size of one section header) after the last current section header are filled
			# with nulls/ are free to use.
			if (
				self.pe.OPTIONAL_HEADER.SizeOfHeaders < section_table_offset + (self.pe.FILE_HEADER.NumberOfSections+1)*0x28
				or not all(char == b'\x00' for char in self.pe.get_data(section_table_offset + (self.pe.FILE_HEADER.NumberOfSections)*0x28, 0x28))
			):
				# Checking if more space can be added.
				if self.pe.OPTIONAL_HEADER.SizeOfHeaders < self.pe.sections[0].VirtualAddress:
					self.__add_header_space()
					# print("Additional space to add a new section header was allocated.")
				else:
					raise ValueError("No more space can be added for the section header.")


			# The validity check of RawAddress is done after space for a new section header may
			# have been added because if space had been added the PointerToRawData of the previous
			# section would have changed.
			if RawAddress != self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData:
				RawAddress = self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData


			# Appending the data of the new section to the file.
			if len(Data) > 0:
				self.pe.__data__ = self.pe.__data__[:RawAddress] + Data + self.pe.__data__[RawAddress:]

			section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections*0x28

			# Manually writing the data of the section header to the file.
			self.pe.set_bytes_at_offset(section_offset, Name)
			self.pe.set_dword_at_offset(section_offset+0x08, VirtualSize)
			self.pe.set_dword_at_offset(section_offset+0x0C, VirtualAddress)
			self.pe.set_dword_at_offset(section_offset+0x10, RawSize)
			self.pe.set_dword_at_offset(section_offset+0x14, RawAddress)
			self.pe.set_dword_at_offset(section_offset+0x18, 0x00000000)
			self.pe.set_dword_at_offset(section_offset+0x1C, 0x00000000)
			self.pe.set_word_at_offset(section_offset+0x20, 0x0000)
			self.pe.set_word_at_offset(section_offset+0x22, 0x0000)
			self.pe.set_dword_at_offset(section_offset+0x24, Characteristics)

			self.pe.FILE_HEADER.NumberOfSections += 1

			# Parsing the section table of the file again to add the new section to the sections
			# list of pefile.
			self.pe.parse_sections(section_table_offset)

			self.__adjust_optional_header()
		else:
			raise ValueError(
				"The NumberOfSections specified in the file header and the size of the sections list of pefile don't match."
			)

		return self.pe



CHARACTER_CLASSES = {
	"default": " \t\n\r !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~",
	"symbols": "… ",
	"latin": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"spanish": "¡¿ÁÉÍÓÚÜÑáéíóúüñã",
	"cyrillic": "ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂҃҄҅҆҇҈҉ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽӾ",
}

STRINDEX_DELIMITERS = ('_' * 80, '↓' * 80, '/', '-')



def print_progress(iteration, total, format=('[', '#', '-', ']')):
	print(round(iteration / total * 100, 1), end="%   \r")
	# length = os.get_terminal_size().columns - len(format[0]) - len(format[3]) - len("100.0%") - 1
	# filled_length = int(length * iteration // total)
	# percent = round(100 * iteration / total, 2)
	# print(
	# 	format[0] + format[1] * filled_length + format[2] * (length - filled_length) + format[3] +
	# 	' ' + str(percent) + "%",
	# 	end='\r'
	# )


def replace_with_table(string: str, table: dict[str, str]) -> str:
	for key, value in table.items():
		string = string.replace(key, value)
	return string


def parse_strindex(filepath: str) -> tuple[list[str], list[str]]:
	with open(filepath, 'r', encoding='utf-8') as f:
		strindex = {
			"original": [],
			"replace": [],
			"raw_pointers": [],
			"pointers": [],
			"settings": {}
		}

		for line in f:
			if line.startswith("{"):
				strindex_settings_lines = line
				while True:
					try:
						strindex["settings"] = json.loads(strindex_settings_lines)
					except json.JSONDecodeError as e:
						line = f.readline()
						if line.startswith(STRINDEX_DELIMITERS[0]):
							print("Error parsing settings:", e)
							exit(1)
						strindex_settings_lines += line
					else:
						break
			elif line.startswith(STRINDEX_DELIMITERS[0]):
				strindex["is_compatible"] = STRINDEX_DELIMITERS[2] not in line

				strindex["replace"].append('')
				if strindex["is_compatible"]:
					strindex["original"].append('')
					get_pointers = lambda line: [bool(int(x)) for x in line.rstrip('\n').lstrip(STRINDEX_DELIMITERS[0])]
				else:
					get_pointers = lambda line: line.rstrip('\n').rsplit(STRINDEX_DELIMITERS[2], 1)[1].split(STRINDEX_DELIMITERS[3])

				strindex["raw_pointers"].append(line)
				strindex["pointers"].append(get_pointers(line))
				break

		is_original = strindex["is_compatible"]
		is_start = True
		for line in f:
			if line.startswith(STRINDEX_DELIMITERS[0]):
				is_start = True
				is_original = strindex["is_compatible"]
				if strindex["is_compatible"]:
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


def open_by_null(*args, **kwargs):
	with open(*args, **kwargs) as file:
		string = b''
		char_count = 0

		for line in file:
			for char in line:
				if char == 0:
					yield string, char_count - len(string)
					string = b''
				else:
					string += bytes([char])

				char_count += 1

		yield string, char_count


def mmap_indices(mm, search_str):
	index = 0
	all_indices = []
	while True:
		index = mm.find(search_str, index)
		if index == -1:
			break
		all_indices.append(index)
		index += 1

	return all_indices



def create(file_filepath, strindex_filepath, compatible, whitelist, min_length):
	sdp = SectionDoubleP(file_filepath)
	print("(1/2) Opened PE file.")

	STRINDEX_HEADER = "###############################################################################/ offset /  rva   / offsets of rva pointers /\n"
	STRINDEX_FORMAT = f"{STRINDEX_DELIMITERS[0]}{{}}{STRINDEX_DELIMITERS[2]}{{}}{STRINDEX_DELIMITERS[2]}{{}}\n{{}}\n"
	STRINDEX_COMPATIBLE_FORMAT = f"{STRINDEX_DELIMITERS[0]}{{}}\n{{}}\n{STRINDEX_DELIMITERS[1]}\n{{}}\n"

	BYTE_LENGTH = 4 if sdp.pe.OPTIONAL_HEADER.Magic == 0x10b else 8

	with open(strindex_filepath, 'w', encoding='utf-8') as f:
		f.write(STRINDEX_HEADER)

		for string, offset in open_by_null(file_filepath, 'rb'):
			try:
				string = string.decode('utf-8')
			except UnicodeDecodeError:
				continue
			if len(string) >= min_length and all(x in whitelist for x in string):
				rva = sdp.pe.get_rva_from_offset(offset) + sdp.pe.OPTIONAL_HEADER.ImageBase
				rva_indexes = mmap_indices(sdp.pe.__data__, rva.to_bytes(BYTE_LENGTH, 'little'))
				if rva_indexes:
					if compatible:
						f.write(STRINDEX_COMPATIBLE_FORMAT.format(len(rva_indexes) * "1", string, string))
					else:
						hex_offset = hex(offset).lstrip("0x").rjust(8, '0')
						hex_rva = hex(rva).lstrip("0x").rjust(2 * BYTE_LENGTH, '0')
						hex_rva_offsets = STRINDEX_DELIMITERS[3].join([hex(offset).lstrip("0x").rjust(8, '0') for offset in rva_indexes])
						f.write(STRINDEX_FORMAT.format(hex_offset, hex_rva, hex_rva_offsets, string))
				print_progress(offset, len(sdp.pe.__data__))

		f.seek(f.tell() - 1)
		f.truncate()
	print("(2/2) Created strindex file.")


def patch(file_filepath, strindex_filepath):
	file_filepath_bak = file_filepath + '.bak'

	COPY_COMMAND = "copy" if sys.platform == "win32" else "cp"
	DEV_NULL = "> NUL" if sys.platform == "win32" else "> /dev/null"
	if os.path.exists(file_filepath_bak):
		os.system(f'{COPY_COMMAND} "{file_filepath_bak}" "{file_filepath}" {DEV_NULL}')
		print("(1/7) Restored from backup.")
	else:
		os.system(f'{COPY_COMMAND} "{file_filepath}" "{file_filepath_bak}" {DEV_NULL}')
		print("(1/7) Created backup.")


	sdp = SectionDoubleP(file_filepath_bak)
	print("(2/7) Opened PE file.")


	if any(sect.Name == b".strdex\0" for sect in sdp.pe.sections):
		print("This file is already patched with strindex.")
		return


	BYTE_LENGTH = 4 if sdp.pe.OPTIONAL_HEADER.Magic == 0x10b else 8


	strdex_section_base_rva = sdp.pe.sections[-1].VirtualAddress + sdp.pe.sections[-1].Misc_VirtualSize
	if strdex_section_base_rva % sdp.pe.OPTIONAL_HEADER.SectionAlignment:
		strdex_section_base_rva += sdp.pe.OPTIONAL_HEADER.SectionAlignment - (strdex_section_base_rva % sdp.pe.OPTIONAL_HEADER.SectionAlignment)
	strdex_section_base_rva += sdp.pe.OPTIONAL_HEADER.ImageBase


	new_section_data = b''
	STRINDEX = parse_strindex(strindex_filepath)
	print("(3/7) Parsed strindex file.")


	if STRINDEX["settings"].get("file_size") and STRINDEX["settings"]["file_size"] != len(sdp.pe.__data__):
		print("File size does not match the file size the strindex was created with. You might encounter issues.")


	if STRINDEX["is_compatible"]:
		rva_replace_table = {}
		for string, offset in open_by_null(file_filepath_bak, 'rb'):
			if STRINDEX["original"] and string == bytes(STRINDEX["original"][0], 'utf-8'):
				STRINDEX["original"].pop(0)

				# get_rva_from_offset is just "sect.VirtualAddress - sect.PointerToRawData + offset" (if encountering issues try this)
				# sect = sdp.pe.get_section_by_offset(offset)
				# if sect.VirtualAddress - sect.PointerToRawData + offset == sdp.pe.get_rva_from_offset(offset):
				# 	print("RVA calculation is somehow different from the PE method. Keep an eye on this.")

				original_rva = sdp.pe.get_rva_from_offset(offset) + sdp.pe.OPTIONAL_HEADER.ImageBase
				replaced_rva = strdex_section_base_rva + len(new_section_data)
				rva_replace_table[original_rva.to_bytes(BYTE_LENGTH, 'little')] = replaced_rva.to_bytes(BYTE_LENGTH, 'little')

				replaced_string = replace_with_table(STRINDEX["replace"].pop(0), STRINDEX["settings"].get("replace", {}))
				new_section_data += bytes(replaced_string, 'utf-8') + b'\x00'

		if STRINDEX["original"]:
			print("String not found:\n", STRINDEX["original"][0])
			return
	else:
		rva_replace_table = []
		for line in STRINDEX["replace"]:
			replaced_rva = strdex_section_base_rva + len(new_section_data)
			rva_replace_table.append(replaced_rva.to_bytes(BYTE_LENGTH, 'little'))

			line = replace_with_table(line, STRINDEX["settings"].get("replace", {}))
			new_section_data += bytes(line, 'utf-8') + b'\x00'
	print("(4/7) Found strings.")


	if STRINDEX["is_compatible"]:
		strindex_index = 0
		for original, replaced in rva_replace_table.items():
			for index in mmap_indices(sdp.pe.__data__, original):
				if STRINDEX["pointers"][strindex_index] and STRINDEX["pointers"][strindex_index].pop(0):
					sdp.pe.__data__[index:index + BYTE_LENGTH] = replaced
			strindex_index += 1
			print_progress(strindex_index, len(rva_replace_table))
	else:
		strindex_index = 0
		for replaced in rva_replace_table:
			for pointers in STRINDEX["pointers"][strindex_index]:
				sdp.pe.set_bytes_at_offset(int(pointers, 16), replaced)
			strindex_index += 1
	print("(5/7) Relocated strings.")


	sdp.push_back(Name=b".strdex", Characteristics=0xD0000040, Data=new_section_data)
	print("(6/7) Added .strdex section.")


	sdp.pe.write(file_filepath)
	print("(7/7) File was patched successfully.")


	# os.system(f'cp "{file_filepath}" "/home/zwolfrost/.steam/steam/steamapps/common/Katana ZERO/Katana ZERO.exe"')


def filter(strindex_full_filepath, strindex_delta_filepath, strindex_filtered_filepath):
	STRINDEX_FULL = parse_strindex(strindex_full_filepath)
	STRINDEX_DELTA = parse_strindex(strindex_delta_filepath)

	if STRINDEX_DELTA["settings"].get("source_language"):
		try:
			from lingua import IsoCode639_1, LanguageDetectorBuilder
		except ImportError:
			print("Please install the 'lingua' package (pip install lingua) to use this feature.\n(Or remove the 'source_language' key from the delta strindex file.)")
			return

		LANGUAGES = [getattr(IsoCode639_1, code.upper()) for code in STRINDEX_DELTA["settings"].get("among_languages")]

		if LANGUAGES:
			detector = LanguageDetectorBuilder.from_iso_codes_639_1(*LANGUAGES).build()
		else:
			detector = LanguageDetectorBuilder.build()

	STRINDEX_FULL_CHECK = STRINDEX_FULL["original"] or STRINDEX_FULL["replace"]
	STRINDEX_DELTA_CHECK = STRINDEX_DELTA["original"] or STRINDEX_DELTA["replace"]

	with open(strindex_filtered_filepath, 'w', encoding='utf-8') as strindex_filter:
		strindex_full_index = 0
		strindex_delta_index = 0
		while strindex_full_index < len(STRINDEX_FULL["replace"]):
			if (strindex_delta_index < len(STRINDEX_DELTA["replace"]) and
		 		STRINDEX_FULL_CHECK[strindex_full_index] == STRINDEX_DELTA_CHECK[strindex_delta_index]
			):
				strindex_delta_index += 1
			elif STRINDEX_DELTA["settings"].get("source_language"):
				line_clean = re.sub(STRINDEX_DELTA["settings"].get("filter_pattern", ""), "", STRINDEX_FULL_CHECK[strindex_full_index])
				confidence = detector.compute_language_confidence_values(line_clean)[0]
				if confidence.language.iso_code_639_1 == getattr(IsoCode639_1, STRINDEX_DELTA["settings"]["source_language"].upper()) and confidence.value > 0.5:
					if STRINDEX_FULL["is_compatible"]:
						strindex_filter.write(
							STRINDEX_FULL["raw_pointers"][strindex_full_index] +
							STRINDEX_FULL["original"][strindex_full_index] + '\n' +
							STRINDEX_DELIMITERS[1] + '\n' +
							STRINDEX_FULL["replace"][strindex_full_index] + '\n'
						)
					else:
						strindex_filter.write(
							STRINDEX_FULL["raw_pointers"][strindex_full_index] +
							STRINDEX_FULL["replace"][strindex_full_index] + '\n'
						)

			strindex_full_index += 1
			print_progress(strindex_full_index, len(STRINDEX_FULL_CHECK))
	print("Filtered strindex file.")


def spellcheck(strindex_filepath, strindex_spellcheck_filepath, target_language):
	try:
		from language_tool_python import LanguageTool
	except ImportError:
		print("Please install the 'language-tool-python' package (pip install language-tool-python) to use this feature.")
		return

	STRINDEX = parse_strindex(strindex_filepath)

	target_language = target_language or STRINDEX["settings"].get("target_language")
	if not target_language:
		print("Please specify the target language to spellcheck in the strindex file. (Or use the --language argument.)")
		return

	lang = LanguageTool(target_language)
	with open(strindex_spellcheck_filepath, 'w', encoding='utf-8') as f:
		strindex_index = 0
		while strindex_index < len(STRINDEX["replace"]):
			line_clean = re.sub(STRINDEX["settings"].get("filter_pattern", ""), "", STRINDEX["replace"][strindex_index])
			for error in lang.check(line_clean):
				f.write('\n'.join(str(error).split('\n')[-3:]) + '\n')

			strindex_index += 1
			print_progress(strindex_index, len(STRINDEX["replace"]))
	print("Spellchecked strindex file.")



def main():
	start_time = time.time()

	args = argparse.ArgumentParser(prog="strindex", description="Command line string replacement tool for games.")

	args.add_argument("action", type=str, choices=["create", "patch", "filter", "spellcheck"], help="Action to perform.")
	args.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE, help="One or more files to process.")
	args.add_argument("-o", "--output", type=str, help="Output file.")

	# create arguments
	args.add_argument("-c", "--compatible", action="store_true", help="Whether to create a strindex file compatible with the previous versions of a program.")
	args.add_argument("-w", "--whitelist", type=str, action="append", choices=CHARACTER_CLASSES.keys(), default=[], help="Character classes to whitelist.")
	args.add_argument("-m", "--min-length", type=int, default=3, help="Minimum length of the strings to be included.")

	# spellcheck arguments
	args.add_argument("-l", "--language", type=str, help="Language to spellcheck the strings (ISO 639-1 code).")

	args = args.parse_args()

	if not all([os.path.exists(file) for file in args.files]):
		print("One or more files do not exist.")
		return

	args.whitelist = ''.join([CHARACTER_CLASSES[whitelist] for whitelist in ((args.whitelist or ["latin"]) + ["default"])])

	try:
		match args.action:
			case "create":
				create(*args.files, strindex_filepath=(args.output or "strindex_full.txt"), compatible=args.compatible, whitelist=args.whitelist, min_length=args.min_length)
			case "patch":
				patch(*args.files)
			case "filter":
				filter(*args.files, strindex_filtered_filepath=(args.output or "strindex_filtered.txt"))
			case "spellcheck":
				spellcheck(*args.files, strindex_spellcheck_filepath=(args.output or "strindex_spellcheck.txt"), target_language=args.language)
	except (TypeError, FileNotFoundError) as e:
		print(e)
	except KeyboardInterrupt:
		print("Interrupted by user.")

	print("Time elapsed:", round(time.time() - start_time), "seconds.")


def frozen_main():
	from filedialpy import openFile

	NFS = "No file selected. Press enter to exit."

	print("Select the file to patch.")
	file_filepath = openFile(
		title="Select the file to patch",
		filter="*.exe"
	)

	if not file_filepath:
		input(NFS)
		return

	print("Select the strindex file.")
	strindex_filepath = openFile(
		title="Select the strindex file",
		filter="*.txt"
	)

	if not strindex_filepath:
		input(NFS)
		return

	patch(file_filepath, strindex_filepath)
	input("Press enter to exit.")



if __name__ == "__main__":
	if getattr(sys, 'frozen', False):
		frozen_main()
	else:
		main()
