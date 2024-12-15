from ..utils import Strindex, StrindexSettings, FileBytearray
import pefile
pefile.fast_load = True


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

def pe_get_rva_from_offset(pe: pefile.PE, offset: int) -> int:
	""" Returns the RVA of the specified offset. """
	rva = pe.get_rva_from_offset(offset)
	return rva + pe.OPTIONAL_HEADER.ImageBase if rva else None

def pe_initialize_data(pe: pefile.PE, data: FileBytearray):
	data.byte_length = 4 if pe.OPTIONAL_HEADER.Magic == 0x10b else 8
	data.byte_order = 'little'


SECTION_NAME = b".strdex"

def validate(data: FileBytearray) -> bool:
	""" Checks if the file is a valid PE file. """
	try:
		pe = pefile.PE(data=bytes(data))
	except pefile.PEFormatError:
		return False

	if pe.DOS_HEADER.e_magic == 0x5A4D:
		if b"\0Cabinet.dll\0" in data:
			print("Warning: This PE file is likely a self-extracting CAB file. The strings might be compressed.")
		return True

	return False

def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	pe = pefile.PE(data=bytes(data))

	if pe_section_exists(pe, SECTION_NAME):
		print(f"Warning: this file already contains a '{SECTION_NAME.decode('utf-8')}' section.")

	pe_initialize_data(pe, data)

	return data.create_macro(settings, lambda offset: pe_get_rva_from_offset(pe, offset))

def patch(data: FileBytearray, strindex: Strindex) -> FileBytearray:
	"""
		The patching is done by adding a new section to the PE file, containing the new data.
		The pointers are changed to reference the new data RVAs'.
	"""

	pe = pefile.PE(data=bytes(data))

	if pe_section_exists(pe, SECTION_NAME):
		raise ValueError(f"This file already contains a '{SECTION_NAME.decode('utf-8')}' section.")

	pe_initialize_data(pe, data)

	STRDEX_SECTION_BASE_RVA = pe_get_new_section_base_rva(pe)

	new_data = data.patch_macro(strindex,
		lambda offset: pe_get_rva_from_offset(pe, offset),
		lambda offset: STRDEX_SECTION_BASE_RVA + offset,
		lambda string: bytearray(string, 'utf-8') + b'\x00'
	)

	pe = pe_add_section(pefile.PE(data=bytes(data)), Name=SECTION_NAME, Data=new_data, Characteristics=0xF0000040)
	print(f"Added '{SECTION_NAME.decode('utf-8')}' section.")

	return FileBytearray(pe.write())
