import pefile

from strindex.utils import FileBuffer, ModuleSettings, Print, Strindex, StrindexSettings

SETTINGS = ModuleSettings(
	default_byte_order="little",
	filter_after_create=False
)


class PEFileWrapper(pefile.PE):
	def __init__(self, data: bytearray):
		super().__init__(data=bytes(data), fast_load=True)


	def get_new_section_rva(self) -> int:
		""" Returns the base rva for a possibly new PE section. """
		new_section_base_rva = self.sections[-1].VirtualAddress + self.sections[-1].Misc_VirtualSize
		virtual_size_remainder = self.sections[-1].Misc_VirtualSize % self.OPTIONAL_HEADER.SectionAlignment
		if virtual_size_remainder != 0:
			new_section_base_rva += self.OPTIONAL_HEADER.SectionAlignment - virtual_size_remainder
		return new_section_base_rva


	def add_header_space(self):
		"""
			To make space for a new section header a buffer filled with nulls is added at the
			end of the headers. The buffer has the size of one file alignment.
			The data between the last section header and the end of the headers is copied to
			the new space (everything moved by the size of one file alignment).
			If any data directory entry points to the moved data the pointer is adjusted.
		"""

		data = b"\x00" * self.OPTIONAL_HEADER.FileAlignment

		def insert_at_offset(offset: int, data: bytes):
			self.__data__ = self.__data__[:offset] + data + self.__data__[offset:]

		# Adding the null buffer.
		insert_at_offset(self.OPTIONAL_HEADER.SizeOfHeaders, data)

		section_table_offset = (
			self.DOS_HEADER.e_lfanew + 4 + self.FILE_HEADER.sizeof() + self.FILE_HEADER.SizeOfOptionalHeader
		)

		# Copying the data between the last section header and SizeOfHeaders to the newly allocated space.
		new_section_offset = section_table_offset + self.FILE_HEADER.NumberOfSections * 0x28
		data = self.get_data(new_section_offset, self.OPTIONAL_HEADER.SizeOfHeaders - new_section_offset)
		self.set_bytes_at_offset(new_section_offset + self.OPTIONAL_HEADER.FileAlignment, data)

		# Filling the space, from which the data was copied from, with NULLs.
		self.set_bytes_at_offset(new_section_offset, b"\x00" * self.OPTIONAL_HEADER.FileAlignment)

		data_directory_offset = section_table_offset - self.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8

		# Checking data directories if anything points to the space between the last section header
		# and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
		for data_offset in range(data_directory_offset, section_table_offset, 0x8):
			data_rva = self.get_dword_from_offset(data_offset)

			if new_section_offset <= data_rva < self.OPTIONAL_HEADER.SizeOfHeaders:
				self.set_dword_at_offset(data_offset, data_rva + self.OPTIONAL_HEADER.FileAlignment)

		SizeOfHeaders_offset = self.DOS_HEADER.e_lfanew + 4 + self.FILE_HEADER.sizeof() + 0x3C

		# Adjusting the SizeOfHeaders value.
		self.set_dword_at_offset(
			SizeOfHeaders_offset,
			self.OPTIONAL_HEADER.SizeOfHeaders + self.OPTIONAL_HEADER.FileAlignment
		)

		section_raw_address_offset = section_table_offset + 0x14

		# The raw addresses of the sections are adjusted.
		for section in self.sections:
			if section.PointerToRawData != 0:
				self.set_dword_at_offset(
					section_raw_address_offset,
					section.PointerToRawData + self.OPTIONAL_HEADER.FileAlignment
				)

			section_raw_address_offset += 0x28

		# The SizeOfHeaders and the PointerToRawData of the sections are increased by FileAlignment.
		# This is untested! It might be necessary to reparse the pe file data again.
		alignment = self.OPTIONAL_HEADER.FileAlignment

		self.OPTIONAL_HEADER.SizeOfHeaders += alignment

		for section in self.sections:
			if section.PointerToRawData:
				section.PointerToRawData += alignment


	def add_section(self, Name: str, Data: str, Characteristics=0xE00000E0):
		"""
			Tested with pefile 1.2.10-123 on 32bit PE executable files.
			An implementation to push a section header to the section table of a PE file.
			by n0p

			Adds the section, specified by the functions parameters, at the end of the section table.
			If the space to add an additional section header is insufficient, a buffer is inserted
			after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
			is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.
		"""

		if self.FILE_HEADER.NumberOfSections != len(self.sections):
			raise ValueError(
				"The NumberOfSections specified in the file header "
				"and the size of the sections list of pefile don't match."
			)

		if len(Name) > 8:
			raise ValueError("The name is too long for a section.")

		if (len(Data) % self.OPTIONAL_HEADER.FileAlignment) != 0:
			# Padding the data of the section.
			Data += b"\x00" * (self.OPTIONAL_HEADER.FileAlignment - (len(Data) % self.OPTIONAL_HEADER.FileAlignment))

		section_table_offset = (
			self.DOS_HEADER.e_lfanew + 4 + self.FILE_HEADER.sizeof() + self.FILE_HEADER.SizeOfOptionalHeader
		)

		# If the new section header exceeds the SizeOfHeaders there won't be enough space
		# for an additional section header. Besides that it's checked if the 0x28 bytes
		# (size of one section header) after the last current section header are filled
		# with nulls / are free to use.
		_num_sections = self.FILE_HEADER.NumberOfSections
		if (
			self.OPTIONAL_HEADER.SizeOfHeaders < section_table_offset + (_num_sections + 1) * 0x28 or
			not all(char == b"\x00" for char in self.get_data(section_table_offset + _num_sections * 0x28, 0x28))
		):
			# Checking if more space can be added.
			if self.OPTIONAL_HEADER.SizeOfHeaders < self.sections[0].VirtualAddress:
				self.add_header_space()
			else:
				raise ValueError("No more space can be added for the section header.")

		# The validity check of RawAddress is done after space for a new section header may
		# have been added because if space had been added the PointerToRawData of the previous
		# section would have changed.
		RawAddress = self.sections[-1].PointerToRawData + self.sections[-1].SizeOfRawData

		# Appending the data of the new section to the file.
		self.__data__ = self.__data__[:RawAddress] + Data + self.__data__[RawAddress:]

		section_offset = section_table_offset + self.FILE_HEADER.NumberOfSections * 0x28

		# Manually writing the data of the section header to the file.
		self.set_bytes_at_offset(section_offset, Name)
		self.set_dword_at_offset(section_offset + 0x08, len(Data))
		self.set_dword_at_offset(section_offset + 0x0C, self.get_new_section_rva())
		self.set_dword_at_offset(section_offset + 0x10, len(Data))
		self.set_dword_at_offset(section_offset + 0x14, RawAddress)
		self.set_dword_at_offset(section_offset + 0x18, 0x00000000)
		self.set_dword_at_offset(section_offset + 0x1C, 0x00000000)
		self.set_word_at_offset(section_offset + 0x20, 0x0000)
		self.set_word_at_offset(section_offset + 0x22, 0x0000)
		self.set_dword_at_offset(section_offset + 0x24, Characteristics)

		self.FILE_HEADER.NumberOfSections += 1

		# Parsing the section table of the file again to add the new section to the sections list of pefile.
		self.parse_sections(section_table_offset)

		# SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
		self.OPTIONAL_HEADER.SizeOfImage = self.sections[-1].VirtualAddress + self.sections[-1].Misc_VirtualSize

		self.OPTIONAL_HEADER.SizeOfCode = 0
		self.OPTIONAL_HEADER.SizeOfInitializedData = 0
		self.OPTIONAL_HEADER.SizeOfUninitializedData = 0

		# Recalculating the sizes by iterating over every section and checking if
		# the appropriate characteristics are set.
		for section in self.sections:
			if section.Characteristics & 0x00000020:
				# Section contains code.
				self.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
			if section.Characteristics & 0x00000040:
				# Section contains initialized data.
				self.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
			if section.Characteristics & 0x00000080:
				# Section contains uninitialized data.
				self.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData


	def section_exists(self, section_name: str) -> bool:
		""" Checks if a section with the specified name exists. """
		return any(sect.Name == section_name.ljust(8, b"\x00") for sect in self.sections)


	def get_rva_from_offset(self, offset: int) -> int:
		""" Returns the RVA of the specified offset. """
		rva = super().get_rva_from_offset(offset)
		return rva + self.OPTIONAL_HEADER.ImageBase if rva is not None else None


	def get_section_range(self, section_name: str) -> range:
		""" Returns the start and end offset of the specified section. """
		for sect in self.sections:
			if sect.Name == section_name.ljust(8, b"\x00"):
				return range(sect.PointerToRawData, sect.PointerToRawData + sect.SizeOfRawData)
		return None


	@property
	def byte_length(self) -> int:
		""" Returns the byte length of the PE file. """
		return 4 if self.OPTIONAL_HEADER.Magic == 0x10b else 8


SECTION_NAME = b".strdex"


def match(data: FileBuffer) -> bool:
	""" Checks if the file is a valid PE file. """
	if data[0:2] != b"\x4d\x5a":
		return False

	try:
		PEFileWrapper(data)
	except pefile.PEFormatError:
		return False

	if b"\0Cabinet.dll\0" in data:
		Print.warning(
			"This PE file is likely a self-extracting CAB file;\n"
			"You might want to extract the embedded files first."
		)

	return True


def create(data: FileBuffer, settings: StrindexSettings) -> Strindex:
	pe = PEFileWrapper(data)

	if pe.section_exists(SECTION_NAME):
		Print.warning(
			f'This file contains a "{SECTION_NAME.decode('utf-8')}" section;\n'
			"It has likely already been patched once."
		)

	data.byte_length = pe.byte_length

	return data.create_pointers_macro(
		settings,
		lambda offset: data.from_int(rva) if (rva := pe.get_rva_from_offset(offset)) is not None else None
	)


def patch(data: FileBuffer, strindex: Strindex) -> FileBuffer:
	"""
		The patching is done by adding a new section to the PE file, containing the new data.
		The pointers are changed to reference the new data RVAs'.
	"""

	pe = PEFileWrapper(data)

	if pe.section_exists(SECTION_NAME):
		raise ValueError(
			f"This file already contains a \"{SECTION_NAME.decode('utf-8')}\" section. It can't be patched again."
		)

	data.byte_length = pe.byte_length

	STRDEX_SECTION_BASE_RVA = pe.get_new_section_rva() + pe.OPTIONAL_HEADER.ImageBase

	new_data = data.patch_pointers_macro(
		strindex,
		lambda offset: data.from_int(rva) if (rva := pe.get_rva_from_offset(offset)) is not None else None,
		lambda offset: data.from_int(STRDEX_SECTION_BASE_RVA + offset),
		lambda string: string.encode("utf-8") + b"\x00"
	)

	pe = PEFileWrapper(data)
	pe.add_section(Name=SECTION_NAME, Data=new_data, Characteristics=0xF0000040)

	return FileBuffer(pe.write())
