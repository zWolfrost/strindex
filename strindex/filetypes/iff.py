from ..utils import Strindex, StrindexSettings, FileBytearray


def get_last_chunk_pointer(data: FileBytearray) -> int:
	offset = 12
	while offset < len(data):
		size = int.from_bytes(data[offset:offset+4], 'little')
		if size != 0:
			prev_offset = offset
		offset += size + 8
	return prev_offset


def is_valid(data: FileBytearray) -> bool:
	""" Checks if the file is an IFF file. """
	return data[0:4] == b"FORM"

def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	BYTE_LENGTH = 4

	temp_strindex = {
		"original": [],
		"offsets": [],
		"offset_bytes": [],
		"pointers": []
	}

	for string, offset in data.yield_strings():
		if len(string) >= settings.min_length:
			offset -= BYTE_LENGTH
			temp_strindex["original"].append(string)
			temp_strindex["offsets"].append(offset)
			temp_strindex["offset_bytes"].append(offset.to_bytes(BYTE_LENGTH, 'little'))

	if not temp_strindex["original"]:
		raise ValueError("No strings found in the file.")
	print(f"(1/2) Created search dictionary with {len(temp_strindex['original'])} strings.")

	temp_strindex["pointers"] = data.get_indices_fixed(temp_strindex["offset_bytes"], settings.prefix_bytes, settings.suffix_bytes)

	STRINDEX = Strindex()
	for original, offset, _, pointers in zip(*temp_strindex.values()):
		if pointers:
			STRINDEX.overwrite.append(original)
			STRINDEX.offsets.append(offset)
			STRINDEX.pointers.append(pointers)

	print(f"(2/2) Found pointers for {len(STRINDEX.overwrite)} / {len(temp_strindex['original'])} strings.")

	return STRINDEX

def patch(data: FileBytearray, strindex: Strindex) -> FileBytearray:
	"""
		The patching is done by increasing both
		the "FORM" chunk size and the last chunk size to fit the new data.
		The data is thus contained in the last chunk of the file,
		to avoid having to change the pointers of the other chunks as well.
		The pointers are changed to reference the new data.
		This works fine with gamemaker "data.win" files,
		and might also work with IFF files in general, but I haven't tested it.
	"""

	BYTE_LENGTH = 4
	DATA_LEN = len(data)

	new_section_data = bytearray()

	def increase_bytes(pointer: int, increase: int):
		data[pointer:pointer+BYTE_LENGTH] = (int.from_bytes(data[pointer:pointer+BYTE_LENGTH], 'little') + increase).to_bytes(BYTE_LENGTH, 'little')
	def get_replaced_offset() -> bytes:
		return (DATA_LEN + len(new_section_data)).to_bytes(BYTE_LENGTH, 'little')
	def new_section_string(string: str) -> bytes:
		return len(string).to_bytes(BYTE_LENGTH, 'little') + bytearray(strindex.settings.patch_replace_string(string), 'utf-8') + b'\x00'

	temp_strindex = {
		"original_offset": [],
		"replaced_offset": [],
		"pointers": [],
		"pointers_switches": []
	}

	# Deal with compatible strings
	for strindex_index, offset in enumerate(data.get_indices_ordered(strindex.original, b"\x00", b"\x00")):
		if offset is None:
			print(f'String not found: "{strindex.original[strindex_index]}"')
			continue

		offset -= BYTE_LENGTH

		temp_strindex["original_offset"].append(offset.to_bytes(BYTE_LENGTH, 'little'))
		temp_strindex["replaced_offset"].append(get_replaced_offset())
		temp_strindex["pointers_switches"].append(strindex.pointers_switches[strindex_index])

		new_section_data += new_section_string(strindex.replace[strindex_index])

	temp_strindex["pointers"] = data.get_indices_fixed(temp_strindex["original_offset"], strindex.settings.prefix_bytes, strindex.settings.suffix_bytes)

	for original_offset, replaced_offset, pointers, pointers_switches in zip(*temp_strindex.values()):
		if pointers:
			for pointer, switch in zip(pointers, pointers_switches):
				if switch:
					data[pointer:pointer+BYTE_LENGTH] = replaced_offset
		else:
			print("No pointers found for rva: " + original_offset.hex())

	# Deal with overwrite strings
	for strindex_index in range(len(strindex.overwrite)):
		replaced_offset = get_replaced_offset()
		new_section_data += new_section_string(strindex.overwrite[strindex_index])

		for pointer in strindex.pointers[strindex_index]:
			if pointer:
				data[pointer:pointer+BYTE_LENGTH] = replaced_offset
			else:
				print("No pointers found for string: " + strindex.overwrite[strindex_index])
	print("(1/1) Created chunk data & relocated pointers.")

	# Increase the "FORM" chunk size and the last chunk size
	increase_bytes(4, len(new_section_data))
	increase_bytes(get_last_chunk_pointer(data), len(new_section_data))

	data += new_section_data

	return data
