from ..utils import Strindex, StrindexSettings, FileBytearray


def get_last_chunk_pointer(data: FileBytearray) -> int:
	offset = 12
	while offset < len(data):
		size = data.int_at(offset)
		if size != 0:
			prev_offset = offset
		offset += size + 8
	return prev_offset

def initialize_data(data: FileBytearray):
	data.byte_length = 4
	data.byte_order = 'little'


def validate(data: FileBytearray) -> bool:
	""" Checks if the file is an IFF file. """
	return data[0:4] == b"FORM"

def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	initialize_data(data)

	return data.create_pointers_macro(settings, lambda offset: offset - data.byte_length)

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

	initialize_data(data)

	new_data = data.patch_pointers_macro(strindex,
		lambda offset: offset - data.byte_length,
		lambda offset: len(data) + offset,
		lambda string: data.int_to_bytes(len(string)) + bytearray(string, 'utf-8') + b'\x00'
	)

	data.delta_int_at(4, len(new_data))
	data.delta_int_at(get_last_chunk_pointer(data), len(new_data))

	data += new_data

	return data
