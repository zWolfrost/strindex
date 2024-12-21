from ..utils import Strindex, StrindexSettings, FileBytearray

# https://github.com/panzi/cook-serve-hoomans/blob/master/fileformat.md


def get_last_chunk_pointer(data: FileBytearray) -> int:
	data.cursor = 12
	while data.cursor < len(data):
		size = data.get_int()
		if size != 0:
			prev_offset = data.cursor - 4
		data.cursor += size + 4
	return prev_offset


def validate(data: FileBytearray) -> bool:
	""" Checks if the file is an IFF file. """
	return data[0:4] == b"FORM"

def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	data.byte_length = 4
	data.byte_order = 'little'

	return data.create_pointers_macro(settings,
		lambda offset: data.from_int(offset - data.byte_length)
	)

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

	data.byte_length = 4
	data.byte_order = 'little'

	new_data = data.patch_pointers_macro(strindex,
		lambda offset: data.from_int(offset - data.byte_length),
		lambda offset: data.from_int(len(data) + offset),
		lambda string: data.from_int(len(string)) + bytearray(string, 'utf-8') + b'\x00'
	)

	data.cursor = 4
	data.add_int(len(new_data))
	data.cursor = get_last_chunk_pointer(data)
	data.add_int(len(new_data))

	data += new_data

	return data
