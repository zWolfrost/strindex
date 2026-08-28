from strindex.utils import FileBytearray, Strindex, StrindexSettings


def is_negative_utf16_length(length: int) -> bool:
	return length > int("8fffffff", 16)


def get_text_start_offset(data: FileBytearray) -> int:
	data.cursor = 17
	return data.get_int()


def init(data: FileBytearray) -> FileBytearray:
	data.byte_length = 4
	data.byte_order = 'little'
	return data


def match(data: FileBytearray) -> bool:
	return data[0:4] == b"\x0e\x14\x74\x75" and b"ST_Localization" in data


def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	strindex = Strindex()

	data.cursor = get_text_start_offset(data)

	while data.cursor < len(data)-4:
		pointer = data.cursor
		_ = data.get_int() # id
		length = data.get_int()

		if is_negative_utf16_length(length): # utf-16
			length = int("ffffffff", 16) - length
			string = data.get(length*2).decode("utf-16-le")
			data.cursor += 2
		else: # utf-8
			length -= 1
			string = data.get(length).decode("utf-8")
			data.cursor += 1

		strindex.pointers.append([pointer])
		strindex.strings.append(string)
		strindex.type_order.append("overwrite")

	return strindex


def patch(data: FileBytearray, strindex: Strindex) -> FileBytearray:
	id_lst = []
	is_utf16_lst = []

	for p in strindex.pointers:
		data.cursor = p[0]
		id_lst.append(data.get_int())
		is_utf16_lst.append(is_negative_utf16_length(data.get_int()))

	new_data = bytearray()

	for id, is_utf16, string in zip(id_lst, is_utf16_lst, strindex.get_overwrite):
		new_data += data.from_int(id)

		if is_utf16:
			string_encoded = string.encode("utf-16-le")
			new_data += data.from_int(int("ffffffff", 16) - len(string_encoded) // 2) + string_encoded + b'\x00\x00'
		else:
			string_encoded = string.encode("utf-8")
			new_data += data.from_int(len(string_encoded) + 1) + string_encoded + b'\x00'

	new_data += b"\x01\x00\x00\x00"

	data = FileBytearray(data[:get_text_start_offset(data)] + new_data)

	return data
