from strindex.utils import FileBytearray, Print, Strindex, StrindexSettings


def is_utf16_from_length(length: int) -> bool:
	return length > int("8fffffff", 16)


def get_text_start_offset(data: FileBytearray) -> int:
	data.cursor = 17
	return data.get_int()


def get_structures_dict(data: FileBytearray) -> dict[int, tuple[int, int, str]]:
	data.cursor = get_text_start_offset(data)
	structures = {}

	while data.cursor < len(data)-4:
		offset = data.cursor
		id = data.get_int()
		length = data.get_int()

		if is_utf16_from_length(length): # utf-16
			string = data.get((int("ffffffff", 16) - length)*2).decode("utf-16-le")
			data.cursor += 2
		else: # utf-8
			string = data.get(length - 1).decode("utf-8")
			data.cursor += 1

		structures[offset] = (id, length, string)

	return structures


def init(data: FileBytearray) -> FileBytearray:
	data.byte_length = 4
	data.byte_order = 'little'
	return data


def match(data: FileBytearray) -> bool:
	return data[0:4] == b"\x0e\x14\x74\x75" and b"ST_Localization" in data


def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	strindex = Strindex()

	data.cursor = get_text_start_offset(data)

	for offset, (_, _, string) in get_structures_dict(data).items():
		strindex.pointers.append([offset])
		strindex.strings.append(string)
		strindex.type_order.append("overwrite")

	return strindex


def patch(data: FileBytearray, strindex: Strindex) -> FileBytearray:
	structures = get_structures_dict(data)
	lst_offset, lst_string = zip(*[(offset, string) for offset, (_, _, string) in structures.items()])

	def update_structures_string(offset, string):
		structures[offset] = (structures[offset][0], structures[offset][1], string)

	start_i = 0
	for switches, original, replace in zip(strindex.get_switches, strindex.get_original, strindex.get_replace):
		if switches[0]:
			try:
				search_i = lst_string.index(original, start_i)
			except ValueError:
				Print.warning(f"String not found: \"{original}\"")
			else:
				start_i = search_i + 1
				update_structures_string(lst_offset[search_i], replace)

	for pointers, overwrite in zip(strindex.get_offsets, strindex.get_overwrite):
		if pointers[0] not in structures:
			Print.warning(f"No string found at offset {pointers[0]:08x}")
			continue
		update_structures_string(pointers[0], overwrite)

	new_data = bytearray()

	for id, length, string in structures.values():
		new_data += data.from_int(id)

		if is_utf16_from_length(length):
			string_encoded = string.encode("utf-16-le")
			new_data += data.from_int(int("ffffffff", 16) - len(string_encoded) // 2) + string_encoded + b'\x00\x00'
		else:
			string_encoded = string.encode("utf-8")
			new_data += data.from_int(len(string_encoded) + 1) + string_encoded + b'\x00'

	new_data += b"\x01\x00\x00\x00"

	data = FileBytearray(data[:get_text_start_offset(data)] + new_data)

	return data
