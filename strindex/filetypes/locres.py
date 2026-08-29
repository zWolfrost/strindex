from strindex.utils import FileBytearray, ModuleSettings, Print, Strindex, StrindexSettings

SETTINGS = ModuleSettings(
	default_byte_length=4,
	default_byte_order="little"
)


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


def match(data: FileBytearray) -> bool:
	return data[0:4] == b"\x0e\x14\x74\x75"


def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	strindex = Strindex()

	data.cursor = get_text_start_offset(data)

	for offset, (_, _, string) in get_structures_dict(data).items():
		strindex.pointers.append([offset])
		strindex.strings.append(string)

	return strindex


def patch(data: FileBytearray, strindex: Strindex) -> FileBytearray:
	structures = get_structures_dict(data)

	strindex.normalize_to_overwrite([[o] for o in structures], [p[2] for p in structures.values()])

	for pointers, string in zip(strindex.pointers, strindex.strings, strict=True):
		offset = pointers[0]
		if offset not in structures:
			Print.warning(f"No string found at offset {offset:08x}")
			continue
		structures[offset] = (structures[offset][0], structures[offset][1], string)

	data[get_text_start_offset(data):] = b""

	for id, length, string in structures.values():
		data += data.from_int(id)

		if is_utf16_from_length(length):
			string_encoded = string.encode("utf-16-le")
			data += data.from_int(int("ffffffff", 16) - len(string_encoded) // 2) + string_encoded + b"\x00\x00"
		else:
			string_encoded = string.encode("utf-8")
			data += data.from_int(len(string_encoded) + 1) + string_encoded + b"\x00"

	data += b"\x01\x00\x00\x00"

	return data
