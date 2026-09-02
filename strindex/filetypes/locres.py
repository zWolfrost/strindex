from strindex.utils import FileBuffer, ModuleSettings, Print, Strindex

SETTINGS = ModuleSettings(
	default_byte_length=4,
	default_byte_order="little"
)


def is_utf16_from_length(length: int) -> bool:
	return length > int("8fffffff", 16)


def get_text_start_offset(data: FileBuffer) -> int:
	data.cursor = 17
	return data.get_int()


def get_string(data: FileBuffer, length: int) -> str:
	if is_utf16_from_length(length): # utf-16
		string = data.get((int("ffffffff", 16) - length)*2).decode("utf-16-le")
		data.cursor += 2
	else: # utf-8
		string = data.get(length - 1).decode("utf-8")
		data.cursor += 1

	return string


def detect_meta_length(data: FileBuffer, offset: int) -> tuple[bytes, int]: # HACK
	for i in range(6):
		data.cursor = offset
		if i > 0:
			data.get(i*4)
		length = data.get_int()
		try:
			if get_string(data, length) == "":
				raise ValueError
		except (UnicodeDecodeError, ValueError):
			pass
		else:
			data.cursor = offset
			return i*4
	raise ValueError("Failed to detect metadata length")


def get_structures_dict(data: FileBuffer) -> dict[int, tuple[int, int, str]]:
	data.cursor = get_text_start_offset(data)
	structures = {}

	meta_length = 0

	while data.cursor < len(data)-4:
		offset = data.cursor

		if len(structures) <= 2:
			meta_length = detect_meta_length(data, offset)

		meta = data.get(meta_length)
		length = data.get_int()
		string = get_string(data, length)

		structures[offset] = (meta, length, string)

	return structures


def match(data: FileBuffer) -> bool:
	return data[0:4] == b"\x0e\x14\x74\x75"


def create(data: FileBuffer, strindex: Strindex) -> Strindex:
	data.cursor = get_text_start_offset(data)

	for offset, (_, _, string) in get_structures_dict(data).items():
		strindex.pointers.append([offset])
		strindex.strings.append(string)

	return strindex


def patch(data: FileBuffer, strindex: Strindex) -> FileBuffer:
	structures = get_structures_dict(data)

	strindex.normalize_to_overwrite([[o] for o in structures], [p[2] for p in structures.values()])

	for pointers, string in zip(strindex.pointers, strindex.strings, strict=True):
		offset = pointers[0]
		if offset not in structures:
			Print.warning(f"No string found at offset {offset:08x}")
			continue
		structures[offset] = (structures[offset][0], structures[offset][1], string)

	data[get_text_start_offset(data):] = b""

	for meta, length, string in structures.values():
		data += meta

		if is_utf16_from_length(length):
			string_encoded = string.encode("utf-16-le")
			data += data.from_int(int("ffffffff", 16) - len(string_encoded) // 2) + string_encoded + b"\x00\x00"
		else:
			string_encoded = string.encode("utf-8")
			data += data.from_int(len(string_encoded) + 1) + string_encoded + b"\x00"

	data += b"\x01\x00\x00\x00"

	return data
