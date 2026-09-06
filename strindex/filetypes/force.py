from strindex.utils import FileBuffer, ModuleSettings, Print, Strindex

SETTINGS = ModuleSettings(
	supports_dynamic=True
)


def match(_: FileBuffer) -> bool:
	return False


def create(data: FileBuffer, strindex: Strindex) -> Strindex:
	for string, start_offset, _ in data.strings_find():
		strindex.pointers.append([start_offset])
		strindex.strings.append(string)

	Print.debug(f"Found {strindex.count} strings.")

	return strindex


def patch(data: FileBuffer, strindex: Strindex) -> FileBuffer:
	strindex_original, _ = strindex.get_type_pointers(Strindex.Type.DYNAMIC)
	strindex.normalize_to_fixed([[p] for p in data.strings_search_ordered(strindex_original)], strindex_original)

	for string, offset in zip(strindex.strings, strindex.pointers, strict=True):
		data.cursor = offset[0]
		data.replace_string(string)

	return data
