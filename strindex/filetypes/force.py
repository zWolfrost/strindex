from strindex.utils import FileBuffer, ModuleSettings, Print, Strindex

SETTINGS = ModuleSettings()


def match(_: FileBuffer) -> bool:
	return False


def create(data: FileBuffer, strindex: Strindex) -> Strindex:
	for string, start_offset, _ in data.strings_find():
		strindex.pointers.append([start_offset])
		strindex.strings.append(string)

	Print.debug(f"Found {len(strindex.strings)} strings.")

	return strindex


def patch(data: FileBuffer, strindex: Strindex) -> FileBuffer:
	strindex_original = strindex.get_original
	strindex.normalize_to_overwrite([[p] for p in data.strings_search_ordered(strindex_original)], strindex_original)

	for overwrite, offset in zip(strindex.get_overwrite, strindex.get_offsets, strict=True):
		data.cursor = offset[0]
		data.replace_string(overwrite)

	return data
