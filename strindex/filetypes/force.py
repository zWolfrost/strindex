from strindex.utils import Strindex, StrindexSettings, FileBytearray, Print


def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	strindex = Strindex()

	for string, start_offset, end_offset in data.strings_find(min_length=settings.min_length):
		if (
			settings.matches_prefix(data, start_offset) and
			settings.matches_suffix(data, end_offset) and
			settings.is_in_any_range(start_offset)
		):
			strindex.strings.append(string)
			strindex.pointers.append([start_offset])
			strindex.type_order.append("overwrite")

	Print.print(f"Found {len(strindex.strings)} strings.")

	return strindex


def patch(data: FileBytearray, strindex: Strindex) -> FileBytearray:
	strindex_original = strindex.get_original
	strindex_replace = strindex.get_replace

	for index, offset in enumerate(data.strings_search_ordered(strindex_original)):
		if offset is None:
			Print.print(f'String not found: "{strindex_original[index]}"')
			continue

		data.cursor = offset
		data.replace_string(strindex_replace[index])

	for overwrite, offset in zip(strindex.get_overwrite, strindex.get_offsets):
		data.cursor = offset[0]
		data.replace_string(overwrite)

	return data
