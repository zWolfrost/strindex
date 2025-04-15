from strindex.utils import Strindex, StrindexSettings, FileBytearray


def create(data: FileBytearray, settings: StrindexSettings) -> Strindex:
	strindex = Strindex()

	for string, offset in data.yield_strings():
		end_offset = offset + len(bytes(string, "utf-8"))

		if (
			len(string) >= settings.min_length and
			any(bytes(data[offset - len(prefix):offset]) == prefix for prefix in settings.prefix_bytes) and
			any(bytes(data[end_offset:end_offset + len(suffix)]) == suffix for suffix in settings.suffix_bytes)
		):
			strindex.strings.append(string)
			strindex.pointers.append([offset])
			strindex.type_order.append("overwrite")

	print(f"Found {len(strindex.strings)} strings.")

	return strindex

def patch(data: FileBytearray, strindex: Strindex) -> FileBytearray:
	strindex_original = strindex.get_original
	strindex_replace = strindex.get_replace

	for index, offset in enumerate(data.indices_ordered(strindex_original)):
		if offset is None:
			print(f'String not found: "{strindex_original[index]}"')
			continue

		data.cursor = offset
		data.replace_string(strindex_replace[index])

	for overwrite, offset in zip(strindex.get_overwrite, strindex.get_offsets):
		data.cursor = offset[0]
		data.replace_string(overwrite)

	return data
