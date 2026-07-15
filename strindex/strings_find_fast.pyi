def strings_find_fast(data: bytes | bytearray, sep: int, min_length: int) -> list[tuple[str, int, int]]:
	"""
	Find UTF-8 strings separated by a byte separator.

	Returns:
		List of (string, start_index, end_index)
	"""
	...