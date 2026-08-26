def strings_find_fast(
		data: bytes | bytearray,
		sep: int,
		min_length: int,
		ranges: list[tuple[int, int]],
		whitelist: set[str]
	) -> list[tuple[str, int, int]]:
	""" Find UTF-8 strings separated by a byte separator. """
