import os
import pytest
from strindex.filetypes import GenericModule
from strindex.utils import Strindex, StrindexSettings, FileBytearray


# FILES NEEDED FOR TESTING (in ./tests/data/ folder):
# strindex_example.txt
# Katana ZERO.exe


def get_file_path(filename: str) -> str:
	return os.path.join(os.path.dirname(__file__), "data", filename)

def get_text_md5(text: str) -> str:
	return FileBytearray(text.encode('utf-8')).md5



@pytest.fixture
def strindex_example() -> Strindex:
	return Strindex.read(get_file_path("strindex_example.txt"))

@pytest.fixture
def kz_data() -> FileBytearray:
	return FileBytearray.read(get_file_path("Katana ZERO.exe"))

def get_kz_strindex(kz_data: FileBytearray, settings: StrindexSettings) -> Strindex:
	strindex = GenericModule(kz_data, settings.force_mode).create(kz_data, settings)
	strindex.settings = settings
	return strindex

@pytest.fixture
def full_kz_strindex(kz_data: FileBytearray) -> Strindex:
	return get_kz_strindex(kz_data, StrindexSettings(
		min_length=1
	))

@pytest.fixture
def part_kz_strindex(kz_data: FileBytearray) -> Strindex:
	return get_kz_strindex(kz_data, StrindexSettings(
		min_length=3,
		prefix_bytes=["24c7442404", "ec04c70424"],
		ranges=["018bc5ec:01a09fb1"]
	))



def test_strindex_rw(strindex_example: Strindex):
	assert get_text_md5(strindex_example.write(None)) == get_text_md5(get_file_path("strindex_example.txt"))

def test_strindex_settings_rw(strindex_example: Strindex):
	strindex_example.settings.raw_settings = None
	strindex_example.settings.patch_replace = {}
	strindex_example.settings.whitelist = ""

	strindex_example.strings = []
	strindex_example.pointers = []
	strindex_example.type_order = []

	assert get_text_md5(strindex_example.write(None)) == "4e6850a62b988dbb48c4d018351211e8"

def test_create(full_kz_strindex: Strindex, part_kz_strindex: Strindex):
	full_kz_strindex.settings = StrindexSettings(raw_settings = "")
	part_kz_strindex.settings = StrindexSettings(raw_settings = "")

	assert get_text_md5(full_kz_strindex.write(None)) == "a4dee6d4c6f64931fdbb7e7bdb2c1b66"
	assert get_text_md5(part_kz_strindex.write(None)) == "7ba82e99bf64110fec068e46faf0d055"

def test_patch(kz_data: FileBytearray, full_kz_strindex: Strindex, part_kz_strindex: Strindex):
	assert GenericModule(kz_data).patch(kz_data, full_kz_strindex).md5 == "00c0788711cb31cee19b7c1f86fe0009"
	assert GenericModule(kz_data).patch(kz_data, part_kz_strindex).md5 == "09fa2b67b21596db0da6667fd0c653ef"
