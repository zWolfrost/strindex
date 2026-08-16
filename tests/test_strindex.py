import os
import pytest
from tempfile import NamedTemporaryFile as temp_open
from strindex.strindex import create, delta, patch, update, filter
from strindex.filetypes import GenericModule
from strindex.utils import Strindex, StrindexSettings, FileBytearray


# FILES NEEDED FOR TESTING (in ./tests/data/ folder):
# strindex_example.txt
# Katana ZERO.exe
# kz_exe.gz


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
	assert get_text_md5(strindex_example.write(None)) == FileBytearray.read(get_file_path("strindex_example.txt")).md5

def test_strindex_settings_rw(strindex_example: Strindex):
	strindex_example.settings._raw = None

	strindex_example.strings = []
	strindex_example.pointers = []
	strindex_example.type_order = []

	assert get_text_md5(strindex_example.write(None)) == "30220881f3ad9a2fbad5e7c5ee526c03"

def test_create():
	with temp_open() as temp_strindex_created:
		create(get_file_path("Katana ZERO.exe"), temp_strindex_created.name, True, StrindexSettings(_raw = ""))
		FileBytearray.read(temp_strindex_created.name).write("a.txt")
		assert FileBytearray.read(temp_strindex_created.name).md5 == "b5a10f300c3becd2021a83ef918de8c7"

	with temp_open() as temp_strindex_created:
		create(get_file_path("Katana ZERO.exe"), temp_strindex_created.name, False, StrindexSettings(_raw = ""))
		assert FileBytearray.read(temp_strindex_created.name).md5 == "7ba82e99bf64110fec068e46faf0d055"

	with temp_open() as temp_strindex_created:
		create(get_file_path("Katana ZERO.exe"), temp_strindex_created.name, False, StrindexSettings(_raw = ""))
		assert FileBytearray.read(temp_strindex_created.name).md5 == "a4dee6d4c6f64931fdbb7e7bdb2c1b66"

def test_patch(full_kz_strindex: Strindex, part_kz_strindex: Strindex):
	with temp_open() as temp_file_patched:
		patch(get_file_path("Katana ZERO.exe"), get_file_path("kz_exe.gz"), temp_file_patched.name)
		assert FileBytearray.read(temp_file_patched.name).md5 == "d21cb88a3d18753b9cc4e20feadaa56b"

	with temp_open() as temp_strindex_full, temp_open() as temp_file_patched:
		full_kz_strindex.write(temp_strindex_full.name)
		patch(get_file_path("Katana ZERO.exe"), temp_strindex_full.name, temp_file_patched.name)
		assert FileBytearray.read(temp_file_patched.name).md5 == "00c0788711cb31cee19b7c1f86fe0009"

	with temp_open() as temp_strindex_part, temp_open() as temp_file_patched:
		part_kz_strindex.write(temp_strindex_part.name)
		patch(get_file_path("Katana ZERO.exe"), temp_strindex_part.name, temp_file_patched.name)
		assert FileBytearray.read(temp_file_patched.name).md5 == "09fa2b67b21596db0da6667fd0c653ef"

def test_update(part_kz_strindex: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_strindex_updated:
		part_kz_strindex.pointers[0] = []
		part_kz_strindex.write(temp_strindex.name)

		update(get_file_path("Katana ZERO.exe"), temp_strindex.name, temp_strindex_updated.name)

		part_kz_strindex_updated = Strindex.read(temp_strindex_updated.name)
		part_kz_strindex.pointers[0] = part_kz_strindex_updated.pointers[0].copy()

		assert part_kz_strindex.write(None) == part_kz_strindex_updated.write(None)

def test_filter(full_kz_strindex: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_strindex_filtered:
		full_kz_strindex.settings = StrindexSettings(min_length=3, whitelist=["latin"])
		full_kz_strindex.write(temp_strindex.name)

		filter(temp_strindex.name, temp_strindex_filtered.name)

		assert len(Strindex.read(temp_strindex_filtered.name).strings) == 24171

def test_delta(full_kz_strindex: Strindex, part_kz_strindex: Strindex):
	with temp_open() as temp_strindex1, temp_open() as temp_strindex2, temp_open() as temp_strindex_delta:
		full_kz_strindex.write(temp_strindex1.name)
		part_kz_strindex.write(temp_strindex2.name)

		delta(temp_strindex1.name, temp_strindex2.name, temp_strindex_delta.name)

		assert len(Strindex.read(temp_strindex_delta.name).strings) == 20797
