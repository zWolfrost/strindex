import os
from tempfile import NamedTemporaryFile as temp_open

import pytest

from strindex.strindex import create, delta, filter, patch, update
from strindex.utils import FileBytearray, Strindex, StrindexSettings

# FILES NEEDED FOR TESTING (in ./tests/data/ folder):
# Katana ZERO.exe (from Katana ZERO)
# kz_exe.gz
# data.win (from Undertale)
# Game.locres (from MOLE)


def get_file_path(filename: str) -> str:
	return os.path.join(os.path.dirname(__file__), "data", filename)

def get_file_md5(filepath: str) -> str:
	return FileBytearray.read(filepath).md5


@pytest.fixture
def strindex_example() -> Strindex:
	return Strindex.read(get_file_path("strindex_example.txt"))

def get_kz_pe_strindex(compatible: bool, settings: StrindexSettings) -> Strindex:
	with temp_open() as temp_strindex:
		create(get_file_path("Katana ZERO.exe"), temp_strindex.name, settings, compatible)
		return Strindex.read(temp_strindex.name)

@pytest.fixture
def kz_pe_strindex_full() -> Strindex:
	return get_kz_pe_strindex(False, StrindexSettings(min_length=1))

@pytest.fixture
def kz_pe_strindex_part() -> Strindex:
	return get_kz_pe_strindex(False, StrindexSettings(
		min_length=3, prefix_bytes=["24c7442404", "ec04c70424"], ranges=["018bc5ec:01a09fb1"]
	))

def get_ut_iff_strindex(compatible: bool, settings: StrindexSettings) -> Strindex:
	with temp_open() as temp_strindex:
		create(get_file_path("data.win"), temp_strindex.name, settings, compatible)
		return Strindex.read(temp_strindex.name)

@pytest.fixture
def ut_iff_strindex_part() -> Strindex:
	return get_ut_iff_strindex(False, StrindexSettings(
		_raw="", prefix_bytes=["d000"], ranges=["00d00172:00d1002e"]
	))

def get_mole_locres_strindex(compatible: bool, settings: StrindexSettings) -> Strindex:
	with temp_open() as temp_strindex:
		create(get_file_path("Game.locres"), temp_strindex.name, settings, compatible)
		return Strindex.read(temp_strindex.name)

@pytest.fixture
def mole_locres_strindex_full() -> Strindex:
	return get_mole_locres_strindex(False, StrindexSettings(_raw=""))

@pytest.fixture
def mole_locres_strindex_full_comp() -> Strindex:
	return get_mole_locres_strindex(True, StrindexSettings(_raw=""))


def test_strindex_rw(strindex_example: Strindex):
	with temp_open() as temp_strindex:
		strindex_example.write(temp_strindex.name)
		assert get_file_md5(temp_strindex.name) == get_file_md5(get_file_path("strindex_example.txt"))

def test_strindex_settings_rw(strindex_example: Strindex):
	strindex_example.settings._raw = None

	strindex_example.strings = []
	strindex_example.pointers = []
	strindex_example.type_order = []

	with temp_open() as temp_strindex:
		strindex_example.write(temp_strindex.name)
		assert get_file_md5(temp_strindex.name) == "33fdd4dee70dfc8ae5be32d20e56191b"

def test_create_pe():
	with temp_open() as temp_strindex_created:
		create(get_file_path("Katana ZERO.exe"), temp_strindex_created.name, StrindexSettings(_raw=""), compatible=True)
		assert get_file_md5(temp_strindex_created.name) == "11d5bb62d8bf255b62512c3c9cb798e2"

	with temp_open() as temp_strindex_created:
		create(get_file_path("Katana ZERO.exe"), temp_strindex_created.name, StrindexSettings(_raw=""), compatible=False)
		assert get_file_md5(temp_strindex_created.name) == "bead9b4aae83058f9a446dc5c951230c"

	with temp_open() as temp_strindex_created:
		create(get_file_path("Katana ZERO.exe"), temp_strindex_created.name, (StrindexSettings(
			_raw="", min_length=3, prefix_bytes=["24c7442404", "ec04c70424"], ranges=["018bc5ec:01a09fb1"]
		)), compatible=False)
		assert get_file_md5(temp_strindex_created.name) == "a99c090af182c953e65055a34b78d98d"

def test_create_iff():
	with temp_open() as temp_strindex_created:
		create(get_file_path("data.win"), temp_strindex_created.name, StrindexSettings(
			_raw="", prefix_bytes=["d000"], ranges=["00d00172:00d1002e"]
		), compatible=False)
		assert get_file_md5(temp_strindex_created.name) == "bf3604eba22262539fbeddda30dce28b"

def test_create_locres():
	with temp_open() as temp_strindex_created:
		create(get_file_path("Game.locres"), temp_strindex_created.name, StrindexSettings(_raw=""), compatible=False)
		assert get_file_md5(temp_strindex_created.name) == "36fd0d52286aa03aa904281e78f91743"

def test_patch_pe(kz_pe_strindex_full: Strindex, kz_pe_strindex_part: Strindex):
	with temp_open() as temp_file_patched:
		patch(get_file_path("Katana ZERO.exe"), get_file_path("kz_exe.gz"), temp_file_patched.name)
		assert get_file_md5(temp_file_patched.name) == "d21cb88a3d18753b9cc4e20feadaa56b"

	with temp_open() as temp_strindex_full, temp_open() as temp_file_patched:
		kz_pe_strindex_full.write(temp_strindex_full.name)
		patch(get_file_path("Katana ZERO.exe"), temp_strindex_full.name, temp_file_patched.name)
		assert get_file_md5(temp_file_patched.name) == "026491ad7495fdf1e996802885dd410e"

	with temp_open() as temp_strindex_part, temp_open() as temp_file_patched:
		kz_pe_strindex_part.write(temp_strindex_part.name)
		patch(get_file_path("Katana ZERO.exe"), temp_strindex_part.name, temp_file_patched.name)
		assert get_file_md5(temp_file_patched.name) == "09fa2b67b21596db0da6667fd0c653ef"

def test_patch_iff(ut_iff_strindex_part: Strindex):
	with temp_open() as temp_strindex_part, temp_open() as temp_strindex_created:
		ut_iff_strindex_part.write(temp_strindex_part.name)
		patch(get_file_path("data.win"), temp_strindex_part.name, temp_strindex_created.name)
		assert get_file_md5(temp_strindex_created.name) == "e41cd288d23b8154d2c04839643921ca"

def test_patch_locres(mole_locres_strindex_full: Strindex, mole_locres_strindex_full_comp: Strindex):
	with temp_open() as temp_strindex_full, temp_open() as temp_file_patched:
		for mole_locres_strindex in (mole_locres_strindex_full, mole_locres_strindex_full_comp):
			mole_locres_strindex.write(temp_strindex_full.name)
			patch(get_file_path("Game.locres"), temp_strindex_full.name, temp_file_patched.name)
			assert get_file_md5(temp_file_patched.name) == get_file_md5(get_file_path("Game.locres"))

	with temp_open() as temp_file_patched:
		patch(get_file_path("Game.locres"), get_file_path("Game_strindex.txt"), temp_file_patched.name)
		assert get_file_md5(temp_file_patched.name) == "2bb9094b3e5b2e9acb10eb1c6bdb83e6"

def test_update(kz_pe_strindex_part: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_strindex_updated:
		kz_pe_strindex_part.pointers[0] = []
		kz_pe_strindex_part.write(temp_strindex.name)

		update(get_file_path("Katana ZERO.exe"), temp_strindex.name, temp_strindex_updated.name)

		part_kz_strindex_updated = Strindex.read(temp_strindex_updated.name)
		kz_pe_strindex_part.pointers[0] = part_kz_strindex_updated.pointers[0].copy()

		assert kz_pe_strindex_part.write(None) == part_kz_strindex_updated.write(None)

def test_filter(kz_pe_strindex_full: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_strindex_filtered:
		kz_pe_strindex_full.settings = StrindexSettings(min_length=3, whitelist=["latin"])
		kz_pe_strindex_full.write(temp_strindex.name)

		filter(temp_strindex.name, temp_strindex_filtered.name)

		assert len(Strindex.read(temp_strindex_filtered.name).strings) == 24180

def test_delta(kz_pe_strindex_full: Strindex, kz_pe_strindex_part: Strindex):
	with temp_open() as temp_strindex1, temp_open() as temp_strindex2, temp_open() as temp_strindex_delta:
		kz_pe_strindex_full.write(temp_strindex1.name)
		kz_pe_strindex_part.write(temp_strindex2.name)

		delta(temp_strindex1.name, temp_strindex2.name, temp_strindex_delta.name)

		assert len(Strindex.read(temp_strindex_delta.name).strings) == 20840
