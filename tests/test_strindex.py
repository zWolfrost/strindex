# FILES NEEDED FOR TESTING (in ./tests/data/ folder):
# Katana ZERO.exe (from Katana ZERO)
# kz_exe.gz
# data.win (from Undertale)
# Game.locres (from MOLE)

from pathlib import Path
from tempfile import NamedTemporaryFile as temp_open

import pytest

import strindex.core
from strindex.utils import FileBytearray, Strindex, StrindexSettings


def get_file_path(filename: str) -> str:
	return (Path(__file__).parent / "data" / filename).resolve().as_posix()

def get_file_md5(filepath: str) -> str:
	return FileBytearray.read(filepath).md5



@pytest.fixture
def strindex_example() -> Strindex:
	return Strindex.read(get_file_path("strindex_example.txt"))

def get_kz_pe_strindex(compatible: bool, settings: StrindexSettings) -> Strindex:
	with temp_open() as temp_strindex:
		strindex.core.create(get_file_path("Katana ZERO.exe"), temp_strindex.name, settings, compatible)
		return Strindex.read(temp_strindex.name)

@pytest.fixture
def kz_pe_strindex_full() -> Strindex:
	return get_kz_pe_strindex(False, StrindexSettings(min_length=1))

@pytest.fixture
def kz_pe_strindex_part() -> Strindex:
	return get_kz_pe_strindex(False, StrindexSettings(
		min_length=3, prefix_bytes=["24c7442404", "ec04c70424"], ranges=["00441078:0060e501"]
	))

def get_ut_iff_strindex(compatible: bool, settings: StrindexSettings) -> Strindex:
	with temp_open() as temp_strindex:
		strindex.core.create(get_file_path("data.win"), temp_strindex.name, settings, compatible)
		return Strindex.read(temp_strindex.name)

@pytest.fixture
def ut_iff_strindex_part() -> Strindex:
	return get_ut_iff_strindex(False, StrindexSettings(
		_raw="", prefix_bytes=["d000"], ranges=["00c96ce0:00c98410"]
	))

def get_mole_locres_strindex(compatible: bool, settings: StrindexSettings) -> Strindex:
	with temp_open() as temp_strindex:
		strindex.core.create(get_file_path("Game.locres"), temp_strindex.name, settings, compatible)
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
	with temp_open() as temp_strindex:
		strindex.core.create(get_file_path("Katana ZERO.exe"), temp_strindex.name, StrindexSettings(_raw=""), True)
		assert get_file_md5(temp_strindex.name) == "11d5bb62d8bf255b62512c3c9cb798e2"

		strindex.core.create(get_file_path("Katana ZERO.exe"), temp_strindex.name, StrindexSettings(_raw=""), False)
		assert get_file_md5(temp_strindex.name) == "bead9b4aae83058f9a446dc5c951230c"

		strindex.core.create(get_file_path("Katana ZERO.exe"), temp_strindex.name, (StrindexSettings(
			_raw="", min_length=3, prefix_bytes=["24c7442404", "ec04c70424"], ranges=["00441078:0060e501"]
		)), False)
		assert get_file_md5(temp_strindex.name) == "a99c090af182c953e65055a34b78d98d"

def test_create_iff():
	with temp_open() as temp_strindex:
		strindex.core.create(get_file_path("data.win"), temp_strindex.name, StrindexSettings(
			_raw="", prefix_bytes=["d000"], ranges=["00c96ce0:00c98410"]
		), False)
		assert get_file_md5(temp_strindex.name) == "bf3604eba22262539fbeddda30dce28b"

def test_create_locres():
	with temp_open() as temp_strindex:
		strindex.core.create(get_file_path("Game.locres"), temp_strindex.name, StrindexSettings(_raw=""), False)
		assert get_file_md5(temp_strindex.name) == "36fd0d52286aa03aa904281e78f91743"

def test_patch_pe(kz_pe_strindex_full: Strindex, kz_pe_strindex_part: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_file:
		strindex.core.patch(get_file_path("Katana ZERO.exe"), get_file_path("kz_exe.gz"), temp_file.name)
		assert get_file_md5(temp_file.name) == "d21cb88a3d18753b9cc4e20feadaa56b"

		kz_pe_strindex_full.write(temp_strindex.name)
		strindex.core.patch(get_file_path("Katana ZERO.exe"), temp_strindex.name, temp_file.name)
		assert get_file_md5(temp_file.name) == "026491ad7495fdf1e996802885dd410e"

		kz_pe_strindex_part.write(temp_strindex.name)
		strindex.core.patch(get_file_path("Katana ZERO.exe"), temp_strindex.name, temp_file.name)
		assert get_file_md5(temp_file.name) == "09fa2b67b21596db0da6667fd0c653ef"

def test_patch_iff(ut_iff_strindex_part: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_file:
		ut_iff_strindex_part.write(temp_strindex.name)
		strindex.core.patch(get_file_path("data.win"), temp_strindex.name, temp_file.name)
		assert get_file_md5(temp_file.name) == "e41cd288d23b8154d2c04839643921ca"

def test_patch_locres(mole_locres_strindex_full: Strindex, mole_locres_strindex_full_comp: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_file:
		for mole_locres_strindex in (mole_locres_strindex_full, mole_locres_strindex_full_comp):
			mole_locres_strindex.write(temp_strindex.name)
			strindex.core.patch(get_file_path("Game.locres"), temp_strindex.name, temp_file.name)
			assert get_file_md5(temp_file.name) == get_file_md5(get_file_path("Game.locres"))

		strindex.core.patch(get_file_path("Game.locres"), get_file_path("locres_strindex.txt"), temp_file.name)
		assert get_file_md5(temp_file.name) == "2bb9094b3e5b2e9acb10eb1c6bdb83e6"

def test_patch_force():
	with temp_open() as temp_strindex, temp_open() as temp_file:
		temp_strindex_force = Strindex.read(get_file_path("locres_strindex.txt"))
		temp_strindex_force.settings._raw = None
		temp_strindex_force.settings.force_mode = True
		temp_strindex_force.pointers[0][0] += 8
		temp_strindex_force.pointers[2][0] += 8
		temp_strindex_force.write(temp_strindex.name)
		strindex.core.patch(get_file_path("Game.locres"), temp_strindex.name, temp_file.name)
		assert get_file_md5(temp_file.name) == "a885ec6f2cb6e9bb4cc1d56be1d1949f"

def test_update(kz_pe_strindex_part: Strindex):
	with temp_open() as temp_strindex_in, temp_open() as temp_strindex_out:
		kz_pe_strindex_part.pointers[0] = []
		kz_pe_strindex_part.write(temp_strindex_in.name)

		strindex.core.update(get_file_path("Katana ZERO.exe"), temp_strindex_in.name, temp_strindex_out.name)

		part_kz_strindex_updated = Strindex.read(temp_strindex_out.name)
		kz_pe_strindex_part.pointers[0] = part_kz_strindex_updated.pointers[0].copy()

		assert kz_pe_strindex_part.write(None) == part_kz_strindex_updated.write(None)

def test_filter(kz_pe_strindex_full: Strindex):
	with temp_open() as temp_strindex_in, temp_open() as temp_strindex_out:
		kz_pe_strindex_full.settings = StrindexSettings(min_length=3, whitelist=["latin"])
		kz_pe_strindex_full.write(temp_strindex_in.name)

		strindex.core.filter(temp_strindex_in.name, temp_strindex_out.name)

		assert len(Strindex.read(temp_strindex_out.name).strings) == 24180

def test_delta(kz_pe_strindex_full: Strindex, kz_pe_strindex_part: Strindex):
	with temp_open() as temp_strindex_in1, temp_open() as temp_strindex_in2, temp_open() as temp_strindex_out:
		kz_pe_strindex_full.write(temp_strindex_in1.name)
		kz_pe_strindex_part.write(temp_strindex_in2.name)

		strindex.core.delta(temp_strindex_in1.name, temp_strindex_in2.name, temp_strindex_out.name)

		assert len(Strindex.read(temp_strindex_out.name).strings) == 20840
