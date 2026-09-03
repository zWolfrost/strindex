import hashlib
from copy import deepcopy
from pathlib import Path
from tempfile import NamedTemporaryFile as temp_open

import pytest

import strindex.core
from strindex.utils import Strindex, StrindexSettings


def fixture(func):
	return pytest.fixture(scope="module")(func)

def get_file_path(filename: str) -> str:
	return (Path(__file__).parent / "data" / filename).resolve().as_posix()

def get_file_md5(file: str) -> str:
	with Path(file).open("rb") as f:
		file_hash = hashlib.md5()
		while chunk := f.read(1048576):
			file_hash.update(chunk)
	return file_hash.hexdigest()

def get_strindex_md5(strindex: Strindex) -> str:
	with temp_open() as temp_strindex:
		strindex.write(temp_strindex.name)
		return get_file_md5(temp_strindex.name)

def get_strindex(filename: str, settings: StrindexSettings) -> Strindex:
	with temp_open() as temp_strindex:
		strindex.core.create(get_file_path(filename), temp_strindex.name, settings)
		return Strindex.read(temp_strindex.name)


@fixture
def strindex_example() -> Strindex:
	return Strindex.read(get_file_path("strindex_example.txt"))

@fixture
def kz_pe_strindex_force() -> Strindex:
	return get_strindex("Katana ZERO.exe", StrindexSettings(_raw="", force_mode=True, min_length=3))

@fixture
def kz_pe_strindex_full() -> Strindex:
	return get_strindex("Katana ZERO.exe", StrindexSettings(_raw="", _compatible=False))

@fixture
def kz_pe_strindex_full_comp() -> Strindex:
	return get_strindex("Katana ZERO.exe", StrindexSettings(_raw="", _compatible=True))

@fixture
def kz_pe_strindex_part() -> Strindex:
	return get_strindex("Katana ZERO.exe", StrindexSettings(
		_raw="",
		_compatible=False,
		min_length=3,
		prefix_bytes=["24c7442404", "ec04c70424"],
		ranges=["00441078:0060e501"]
	))

@fixture
def ut_iff_strindex_part() -> Strindex:
	return get_strindex("data.win", StrindexSettings(
		_raw="",
		_compatible=False,
		prefix_bytes=["d000"],
		ranges=["00c96ce0:00c98410"]
	))

@fixture
def mole_locres_strindex_full() -> Strindex:
	return get_strindex("Game.locres", StrindexSettings(_raw="", _compatible=False))

@fixture
def mole_locres_strindex_full_comp() -> Strindex:
	return get_strindex("Game.locres", StrindexSettings(_raw="", _compatible=True))



def test_test_data():
	# FILES NEEDED FOR TESTING (in ./tests/data/ folder):

	for filepath, md5 in (
		("strindex_example.txt", "062713d0ca729317a04e5dc657b50895"), # from this repo
		("locres_strindex.txt",  "f81120bbff6bba873afeab462e95c9de"), # from this repo
		("Katana ZERO.exe",      "29ed1f9e450d43815c2d1a0cab168da3"), # from Katana ZERO
		("kz_exe.gz",            "509abb8f443b6e3327cde567ffe8b589"), # from es -> it translation patch
		("data.win",             "5903fc5cb042a728d4ad8ee9e949c6eb"), # from Undertale
		("Game.locres",          "419202a5ca1b343ec2011e1b610404e3"), # from MOLE
	):
		assert get_file_md5(get_file_path(filepath)) == md5

def test_strindex_rw(strindex_example: Strindex):
	assert get_strindex_md5(strindex_example) == get_file_md5(get_file_path("strindex_example.txt"))

def test_strindex_settings_rw(strindex_example: Strindex):
	strindex_example = deepcopy(strindex_example)
	strindex_example.settings._raw = None

	strindex_example.strings = []
	strindex_example.pointers = []
	strindex_example.type_order = []

	assert get_strindex_md5(strindex_example) == "af5c8927c1a288e25024f7a694f843c1"

def test_create_force(kz_pe_strindex_force: Strindex):
	assert get_strindex_md5(kz_pe_strindex_force) == "185ce250a203820128e5aeb4ee012d64"

def test_create_pe(kz_pe_strindex_full: Strindex, kz_pe_strindex_full_comp: Strindex, kz_pe_strindex_part: Strindex):
	assert get_strindex_md5(kz_pe_strindex_full) == "b3290c5f28ae4d1cadcfce60d4fafdef"
	assert get_strindex_md5(kz_pe_strindex_full_comp) == "9812a2cce013c742d8e5c1235b44690c"
	assert get_strindex_md5(kz_pe_strindex_part) == "ba57555050e4184aae9e1464208b4414"

def test_create_iff(ut_iff_strindex_part: Strindex):
	assert get_strindex_md5(ut_iff_strindex_part) == "7dfa773e0d54b17b0c6bf4c36fd82277"

def test_create_locres(mole_locres_strindex_full: Strindex):
	assert get_strindex_md5(mole_locres_strindex_full) == "8e2449326e6eae99a0b13006ee44433a"

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

def test_update():
	with temp_open() as temp_strindex_in, temp_open() as temp_strindex_out:
		kz_pe_strindex_part_comp = get_strindex("Katana ZERO.exe", StrindexSettings(
			_compatible=True,
			min_length=3,
			prefix_bytes=["24c7442404", "ec04c70424"],
			ranges=["00441078:0060e501"]
		))
		kz_pe_strindex_part_comp.pointers[0] = []
		kz_pe_strindex_part_comp.write(temp_strindex_in.name)

		strindex.core.update(get_file_path("Katana ZERO.exe"), temp_strindex_in.name, temp_strindex_out.name)

		kz_pe_strindex_part_comp.pointers[0] = Strindex.read(temp_strindex_out.name).pointers[0].copy()

		assert get_strindex_md5(kz_pe_strindex_part_comp) == get_file_md5(temp_strindex_out.name)

		strindex.core.update(
			get_file_path("Katana ZERO.exe"), temp_strindex_out.name,
			temp_strindex_out.name, convert_type="overwrite"
		)

		strindex.core.update(
			get_file_path("Katana ZERO.exe"), temp_strindex_out.name,
			temp_strindex_out.name, convert_type="compatible"
		)

		assert get_strindex_md5(kz_pe_strindex_part_comp) == get_file_md5(temp_strindex_out.name)

def test_filter(kz_pe_strindex_full: Strindex):
	with temp_open() as temp_strindex_in, temp_open() as temp_strindex_out:
		kz_pe_strindex_full = deepcopy(kz_pe_strindex_full)
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
