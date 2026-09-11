from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

import strindex.core
from strindex.utils import FileBuffer, Strindex, StrindexSettings


@contextmanager
def temp_open(*args, **kwargs):
	kwargs["delete"] = False

	with NamedTemporaryFile(*args, **kwargs) as f:
		try:
			yield f
		finally:
			name = f.name
			f.close()
			Path(name).unlink(missing_ok=True)

def fixture(func):
	return pytest.fixture(scope="module")(func)

def get_file_path(filename: str) -> str:
	if Path(filename).exists():
		return Path(filename).resolve().as_posix()
	return (Path(__file__).parent / "data" / filename).resolve().as_posix()

def get_file_hash(file: str) -> str:
	return FileBuffer.read(file).hash

def get_strindex_hash(strindex: Strindex) -> str:
	with temp_open() as temp_strindex:
		strindex.write(temp_strindex.name)
		return get_file_hash(temp_strindex.name)

def get_strindex(filename: str, settings: StrindexSettings) -> Strindex:
	with temp_open() as temp_strindex:
		strindex.core.create(get_file_path(filename), temp_strindex.name, settings)
		return Strindex.read(temp_strindex.name)

def convert_strindex_to_dynamic(strindex: Strindex) -> Strindex:
	strindex = deepcopy(strindex)
	strindex.types = [Strindex.Type.DYNAMIC] * strindex.count
	strindex.pointers = [[s, *p] for p, s in zip(strindex.pointers, strindex.strings, strict=True)]
	return strindex



@fixture
def strindex_example() -> Strindex:
	return Strindex.read(get_file_path("strindex_example.txt"))

@fixture
def kz_pe_strindex_force_fixed() -> Strindex:
	return get_strindex("Katana ZERO.exe", StrindexSettings(_raw="", force_mode=True, min_length=3))

@fixture
def kz_pe_strindex_full_fixed() -> Strindex:
	return get_strindex("Katana ZERO.exe", StrindexSettings(_raw="", _dynamic=False))

@fixture
def kz_pe_strindex_full_dynamic(kz_pe_strindex_full_fixed: Strindex) -> Strindex:
	return convert_strindex_to_dynamic(kz_pe_strindex_full_fixed)

@fixture
def kz_pe_strindex_part_fixed() -> Strindex:
	return get_strindex("Katana ZERO.exe", StrindexSettings(
		_dynamic=False,
		min_length=3,
		prefix_bytes=["24c7442404", "ec04c70424"],
		ranges=["00441078:0060e501"]
	))

@fixture
def kz_pe_strindex_part_dynamic(kz_pe_strindex_part_fixed: Strindex) -> Strindex:
	return convert_strindex_to_dynamic(kz_pe_strindex_part_fixed)

@fixture
def ut_iff_strindex_part_fixed() -> Strindex:
	return get_strindex("data.win", StrindexSettings(
		_raw="",
		_dynamic=False,
		min_length=3,
		prefix_bytes=["d000"],
		ranges=["00c96ce0:00c98410"]
	))

@fixture
def mole_locres_strindex_full_fixed() -> Strindex:
	return get_strindex("Game.locres", StrindexSettings(_raw="", _dynamic=False))

@fixture
def mole_locres_strindex_full_dynamic(mole_locres_strindex_full_fixed: Strindex) -> Strindex:
	return convert_strindex_to_dynamic(mole_locres_strindex_full_fixed)



def test_test_data():
	# FILES NEEDED FOR TESTING (in ./tests/data/ folder):

	for filepath, hash in (
		("strindex_example.txt", "1b120609"), # from this repo
		("locres_strindex.txt",  "791dc7ab"), # from this repo
		("kz_exe.gz",            "b7230123"), # from this repo
		("Katana ZERO.exe",      "b40bda78"), # from Katana ZERO
		("data.win",             "d3d27c56"), # from Undertale
		("Game.locres",          "e4175036"), # from MOLE
	):
		assert get_file_hash(get_file_path(filepath)) == hash

def test_strindex_rw(strindex_example: Strindex):
	assert get_strindex_hash(strindex_example) == get_file_hash(get_file_path("strindex_example.txt"))

def test_strindex_settings_rw(strindex_example: Strindex):
	strindex_example = deepcopy(strindex_example)
	strindex_example.settings._raw = None

	strindex_example.strings = []
	strindex_example.pointers = []
	strindex_example.types = []

	assert get_strindex_hash(strindex_example) == "8796d862"

def test_create_force(kz_pe_strindex_force_fixed: Strindex):
	assert get_strindex_hash(kz_pe_strindex_force_fixed) == "9f9484c2"

def test_create_pe(
	kz_pe_strindex_full_fixed: Strindex,
	kz_pe_strindex_full_dynamic: Strindex,
	kz_pe_strindex_part_fixed: Strindex
):
	assert get_strindex_hash(kz_pe_strindex_full_fixed) == "2691043f"
	assert get_strindex_hash(kz_pe_strindex_full_dynamic) == "bd74b73f"
	assert get_strindex_hash(kz_pe_strindex_part_fixed) == "87ed4ee1"

def test_create_iff(ut_iff_strindex_part_fixed: Strindex):
	assert get_strindex_hash(ut_iff_strindex_part_fixed) == "b79037b8"

def test_create_locres(mole_locres_strindex_full_fixed: Strindex):
	assert get_strindex_hash(mole_locres_strindex_full_fixed) == "3775c199"

def test_patch_pe(kz_pe_strindex_full_fixed: Strindex, kz_pe_strindex_part_fixed: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_file:
		strindex.core.patch(get_file_path("Katana ZERO.exe"), get_file_path("kz_exe.gz"), temp_file.name)
		assert get_file_hash(temp_file.name) == "d3eed884"

		kz_pe_strindex_full_fixed.write(temp_strindex.name)
		strindex.core.patch(get_file_path("Katana ZERO.exe"), temp_strindex.name, temp_file.name)
		assert get_file_hash(temp_file.name) == "cf351621"

		kz_pe_strindex_part_fixed.write(temp_strindex.name)
		strindex.core.patch(get_file_path("Katana ZERO.exe"), temp_strindex.name, temp_file.name)
		assert get_file_hash(temp_file.name) == "f7546be9"

def test_patch_iff(ut_iff_strindex_part_fixed: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_file:
		ut_iff_strindex_part_fixed.write(temp_strindex.name)
		strindex.core.patch(get_file_path("data.win"), temp_strindex.name, temp_file.name)
		assert get_file_hash(temp_file.name) == "1f3a3685"

def test_patch_locres(mole_locres_strindex_full_fixed: Strindex, mole_locres_strindex_full_dynamic: Strindex):
	with temp_open() as temp_strindex, temp_open() as temp_file:
		for mole_locres_strindex in (mole_locres_strindex_full_fixed, mole_locres_strindex_full_dynamic):
			mole_locres_strindex.write(temp_strindex.name)
			strindex.core.patch(get_file_path("Game.locres"), temp_strindex.name, temp_file.name)
			assert get_file_hash(temp_file.name) == get_file_hash(get_file_path("Game.locres"))

		strindex.core.patch(get_file_path("Game.locres"), get_file_path("locres_strindex.txt"), temp_file.name)
		assert get_file_hash(temp_file.name) == "811cc32e"

def test_patch_force():
	with temp_open() as temp_strindex, temp_open() as temp_file:
		temp_strindex_force = Strindex.read(get_file_path("locres_strindex.txt"))
		temp_strindex_force.settings._raw = None
		temp_strindex_force.settings.force_mode = True
		temp_strindex_force.pointers[0][0] += 8
		temp_strindex_force.pointers[2][0] += 8
		temp_strindex_force.write(temp_strindex.name)
		strindex.core.patch(get_file_path("Game.locres"), temp_strindex.name, temp_file.name)
		assert get_file_hash(temp_file.name) == "6cd4358f"

def test_update(kz_pe_strindex_part_dynamic: Strindex):
	with temp_open() as temp_strindex_in, temp_open() as temp_strindex_out:
		kz_pe_strindex_part_dynamic = deepcopy(kz_pe_strindex_part_dynamic)
		kz_pe_strindex_part_dynamic.pointers[0] = kz_pe_strindex_part_dynamic.pointers[0][:1]
		kz_pe_strindex_part_dynamic.write(temp_strindex_in.name)

		strindex.core.update(get_file_path("Katana ZERO.exe"), temp_strindex_in.name, temp_strindex_out.name)

		kz_pe_strindex_part_dynamic.pointers[0] = Strindex.read(temp_strindex_out.name).pointers[0].copy()

		assert get_strindex_hash(kz_pe_strindex_part_dynamic) == get_file_hash(temp_strindex_out.name)

def test_update_conversion(kz_pe_strindex_part_dynamic: Strindex):
	with temp_open() as temp_strindex:
		kz_pe_strindex_part_dynamic.write(temp_strindex.name)

		strindex.core.update(
			get_file_path("Katana ZERO.exe"), temp_strindex.name, temp_strindex.name,
			convert_type=Strindex.Type.FIXED
		)

		strindex.core.update(
			get_file_path("Katana ZERO.exe"), temp_strindex.name, temp_strindex.name,
			convert_type=Strindex.Type.DYNAMIC
		)

		assert get_strindex_hash(kz_pe_strindex_part_dynamic) == get_file_hash(temp_strindex.name)

def test_filter(kz_pe_strindex_full_fixed: Strindex):
	with temp_open() as temp_strindex_in, temp_open() as temp_strindex_out:
		kz_pe_strindex_full_fixed = deepcopy(kz_pe_strindex_full_fixed)
		kz_pe_strindex_full_fixed.settings = StrindexSettings(min_length=3, whitelist=["latin"])
		kz_pe_strindex_full_fixed.write(temp_strindex_in.name)

		strindex.core.filter(temp_strindex_in.name, temp_strindex_out.name)

		assert Strindex.read(temp_strindex_out.name).count == 24180

def test_diff(kz_pe_strindex_full_fixed: Strindex, kz_pe_strindex_part_fixed: Strindex):
	with temp_open() as temp_strindex_in1, temp_open() as temp_strindex_in2, temp_open() as temp_strindex_out:
		diff_count = kz_pe_strindex_full_fixed.count - kz_pe_strindex_part_fixed.count

		kz_pe_strindex_full_fixed.write(temp_strindex_in1.name)
		kz_pe_strindex_part_fixed.write(temp_strindex_in2.name)

		strindex.core.diff(temp_strindex_in1.name, temp_strindex_in2.name, temp_strindex_out.name)

		assert Strindex.read(temp_strindex_out.name).count == diff_count

def test_merge(kz_pe_strindex_full_dynamic: Strindex):
	with temp_open() as temp_strindex_in2, temp_open() as temp_strindex_out:
		kz_pe_strindex_full_dynamic.write(temp_strindex_in2.name)

		res = strindex.core.merge(get_file_path("kz_exe.gz"), temp_strindex_in2.name, temp_strindex_out.name)

		assert str(Strindex.read(get_file_path("kz_exe.gz")).count) in res
