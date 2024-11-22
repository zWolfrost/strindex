import os, sys, argparse
from hashlib import md5
from strindex.utils import PrintProgress, Strindex, StrindexSettings, FileBytearray
from strindex.filetypes import MODULES


def get_module_methods(data: FileBytearray, action: str) -> dict:
	"""
		Returns the methods of the module associated with the file type.
	"""

	for module in MODULES:
		if module.is_valid(data):
			print(f'Detected filetype: "{module.__name__.split(".")[-1]}".')
			assert action in module.__dict__, f"Action '{action}' is not available for this file type."
			return module.__dict__[action]

	raise ValueError("This file type has no associated module, or the required libraries to handle it are not installed.")


def create(file_filepath: str, strindex_filepath: str, compatible: bool, settings: StrindexSettings):
	"""
		Calls the create method of the module associated with the file type.
	"""

	data = FileBytearray(open(file_filepath, 'rb').read())

	STRINDEX: Strindex = get_module_methods(data, "create")(data, settings)

	if compatible:
		STRINDEX.type_order = ["compatible"] * len(STRINDEX.overwrite)
		STRINDEX.original = STRINDEX.overwrite
		STRINDEX.replace = STRINDEX.overwrite
		STRINDEX.overwrite = []
		STRINDEX.pointers_switches = STRINDEX.pointers
		STRINDEX.pointers = []
	else:
		STRINDEX.type_order = ["overwrite"] * len(STRINDEX.overwrite)

	STRINDEX.settings = settings
	STRINDEX.settings.md5 = md5(data).hexdigest()

	STRINDEX.write(strindex_filepath)

	print("Created strindex file.")

def patch(file_filepath: str, strindex_filepath: str, file_patched_filepath: str):
	"""
		Calls the patch method of the module associated with the file type.
	"""

	file_filepath_bak = file_filepath + '.bak'

	data = FileBytearray(open(file_filepath_bak if os.path.exists(file_filepath_bak) else file_filepath, 'rb').read())

	STRINDEX = Strindex.read(strindex_filepath)

	if STRINDEX.settings.md5 and STRINDEX.settings.md5 != md5(data).hexdigest():
		print("MD5 hash does not match the one the strindex was created for. You may encounter issues.")

	data = get_module_methods(data, "patch")(data, STRINDEX)

	if not file_patched_filepath:
		if not os.path.exists(file_filepath_bak):
			os.rename(file_filepath, file_filepath_bak)
		file_patched_filepath = file_filepath

	open(file_patched_filepath, 'wb').write(data)

	print("File was patched successfully.")

def patch_gui():
	try:
		from PySide6 import QtCore, QtWidgets, QtGui
	except ImportError:
		raise ImportError("Please install the 'PySide6' package (pip install pyside6) to use this feature.")

	class PatchGUI(QtWidgets.QWidget):
		def __init__(self):
			super().__init__()

			# file selection
			self.file_line = QtWidgets.QLineEdit()
			self.file_line.setPlaceholderText("Select a file to patch")
			self.file_line.textChanged.connect(self.update)
			self.file_line.textChanged.connect(lambda: self.file_line.setStyleSheet(self.file_line.styleSheet()))
			self.file_line.setFont(QtGui.QFont("monospace"))
			self.file_button = QtWidgets.QPushButton("Browse Files")
			self.file_button.clicked.connect(lambda: self.browse(self.file_line, "Open File", "All Files (*)"))

			# strindex selection
			self.strindex_line = QtWidgets.QLineEdit()
			self.strindex_line.setPlaceholderText("Select a Strindex file")
			self.strindex_line.textChanged.connect(self.update)
			self.strindex_line.textChanged.connect(lambda: self.strindex_line.setStyleSheet(self.strindex_line.styleSheet()))
			self.strindex_line.setFont(QtGui.QFont("monospace"))
			self.strindex_button = QtWidgets.QPushButton("Browse Strindex")
			self.strindex_button.clicked.connect(lambda: self.browse(self.strindex_line, "Open Strindex", "Text Files (*.txt)"))

			# patch button
			self.patch_button = QtWidgets.QPushButton("Patch")
			self.patch_button.clicked.connect(self.patch)
			self.patch_button.setEnabled(False)

			# progress bar
			self.progress_bar = QtWidgets.QProgressBar()
			self.progress_bar.setRange(0, 100)
			self.progress_bar.setFormat("Patching... %p%")
			self.progress_bar.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
			PrintProgress.callback = lambda progress: self.progress_bar.setValue(progress.percent)

			# add widgets to layout
			self.grid_layout = QtWidgets.QGridLayout()
			self.grid_layout.addWidget(self.file_line, 0, 0)
			self.grid_layout.addWidget(self.file_button, 0, 1)
			self.grid_layout.addWidget(self.strindex_line, 1, 0)
			self.grid_layout.addWidget(self.strindex_button, 1, 1)
			self.grid_layout.addWidget(self.patch_button, 2, 0, 1, 2)
			self.grid_layout.setSpacing(10)
			self.grid_layout.setColumnStretch(0, 1)
			self.grid_layout.setColumnMinimumWidth(0, 200)
			self.setLayout(self.grid_layout)

			# set window properties
			WINDOWS_STYLESHEET = f""""""
			UNIX_STYLESHEET = f"""QLineEdit[text=""]{{color: {self.palette().windowText().color().name()};}}"""
			self.setWindowTitle("Strindex Patch")
			self.setStyleSheet(WINDOWS_STYLESHEET if sys.platform == "win32" else UNIX_STYLESHEET)
			self.setWindowFlag(QtCore.Qt.WindowType.WindowMaximizeButtonHint, False)
			self.setMaximumSize(1600, 0)
			self.resize(800, 0)
			self.center()

		def browse(self, line: QtWidgets.QLineEdit, caption, filter):
			if filepath := QtWidgets.QFileDialog.getOpenFileName(self, caption, "", filter)[0]:
				line.setText(filepath)

		def update(self):
			path_exists = os.path.isfile(self.file_line.text()) and os.path.isfile(self.strindex_line.text())
			self.patch_button.setEnabled(path_exists)

		def patch(self):
			self.setEnabled(False)
			self.progress_bar.setValue(0)
			self.grid_layout.replaceWidget(self.patch_button, self.progress_bar)
			self.patch_button.setParent(None)
			QtWidgets.QApplication.processEvents()

			try:
				patch(self.file_line.text(), self.strindex_line.text(), None)
				self.progress_bar.setValue(100)
			except BaseException as e:
				self.message(str(e), QtWidgets.QMessageBox.Critical)
			else:
				self.message("File patched successfully.", QtWidgets.QMessageBox.Information)
			finally:
				self.grid_layout.replaceWidget(self.progress_bar, self.patch_button)
				self.progress_bar.setParent(None)
				self.setEnabled(True)
				QtWidgets.QApplication.processEvents()

		def center(self):
			res = QtGui.QGuiApplication.primaryScreen().availableGeometry()
			self.move((res.width() - self.width()) // 2, (res.height() - self.height()) // 2)

		def message(self, text: str, icon):
			msg = QtWidgets.QMessageBox()
			msg.setWindowTitle(self.windowTitle())
			msg.setIcon(icon)
			msg.setText(text)
			msg.setStandardButtons(QtWidgets.QMessageBox.Ok.Ok)
			msg.exec()
			return msg

	app = QtWidgets.QApplication([])
	gui = PatchGUI()
	gui.show()
	sys.exit(app.exec())

def update(file_filepath: str, strindex_filepath: str, file_updated_filepath: str):
	"""
		Update a strindex file with newly created pointers.
	"""

	data = FileBytearray(open(file_filepath, 'rb').read())

	STRINDEX = Strindex.read(strindex_filepath)
	STRINDEX_UPDATED: Strindex = get_module_methods(data, "create")(data, STRINDEX.settings)

	updated_pointers = 0
	search_index = 0
	for strindex_index in range(len(STRINDEX.original)):
		try:
			search_index = STRINDEX_UPDATED.overwrite.index(STRINDEX.original[strindex_index], search_index)
		except ValueError:
			pass
		else:
			if len(STRINDEX.pointers_switches[strindex_index]) != len(STRINDEX_UPDATED.pointers[search_index]):
				updated_pointers += 1
			STRINDEX.pointers_switches[strindex_index] = STRINDEX_UPDATED.pointers[search_index]

	STRINDEX.write(file_updated_filepath)

	print(f"Created strindex file with {updated_pointers} updated pointer(s).")

def filter(strindex_filepath: str, strindex_filter_filepath: str):
	"""
		Filters a strindex file with another with respect to length, whitelist and source language.
	"""

	STRINDEX = Strindex.read(strindex_filepath)
	STRINDEX_FILTER = Strindex()
	STRINDEX_FILTER.full_header = STRINDEX.full_header

	if STRINDEX.settings.source_language:
		try:
			from lingua import LanguageDetectorBuilder, IsoCode639_1
		except ImportError:
			raise ImportError("Please install the 'lingua' package (pip install lingua-language-detector) to filter by language.")

		ALL_LANGUAGES = [code for code in IsoCode639_1.__dict__.values() if isinstance(code, IsoCode639_1)]
		SETTINGS_LANGUAGES = [getattr(IsoCode639_1, code.upper()) for code in STRINDEX.settings.among_languages or []]

		detector = LanguageDetectorBuilder.from_iso_codes_639_1(*(SETTINGS_LANGUAGES or ALL_LANGUAGES)).build()

	def is_source_language(string: str) -> bool:
		string_clean = STRINDEX.settings.clean_string(string)
		confidence = detector.compute_language_confidence_values(string_clean)[0]
		return confidence.language.iso_code_639_1 == getattr(IsoCode639_1, STRINDEX.settings.source_language.upper()) and confidence.value > 0.5

	print_progress = PrintProgress(len(STRINDEX.type_order))
	for strindex_index, (type_index, type) in enumerate(STRINDEX.iterate_type_count()):
		string = STRINDEX.original[type_index] if type == "compatible" else STRINDEX.overwrite[type_index]
		valid_language = not STRINDEX.settings.source_language or is_source_language(string)
		valid_length = len(string) >= STRINDEX.settings.min_length
		valid_whitelist = not STRINDEX.settings.whitelist or not any(ch not in STRINDEX.settings.whitelist for ch in string)

		if all([valid_language, valid_length, valid_whitelist]):
			STRINDEX.append_to_strindex(STRINDEX_FILTER, type, type_index)

		print_progress(strindex_index)

	STRINDEX_FILTER.write(strindex_filter_filepath)
	print(f"Created strindex file with {len(STRINDEX_FILTER.type_order)} / {len(STRINDEX.type_order)} strings.")

def delta(strindex_full_filepath: str, strindex_diff_filepath: str, strindex_delta_filepath: str):
	"""
		Filters a full strindex file with a delta strindex file, or intersects them.
	"""

	STRINDEX_1 = Strindex.read(strindex_full_filepath)
	STRINDEX_2 = Strindex.read(strindex_diff_filepath)

	STRINDEX_1_FULL = [STRINDEX_1.original[i] if t == "compatible" else STRINDEX_1.overwrite[i] for i, t in STRINDEX_1.iterate_type_count()]
	STRINDEX_2_FULL = [STRINDEX_2.original[i] if t == "compatible" else STRINDEX_2.overwrite[i] for i, t in STRINDEX_2.iterate_type_count()]

	STRINDEX_DELTA = Strindex()
	STRINDEX_DELTA.full_header = STRINDEX_1.full_header

	index_2 = 0
	for full_index, (type_index, type) in enumerate(STRINDEX_1.iterate_type_count()):
		try:
			index_2 = STRINDEX_2_FULL.index(STRINDEX_1_FULL[full_index], index_2)
		except ValueError:
			STRINDEX_1.append_to_strindex(STRINDEX_DELTA, type, type_index)

	STRINDEX_DELTA.write(strindex_delta_filepath)
	print(f"Created delta strindex file with {len(STRINDEX_DELTA.type_order)} / {len(STRINDEX_1.type_order)} strings.")

def spellcheck(strindex_filepath: str, strindex_spellcheck_filepath: str):
	"""
		Creates a spellcheck file from a strindex file, for the specified language.
	"""

	try:
		from language_tool_python import LanguageTool
	except ImportError:
		raise ImportError("Please install the 'language-tool-python' package (pip install language-tool-python) to use this feature.")

	STRINDEX = Strindex.read(strindex_filepath)
	STRINDEX_FULL = [STRINDEX.replace[i] if t == "compatible" else STRINDEX.overwrite[i] for i, t in STRINDEX.iterate_type_count()]

	if not STRINDEX.settings.target_language:
		raise ValueError("Please specify the target language to spellcheck in the strindex file ('target_language').")

	lang = LanguageTool(STRINDEX.settings.target_language)
	print("Created language tool.")

	with open(strindex_spellcheck_filepath, 'w', encoding='utf-8') as f:
		print_progress = PrintProgress(len(STRINDEX_FULL))
		for strindex_index, string in enumerate(STRINDEX_FULL):
			string_clean = STRINDEX.settings.clean_string(string)
			for error in lang.check(string_clean):
				f.write('\n'.join(str(error).split('\n')[-3:]) + '\n')

			print_progress(strindex_index)
	print("Spellchecked strindex file.")


def main():
	if "__compiled__" in globals():
		patch_gui()
	else:
		try:
			parser = argparse.ArgumentParser(prog="strindex", description="Command line string replacement tool for games.")

			parser.add_argument("action", type=str, choices=["create", "patch", "patch_gui", "update", "filter", "delta", "spellcheck"], help="Action to perform.")
			parser.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE, help="One or more files to process.")
			parser.add_argument("-o", "--output", type=str, help="Output file.")

			# create arguments
			parser.add_argument("-c", "--compatible", action="store_true", help="Whether to create a strindex file compatible with the previous versions of a program.")
			parser.add_argument("-m", "--min-length", type=int, help="Minimum length of the strings to be included.")
			parser.add_argument("-p", "--prefix-bytes", type=str, action="append", default=[], help="Prefix bytes to add to the rva in the strindex file.")
			parser.add_argument("-s", "--suffix-bytes", type=str, action="append", default=[], help="Suffix bytes to add to the rva in the strindex file.")

			args = parser.parse_args()

			if not all([os.path.isfile(file) for file in args.files]):
				raise FileNotFoundError("One or more files do not exist.")

			match args.action:
				case "create":
					settings = StrindexSettings(**{
						"min_length": args.min_length,
						"prefix_bytes": args.prefix_bytes,
						"suffix_bytes": args.suffix_bytes
					})

					create(*args.files, (args.output or "strindex.txt"), args.compatible, settings)
				case "patch":
					patch(*args.files, args.output)
				case "patch_gui":
					patch_gui()
				case "update":
					update(*args.files, (args.output or "strindex_updated.txt"))
				case "filter":
					filter(*args.files, (args.output or "strindex_filter.txt"))
				case "delta":
					delta(*args.files, (args.output or "strindex_delta.txt"))
				case "spellcheck":
					spellcheck(*args.files, (args.output or "strindex_spellcheck.txt"))
		except KeyboardInterrupt:
			print("Interrupted by user.")
		except BaseException as e:
			print(f"Error: {e}")

if __name__ == "__main__":
	main()
