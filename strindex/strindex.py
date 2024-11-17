import os, sys, argparse, re
from hashlib import md5
from importlib import import_module
from .utils import PrintProgress, Strindex, FileBytearray, truncate_prev_char


def get_module_methods(data: FileBytearray, action: str) -> dict:
	"""
		Returns the methods of the module associated with the file type.
	"""

	for file in os.listdir(os.path.join(os.path.dirname(__file__), "filetypes")):
		if file.endswith(".py") and file != "__init__.py":
			try:
				module = import_module(".filetypes." + file.rstrip('.py'), __package__)
			except ImportError:
				continue

			if module.is_valid(data):
				print(f'Detected filetype: "{file.rstrip(".py")}"')
				assert action in module.__dict__, f"Action '{action}' is not available for this file type."
				return module.__dict__[action]

	raise ValueError("This file type has no associated module, or the required libraries to handle it are not installed.")


def create(file_filepath: str, strindex_filepath: str, compatible: bool, min_length: int, prefixes: list[bytes]):
	"""
		Calls the create method of the module associated with the file type.
	"""

	data = FileBytearray(open(file_filepath, 'rb').read())

	STRINDEX: Strindex = get_module_methods(data, "create")(data, min_length, prefixes)

	STRINDEX.original = STRINDEX.overwrite
	STRINDEX.replace = STRINDEX.overwrite
	STRINDEX.pointers_switches = STRINDEX.pointers
	STRINDEX.type_order = ["compatible" if compatible else "original"] * len(STRINDEX.overwrite)

	STRINDEX.settings["md5"] = md5(data).hexdigest()
	if prefixes != [b'']:
		STRINDEX.settings["prefix_bytes"] = [prefix.hex() for prefix in prefixes]

	STRINDEX.save(strindex_filepath)

	print("Created strindex file.")

def patch(file_filepath: str, strindex_filepath: str, file_patched_filepath: str):
	"""
		Calls the patch method of the module associated with the file type.
	"""

	file_filepath_bak = file_filepath + '.bak'

	data = FileBytearray(open(file_filepath_bak if os.path.exists(file_filepath_bak) else file_filepath, 'rb').read())

	STRINDEX: Strindex = Strindex.from_file(strindex_filepath)

	if STRINDEX.settings["md5"] and STRINDEX.settings["md5"] != md5(data).hexdigest():
		print("MD5 hash does not match the one the strindex was created for. You might encounter issues.")

	if not file_patched_filepath:
		if not os.path.exists(file_filepath_bak):
			os.rename(file_filepath, file_filepath_bak)
		file_patched_filepath = file_filepath

	data = get_module_methods(data, "patch")(data, STRINDEX)
	open(file_patched_filepath, 'wb').write(data)

	print("File was patched successfully.")

def filter(strindex_filepath: str, strindex_filter_filepath: str):
	"""
		Filters a strindex file with another with respect to length, whitelist and source language.
	"""

	STRINDEX = Strindex.from_file(strindex_filepath)
	STRINDEX_LINES = STRINDEX.get_ordered_strings(lambda t: "original" if t == "compatible" else t)

	if STRINDEX.settings["source_language"]:
		try:
			from lingua import IsoCode639_1, LanguageDetectorBuilder
		except ImportError:
			raise ImportError(
				"Please install the 'lingua' package (pip install lingua) to filter by language."
			)

		ALL_LANGUAGES = [code for code in IsoCode639_1.__dict__.values() if isinstance(code, IsoCode639_1)]
		SETTINGS_LANGUAGES = [getattr(IsoCode639_1, code.upper()) for code in STRINDEX.settings["among_languages"]]

		detector = LanguageDetectorBuilder.from_iso_codes_639_1(*(SETTINGS_LANGUAGES or ALL_LANGUAGES)).build()

	def is_source_language(string: str) -> bool:
		line_clean = re.sub(STRINDEX.settings["clean_pattern"], "", string)
		confidence = detector.compute_language_confidence_values(line_clean)[0]
		return confidence.language.iso_code_639_1 == getattr(IsoCode639_1, STRINDEX.settings["source_language"].upper()) and confidence.value > 0.5

	print_progress = PrintProgress(len(STRINDEX_LINES))
	with open(strindex_filter_filepath, 'w', encoding='utf-8') as f:
		f.write(STRINDEX.full_header)

		for strindex_index, line in enumerate(STRINDEX_LINES):
			if (
				(not STRINDEX.settings["source_language"] or is_source_language(line)) and
				(len(line) >= STRINDEX.settings["min_length"]) and
				(not STRINDEX.settings.get("whitelist") or not any(ch not in STRINDEX.settings["whitelist"] for ch in line))
			):
				f.write(STRINDEX.create_raw_from_index(strindex_index))

			print_progress(strindex_index)

		truncate_prev_char(f)
	print("Created filtered strindex file.")

def delta(strindex_full_filepath: str, strindex_diff_filepath: str, strindex_delta_filepath: str, reverse: bool = False):
	"""
		Filters a full strindex file with a delta strindex file, or intersects them.
	"""

	STRINDEX_1 = Strindex.from_file(strindex_full_filepath)
	STRINDEX_2 = Strindex.from_file(strindex_diff_filepath)

	STRINDEX_1_LINES = STRINDEX_1.get_ordered_strings(lambda t: "original" if t == "compatible" else t)
	STRINDEX_2_LINES = STRINDEX_2.get_ordered_strings(lambda t: "original" if t == "compatible" else t)

	with open(strindex_delta_filepath, 'w', encoding='utf-8') as f:
		f.write(STRINDEX_1.full_header)

		index_2 = 0
		for full_index in range(len(STRINDEX_1.type_order)):
			try:
				index_2 = STRINDEX_2_LINES.index(STRINDEX_1_LINES[full_index], index_2)
			except ValueError:
				if not reverse:
					f.write(STRINDEX_1.create_raw_from_index(full_index))
			else:
				if reverse:
					f.write(STRINDEX_1.create_raw_from_index(full_index))

		truncate_prev_char(f)

	print("Created delta strindex file.")

def spellcheck(strindex_filepath: str, strindex_spellcheck_filepath: str):
	"""
		Creates a spellcheck file from a strindex file, for the specified language.
	"""

	try:
		from language_tool_python import LanguageTool
	except ImportError:
		raise ImportError("Please install the 'language-tool-python' package (pip install language-tool-python) to use this feature.")

	STRINDEX = Strindex.from_file(strindex_filepath)
	STRINDEX_LINES = STRINDEX.get_ordered_strings(lambda t: "replace" if t == "compatible" else t)

	if not STRINDEX.settings["target_language"]:
		raise ValueError("Please specify the target language to spellcheck in the strindex file ('target_language').")

	lang = LanguageTool(STRINDEX.settings["target_language"])
	print("Created language tool.")

	with open(strindex_spellcheck_filepath, 'w', encoding='utf-8') as f:
		print_progress = PrintProgress(len(STRINDEX_LINES))
		for strindex_index, line in enumerate(STRINDEX_LINES):
			line_clean = re.sub(STRINDEX.settings["clean_pattern"], "", line)
			for error in lang.check(line_clean):
				f.write('\n'.join(str(error).split('\n')[-3:]) + '\n')

			print_progress(strindex_index)
	print("Spellchecked strindex file.")


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


def main():
	if "__compiled__" in globals():
		patch_gui()
	else:
		try:
			parser = argparse.ArgumentParser(prog="strindex", description="Command line string replacement tool for games.")

			parser.add_argument("action", type=str, choices=["create", "patch", "patch_gui", "filter", "delta", "spellcheck"], help="Action to perform.")
			parser.add_argument("files", type=str, nargs=argparse.ZERO_OR_MORE, help="One or more files to process.")
			parser.add_argument("-o", "--output", type=str, help="Output file.")

			# create arguments
			parser.add_argument("-c", "--compatible", action="store_true", help="Whether to create a strindex file compatible with the previous versions of a program.")
			parser.add_argument("-m", "--min-length", type=int, default=3, help="Minimum length of the strings to be included.")
			parser.add_argument("-p", "--prefix-bytes", type=str, action="append", default=[], help="Prefix bytes to add to the rva in the strindex file.")

			# delta arguments
			parser.add_argument("-r", "--reverse-delta", action="store_true", help="Whether to reverse the delta operation and intersect the files.")

			args = parser.parse_args()

			if not all([os.path.isfile(file) for file in args.files]):
				raise FileNotFoundError("One or more files do not exist.")

			args.prefix_bytes = [bytes.fromhex(prefix) for prefix in (args.prefix_bytes or [''])]

			match args.action:
				case "create":
					create(*args.files, (args.output or "strindex.txt"), args.compatible, args.min_length, args.prefix_bytes)
				case "patch":
					patch(*args.files, args.output)
				case "patch_gui":
					patch_gui()
				case "filter":
					filter(*args.files, (args.output or "strindex_filter.txt"))
				case "delta":
					delta(*args.files, (args.output or "strindex_delta.txt"), args.reverse_delta)
				case "spellcheck":
					spellcheck(*args.files, (args.output or "strindex_spellcheck.txt"))
		except KeyboardInterrupt:
			print("Interrupted by user.")
		except BaseException as e:
			print(e)

if __name__ == "__main__":
	main()
