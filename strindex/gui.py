import os, sys
from PySide6 import QtWidgets, QtGui, QtCore
from strindex.utils import PrintProgress, StrindexSettings
from strindex.strindex import create, patch, update, filter, delta, spellcheck, VERSION


class CallbackWorker(QtCore.QThread):
	sig_progress = QtCore.Signal(PrintProgress)
	sig_except = QtCore.Signal(Exception)
	sig_else = QtCore.Signal()

	def __init__(self, callback):
		super().__init__()
		self.callback = callback

	def run(self):
		PrintProgress.callback = lambda progress: self.sig_progress.emit(progress)

		try:
			self.callback()
		except Exception as e:
			self.sig_except.emit(e)
		else:
			self.sig_else.emit()

class BaseStrindexGUI(QtWidgets.QWidget):
	__widgets__: list[QtWidgets.QWidget]
	__required__: list[QtWidgets.QWidget]
	__actions__: list[QtWidgets.QWidget]
	__callback_worker__: CallbackWorker

	def __init__(self):
		super().__init__()

		self.__widgets__ = []
		self.__required__ = []
		self.__actions__ = []
		self.setup()

	@staticmethod
	def parse_widgets(args):
		parsed_args = []
		for arg in args:
			if isinstance(arg, QtWidgets.QLineEdit):
				parsed_args.append(arg.text())
			elif isinstance(arg, QtWidgets.QCheckBox):
				parsed_args.append(arg.isChecked())
		return parsed_args


	def setup(self):
		pass


	def create_file_selection(self, line_text: str, button_text: str = "Browse Files"):
		file_select = self.create_lineedit(line_text)
		file_browse = self.create_button(
			button_text,
			lambda: self.browse_files(file_select, "Select File", "All Files (*)")
		)

		self.__required__.append(file_select)

		return file_select, file_browse

	def create_strindex_selection(self, line_text: str, button_text: str = "Browse strindex"):
		strindex_select = self.create_lineedit(line_text)
		strindex_browse = self.create_button(
			button_text,
			lambda: self.browse_files(strindex_select, "Select Strindex", "Strindex Files (*.txt *.gz)")
		)

		self.__required__.append(strindex_select)

		return strindex_select, strindex_browse

	def create_action_button(self, text: str, progress_text: str, complete_text: str, callback):
		action_button = QtWidgets.QPushButton(text)
		action_button.setEnabled(False)

		progress_bar = QtWidgets.QProgressBar()
		progress_bar.setRange(0, 100)
		progress_bar.setFormat(progress_text)
		progress_bar.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

		def callback_wrapper():
			self.window().setEnabled(False)
			progress_bar.setValue(0)
			self.layout().replaceWidget(action_button, progress_bar)
			action_button.setParent(None)
			QtWidgets.QApplication.processEvents()

			def callback_worker():
				callback(*self.parse_widgets(self.__widgets__))
				progress_bar.setValue(100)

			def callback_progress(progress):
				progress_bar.setValue(progress.percent)

			def callback_except(e):
				self.show_message(str(e), QtWidgets.QMessageBox.Icon.Critical)
				callback_finally()

			def callback_else():
				self.show_message(complete_text, QtWidgets.QMessageBox.Icon.Information)
				callback_finally()

			def callback_finally():
				self.layout().replaceWidget(progress_bar, action_button)
				progress_bar.setParent(None)
				self.window().setEnabled(True)
				QtWidgets.QApplication.processEvents()

			self.__callback_worker__ = CallbackWorker(callback_worker)
			self.__callback_worker__.sig_progress.connect(callback_progress)
			self.__callback_worker__.sig_except.connect(callback_except)
			self.__callback_worker__.sig_else.connect(callback_else)
			self.__callback_worker__.start()

		action_button.clicked.connect(callback_wrapper)

		self.__widgets__.append(action_button)
		self.__actions__.append(action_button)

		return action_button

	def update_action_button(self):
		enabled = all(os.path.isfile(file_select.text()) for file_select in self.__required__)
		for widget in self.__actions__:
			widget.setEnabled(enabled)


	def create_lineedit(self, text: str):
		line_edit = QtWidgets.QLineEdit()
		line_edit.setPlaceholderText(text)
		line_edit.textChanged.connect(self.update_action_button)
		line_edit.textChanged.connect(lambda: line_edit.setStyleSheet(line_edit.styleSheet()))
		line_edit.dragEnterEvent = lambda event: event.accept() if event.mimeData().hasUrls() else event.ignore()
		line_edit.dropEvent = lambda event: line_edit.setText(event.mimeData().urls()[0].toLocalFile())
		line_edit.setFont(QtGui.QFont("monospace"))

		self.__widgets__.append(line_edit)

		return line_edit

	def create_button(self, text: str, callback):
		button = QtWidgets.QPushButton(text)
		button.clicked.connect(callback)

		self.__widgets__.append(button)

		return button

	def create_checkbox(self, text: str):
		checkbox = QtWidgets.QCheckBox(text)

		self.__widgets__.append(checkbox)

		return checkbox

	def create_grid_layout(self, columns: int):
		widget_col_span = []
		index = 0
		while index < len(self.__widgets__):
			if self.__widgets__[index] is None:
				self.__widgets__.pop(index)
				widget_col_span[-1] += 1
			else:
				widget_col_span.append(1)
				index += 1

		index = 0
		grid_layout = QtWidgets.QGridLayout()
		for widget, col_span in zip(self.__widgets__, widget_col_span):
			if widget is not None:
				grid_layout.addWidget(widget, index // columns, index % columns, 1, col_span)
				index += col_span

		grid_layout.setSpacing(10)
		for i in range(columns):
			grid_layout.setColumnMinimumWidth(i, 125)

		grid_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

		self.setLayout(grid_layout)

		return grid_layout

	def create_padding(self, padding: int):
		self.__widgets__ += [None] * padding


	def browse_files(self, line: QtWidgets.QLineEdit, caption, filter):
		if filepath := QtWidgets.QFileDialog.getOpenFileName(self, caption, "", filter)[0]:
			line.setText(filepath)

	def center_window(self):
		target_rect = QtGui.QGuiApplication.primaryScreen().availableGeometry()

		diff_size = target_rect.size() - self.frameGeometry().size()
		self.move(target_rect.x() + diff_size.width() // 2, target_rect.y() + diff_size.height() // 2)

	def show_message(self, text: str, icon):
		msg = QtWidgets.QMessageBox()
		msg.setWindowTitle(self.windowTitle())
		msg.setIcon(icon)
		msg.setText(text)
		msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok)
		msg.exec()
		return msg


class MainStrindexGUI(BaseStrindexGUI):
	def __init__(self):
		app = QtWidgets.QApplication([])

		super().__init__()

		self.show()
		self.center_window()

		sys.exit(app.exec())

	def set_custom_appearance(self):
		WINDOWS_STYLESHEET = f"""QLineEdit{{padding: 2px; margin: 1px 0px;}}"""
		UNIX_STYLESHEET = f"""QLineEdit[text=""]{{color: {self.palette().windowText().color().name()};}}"""
		self.setStyleSheet(WINDOWS_STYLESHEET if sys.platform == "win32" else UNIX_STYLESHEET)

		self.setWindowFlag(QtCore.Qt.WindowType.WindowMaximizeButtonHint, False)
		self.setMinimumSize(500, 0)
		self.setMaximumSize(1600, 0)
		self.resize(800, 0)

	def setup(self):
		self.tab_widget = QtWidgets.QTabWidget()

		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(CreateGUI(), "Create"),
			"Create a list of strings (a strindex) extracted from a file."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(PatchGUI(), "Patch"),
			"Patch a file with a strindex.\n" \
			"Strindexes compressed with gzip are also supported for all actions."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(UpdateGUI(), "Update"),
			"Update a strindex file pointers' with the updated version of a file."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(FilterGUI(), "Filter"),
			"Filter a strindex by detected language, wordlist or length.\n" \
			"You can specify those in the strindex settings."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(DeltaGUI(), "Delta"),
			"Create a delta file between two strindexes,\n" \
			"that only contains the lines of the first strindex missing in the second one (their difference)."
		)
		if "__compiled__" not in globals():
			self.tab_widget.setTabToolTip(
				self.tab_widget.addTab(SpellcheckGUI(), "Spellcheck"),
				"Spellcheck a strindex.\n" \
				"You can specify the target language in the strindex settings as an ISO 639-1 code."
			)

		version_label = QtWidgets.QLabel(f"<a href='https://github.com/zWolfrost/strindex'>v{VERSION}</a>")
		version_label.setOpenExternalLinks(True)
		version_label.setContentsMargins(3, 3, 3, 3)
		self.tab_widget.setCornerWidget(version_label, QtCore.Qt.Corner.TopRightCorner)

		self.__widgets__.append(self.tab_widget)

		self.create_grid_layout(1)

		self.setWindowTitle("Strindex")

		self.set_custom_appearance()

class CreateGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file")

		self.create_lineedit("Minimum length of strings")
		self.create_padding(1)

		self.create_lineedit("Prefix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424")
		self.create_padding(1)

		self.create_lineedit("Suffix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424")
		self.create_padding(1)

		self.create_checkbox("Force Mode").setToolTip(
			"When patching, replace strings at the same offset they were found.\n" \
			"This means the program will effectively work with any filetype,\n" \
			"but the length of the patched strings can't be longer than the original ones."
		)
		self.create_padding(1)

		self.create_checkbox("Compatible Mode").setToolTip(
			"Create a strindex that uses the original strings as references, instead of pointers."
		)
		self.create_padding(1)

		self.create_action_button(
			text="Create strindex",
			progress_text="Creating... %p%",
			complete_text="Strindex created successfully.",
			callback=lambda file, length, prefix, suffix, force, comp: create(
				file, None, comp, StrindexSettings(**{
					"force_mode": force,
					"min_length": length,
					"prefix_bytes": prefix.split(","),
					"suffix_bytes": suffix.split(",")
				})
			)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

class PatchGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file to patch")
		self.create_strindex_selection(line_text="*Select a strindex file")

		self.create_action_button(
			text="Patch file",
			progress_text="Patching... %p%",
			complete_text="File patched successfully.",
			callback=lambda file, strdex: patch(file, strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

class UpdateGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file to update from")
		self.create_strindex_selection(line_text="*Select a strindex file to update")

		self.create_action_button(
			text="Update strindex",
			progress_text="Updating... %p%",
			complete_text="Created an updated strindex successfully.",
			callback=lambda file, strdex: update(file, strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

class FilterGUI(BaseStrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to filter")

		self.create_action_button(
			text="Filter strindex",
			progress_text="Filtering... %p%",
			complete_text="Created a filtered strindex successfully.",
			callback=lambda strdex: filter(strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

class DeltaGUI(BaseStrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to diff from")
		self.create_strindex_selection(line_text="*Select a strindex to diff against")

		self.create_action_button(
			text="Delta strindex",
			progress_text="Updating... %p%",
			complete_text="Created a delta strindex successfully.",
			callback=lambda strdex1, strdex2: delta(strdex1, strdex2, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

class SpellcheckGUI(BaseStrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to spellcheck")

		self.create_action_button(
			text="Spellcheck strindex",
			progress_text="Spellchecking... %p%",
			complete_text="Created a spellcheck file of a strindex successfully.",
			callback=lambda strdex: spellcheck(strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)
