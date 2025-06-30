import os
import sys
from PySide6 import QtWidgets, QtGui, QtCore
from strindex.utils import StrindexSettings, PrintProgress
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

			def callback_progress(progress):
				progress_bar.setValue(progress.percent)

			def callback_except(e):
				self.show_message(str(e), QtWidgets.QMessageBox.Icon.Critical)
				callback_finally()

			def callback_else():
				progress_bar.setValue(100)
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
	app: QtWidgets.QApplication

	def __init__(self):
		self.app = QtWidgets.QApplication([])
		self.app.setApplicationName("Strindex")
		self.app.setApplicationVersion(VERSION)
		self.app.setOrganizationName("zWolfrost")

		super().__init__()

		self.show()
		self.center_window()

		sys.exit(self.app.exec())

	def set_custom_appearance(self):
		if sys.platform == "win32":
			self.app.setStyle("Fusion")
			self.setStyleSheet(
				"""QLineEdit{padding: 3px; margin: 1px 0px;}"""
			)
		else:
			self.setStyleSheet(
				f"""QLineEdit[text=""]{{color: {self.palette().windowText().color().name()};}}"""
			)

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
			"Patch a file with a strindex.\n"
			"Strindexes compressed with gzip are also supported for all actions."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(UpdateGUI(), "Update"),
			"Update a strindex file pointers' with the updated version of a file."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(FilterGUI(), "Filter"),
			"Filter a strindex by detected language, wordlist or length.\n"
			"You can specify those in the strindex settings."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(DeltaGUI(), "Delta"),
			"Create a delta file between two strindexes,\n"
			"that only contains the lines of the first strindex missing in the second one (their difference)."
		)
		if "__compiled__" not in globals():
			self.tab_widget.setTabToolTip(
				self.tab_widget.addTab(SpellcheckGUI(), "Spellcheck"),
				"Spellcheck a strindex.\n"
				"You can specify the target language in the strindex settings as an ISO 639-1 code."
			)

		version_label = QtWidgets.QLabel(f"<a href='https://github.com/zWolfrost/strindex'>v{VERSION}</a>")
		version_label.setOpenExternalLinks(True)
		version_label.setContentsMargins(3, 3, 3, 3)
		self.tab_widget.setCornerWidget(version_label, QtCore.Qt.Corner.TopRightCorner)

		self.__widgets__.append(self.tab_widget)

		self.create_grid_layout(1)

		self.setWindowTitle("Strindex")

		ICON_BASE64 = b"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"
		icon = QtGui.QPixmap()
		icon.loadFromData(QtCore.QByteArray.fromBase64(ICON_BASE64), "PNG")
		self.setWindowIcon(icon)

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
			"When patching, replace strings at the same offset they were found.\n"
			"This means the program will effectively work with any filetype,\n"
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
