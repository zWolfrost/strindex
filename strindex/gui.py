import os, sys
from urllib.parse import urlparse, unquote
from PySide6 import QtWidgets, QtGui, QtCore
from strindex.utils import PrintProgress, StrindexSettings
from strindex.strindex import create, patch, update, filter, delta, spellcheck


class StrindexGUI(QtWidgets.QWidget):
	__required__: list[QtWidgets.QWidget]
	__widgets__: list[QtWidgets.QWidget]

	def __init__(self):
		if active_window := QtWidgets.QApplication.activeWindow():
			active_window: StrindexGUI
			active_window.hide()
			self.closeEvent = lambda _: (active_window.show(), active_window.center_window())

		is_first_window = not QtWidgets.QApplication.instance()
		app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])

		super().__init__()

		self.__required__ = []
		self.__widgets__ = []
		self.setup()
		self.show()
		self.center_window()

		if is_first_window:
			sys.exit(app.exec())

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
		file_browse = self.create_button(button_text, lambda: self.browse_files(file_select, "Select File", "All Files (*)"))

		self.__required__.append(file_select)

		return file_select, file_browse

	def create_strindex_selection(self, line_text: str, button_text: str = "Browse strindex"):
		strindex_select = self.create_lineedit(line_text)
		strindex_browse = self.create_button(button_text, lambda: self.browse_files(strindex_select, "Select Strindex", "Strindex Files (*.txt *.gz)"))

		self.__required__.append(strindex_select)

		return strindex_select, strindex_browse

	def create_action_button(self, text: str, progress_text: str, complete_text: str, callback):
		action_button = QtWidgets.QPushButton(text)
		action_button.setEnabled(False)

		progress_bar = QtWidgets.QProgressBar()
		progress_bar.setRange(0, 100)
		progress_bar.setFormat(progress_text)
		progress_bar.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
		PrintProgress.callback = lambda progress: progress_bar.setValue(progress.percent)

		def callback_wrapper():
			self.setEnabled(False)
			progress_bar.setValue(0)
			self.layout().replaceWidget(action_button, progress_bar)
			action_button.setParent(None)
			QtWidgets.QApplication.processEvents()

			try:
				# TODO: do this in a separate thread
				callback(*self.parse_widgets(self.__widgets__))
				progress_bar.setValue(100)
			except Exception as e:
				self.show_message(str(e), QtWidgets.QMessageBox.Critical)
			else:
				self.show_message(complete_text, QtWidgets.QMessageBox.Information)
			finally:
				self.layout().replaceWidget(progress_bar, action_button)
				progress_bar.setParent(None)
				self.setEnabled(True)
				QtWidgets.QApplication.processEvents()

		action_button.clicked.connect(callback_wrapper)

		self.__widgets__.append(action_button)

		return action_button

	def update_action_button(self):
		self.__widgets__[-1].setEnabled(all([os.path.isfile(file_select.text()) for file_select in self.__required__]))


	def create_lineedit(self, text: str):
		line_edit = QtWidgets.QLineEdit()
		line_edit.setPlaceholderText(text)
		line_edit.textChanged.connect(self.update_action_button)
		line_edit.textChanged.connect(lambda: line_edit.setStyleSheet(line_edit.styleSheet()))
		line_edit.dropEvent = lambda event: line_edit.setText(unquote(urlparse(event.mimeData().text()).path))
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
		self.setLayout(grid_layout)

		return grid_layout

	def create_padding(self, padding: int):
		self.__widgets__ += [None] * padding


	def set_window_properties(self, title: str):
		WINDOWS_STYLESHEET = f""""""
		UNIX_STYLESHEET = f"""QLineEdit[text=""]{{color: {self.palette().windowText().color().name()};}}"""
		self.setWindowTitle(title)
		self.setStyleSheet(WINDOWS_STYLESHEET if sys.platform == "win32" else UNIX_STYLESHEET)
		self.setWindowFlag(QtCore.Qt.WindowType.WindowMaximizeButtonHint, False)
		self.setMaximumSize(1600, 0)
		self.resize(800, 0)

	def browse_files(self, line: QtWidgets.QLineEdit, caption, filter):
		if filepath := QtWidgets.QFileDialog.getOpenFileName(self, caption, "", filter)[0]:
			line.setText(filepath)

	def center_window(self):
		res = QtGui.QGuiApplication.primaryScreen().availableGeometry()
		self.move((res.width() - self.width()) // 2, (res.height() - self.height()) // 2)

	def show_message(self, text: str, icon):
			msg = QtWidgets.QMessageBox()
			msg.setWindowTitle(self.windowTitle())
			msg.setIcon(icon)
			msg.setText(text)
			msg.setStandardButtons(QtWidgets.QMessageBox.Ok.Ok)
			msg.exec()
			return msg


class GeneralGUI(StrindexGUI):
	def setup(self):
		self.create_button("Create", callback=CreateGUI)
		self.create_button("Patch", callback=PatchGUI)
		self.create_button("Update", callback=UpdateGUI)
		self.create_button("Filter", callback=FilterGUI)
		self.create_button("Delta", callback=DeltaGUI)
		if "__compiled__" not in globals():
			self.create_button("Spellcheck", callback=SpellcheckGUI)

		self.create_grid_layout(1)

		self.set_window_properties(title="Strindex GUI")

		self.resize(300, 0)

class CreateGUI(StrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file"),

		self.create_lineedit("Minimum length of strings")
		self.create_padding(1)

		self.create_lineedit("Prefix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424")
		self.create_padding(1)

		self.create_lineedit("Suffix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424")
		self.create_padding(1)

		self.create_checkbox("Force Mode")
		self.create_padding(1)

		self.create_checkbox("Compatible Mode")
		self.create_padding(1)

		self.create_action_button(
			text="Create strindex", progress_text="Creating... %p%", complete_text="Strindex created successfully.",
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

		self.set_window_properties(title="Strindex Create")

class PatchGUI(StrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file to patch")
		self.create_strindex_selection(line_text="*Select a strindex file")

		self.create_action_button(
			text="Patch file", progress_text="Patching... %p%", complete_text="File patched successfully.",
			callback=lambda file, strdex: patch(file, strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

		self.set_window_properties(title="Strindex Patch")

class UpdateGUI(StrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file to update from")
		self.create_strindex_selection(line_text="*Select a strindex file to update")

		self.create_action_button(
			text="Update strindex", progress_text="Updating... %p%", complete_text="Created an updated strindex successfully.",
			callback=lambda file, strdex: update(file, strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

		self.set_window_properties(title="Strindex Update")

class FilterGUI(StrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to filter")

		self.create_action_button(
			text="Filter strindex", progress_text="Filtering... %p%", complete_text="Created a filtered strindex successfully.",
			callback=lambda strdex: filter(strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

		self.set_window_properties(title="Strindex Filter")

class DeltaGUI(StrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to diff from")
		self.create_strindex_selection(line_text="*Select a strindex to diff against")

		self.create_action_button(
			text="Delta strindex", progress_text="Updating... %p%", complete_text="Created a delta strindex successfully.",
			callback=lambda strdex1, strdex2: delta(strdex1, strdex2, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

		self.set_window_properties(title="Strindex Delta")

class SpellcheckGUI(StrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to spellcheck")

		self.create_action_button(
			text="Spellcheck strindex", progress_text="Spellchecking... %p%", complete_text="Created a spellcheck file of a strindex successfully.",
			callback=lambda strdex: spellcheck(strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

		self.set_window_properties(title="Strindex Spellcheck")


def action_gui(action):
	match action:
		case "gui":
			GeneralGUI()
		case "create":
			CreateGUI()
		case "patch":
			PatchGUI()
		case "update":
			UpdateGUI()
		case "filter":
			FilterGUI()
		case "delta":
			DeltaGUI()
		case "spellcheck":
			SpellcheckGUI()
