import signal
import sys
from collections.abc import Callable
from pathlib import Path

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import QTimer

import strindex.core
from strindex.utils import Progress, StrindexSettings


class CallbackWorker(QtCore.QThread):
	sig_progress = QtCore.Signal(Progress)
	sig_except = QtCore.Signal(Exception)
	sig_else = QtCore.Signal(object)

	def __init__(self, callback):
		super().__init__()
		self.callback = callback

	def run(self):
		Progress.global_callback = lambda progress: self.sig_progress.emit(progress)

		try:
			result = self.callback()
		except Exception as e: # noqa: BLE001
			self.sig_except.emit(e)
		else:
			self.sig_else.emit(result)


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

	def create_action_button(self, text: str, progress_text: str, callback: Callable) -> QtWidgets.QPushButton:
		action_button = QtWidgets.QPushButton(text)
		action_button.setEnabled(False)

		progress_bar = QtWidgets.QProgressBar()
		progress_bar.setRange(0, 100)
		progress_bar.setFormat(progress_text)
		progress_bar.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

		def callback_worker_start():
			self.window().setEnabled(False)
			progress_bar.setValue(0)
			self.layout().replaceWidget(action_button, progress_bar)
			action_button.setParent(None)
			QtWidgets.QApplication.processEvents()

			def callback_wrapper():
				return callback(*self.parse_widgets(self.__widgets__))

			def callback_progress(progress):
				progress_bar.setValue(progress.percent)

			def callback_except(e):
				self.show_message(str(e), QtWidgets.QMessageBox.Icon.Critical)
				callback_finally()

			def callback_else(result):
				progress_bar.setValue(100)
				self.show_message(str(result), QtWidgets.QMessageBox.Icon.Information)
				callback_finally()

			def callback_finally():
				self.layout().replaceWidget(progress_bar, action_button)
				progress_bar.setParent(None)
				self.window().setEnabled(True)
				QtWidgets.QApplication.processEvents()

			self.__callback_worker__ = CallbackWorker(callback_wrapper)
			self.__callback_worker__.sig_progress.connect(callback_progress)
			self.__callback_worker__.sig_except.connect(callback_except)
			self.__callback_worker__.sig_else.connect(callback_else)
			self.__callback_worker__.start()

		action_button.clicked.connect(callback_worker_start)

		self.__widgets__.append(action_button)
		self.__actions__.append(action_button)

		return action_button

	def update_action_button(self):
		enabled = all(Path(file_select.text()).is_file() for file_select in self.__required__)
		for widget in self.__actions__:
			widget.setEnabled(enabled)

	def create_lineedit(self, text: str) -> QtWidgets.QLineEdit:
		line_edit = QtWidgets.QLineEdit()
		line_edit.setPlaceholderText(text)
		line_edit.textChanged.connect(self.update_action_button)
		line_edit.textChanged.connect(lambda: line_edit.setStyleSheet(line_edit.styleSheet()))
		line_edit.dragEnterEvent = lambda event: event.accept() if event.mimeData().hasUrls() else event.ignore()
		line_edit.dropEvent = lambda event: line_edit.setText(event.mimeData().urls()[0].toLocalFile())
		line_edit.setFont(QtGui.QFont("monospace"))

		self.__widgets__.append(line_edit)

		return line_edit

	def create_button(self, text: str, callback: Callable) -> QtWidgets.QPushButton:
		button = QtWidgets.QPushButton(text)
		button.clicked.connect(callback)

		self.__widgets__.append(button)

		return button

	def create_checkbox(self, text: str) -> QtWidgets.QCheckBox:
		checkbox = QtWidgets.QCheckBox(text)
		checkbox.stateChanged.connect(self.update_action_button)

		self.__widgets__.append(checkbox)

		return checkbox

	def create_grid_layout(self, columns: int) -> QtWidgets.QGridLayout:
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
		for widget, col_span in zip(self.__widgets__, widget_col_span, strict=True):
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

	def show_message(self, text: str, icon = QtWidgets.QMessageBox.Icon.NoIcon) -> QtWidgets.QMessageBox:
		msg = QtWidgets.QMessageBox()
		msg.setWindowTitle(self.windowTitle())
		msg.setWindowIcon(self.windowIcon())
		msg.setIcon(icon)
		msg.setText(text)
		msg.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok)
		msg.exec()
		return msg


class MainStrindexGUI(BaseStrindexGUI):
	app: QtWidgets.QApplication

	def __init__(self):
		signal.signal(signal.SIGINT, signal.SIG_DFL)

		self.app = QtWidgets.QApplication([])
		self.app.setApplicationName("Strindex")
		self.app.setApplicationVersion(strindex.core.VERSION)
		self.app.setOrganizationName("zWolfrost")

		super().__init__()

		self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
		self.setFocus()
		self.show()
		self.center_window()

		sys.exit(self.app.exec())

	def set_custom_appearance(self):
		if sys.platform == "win32":
			self.app.setStyle("Fusion")
			self.setStyleSheet(f"""QLineEdit{{padding: 3px; margin: 1px 0px;}}""") # noqa: F541
		else:
			self.setStyleSheet(f"""QLineEdit[text=""]{{color: {self.palette().windowText().color().name()};}}""")

	def set_custom_size(self):
		# 52 is the approx. height of the tab bar + other stuff
		height_hint = (
			self.tab_widget.currentWidget().sizeHint().height() + 52
			if hasattr(self, "tab_widget") else self.sizeHint().height()
		)

		if sys.platform == "win32":
			self.setMinimumWidth(500)
			self.setMaximumWidth(1600)
			self.setFixedHeight(height_hint)
		else:
			self.setFixedSize(800, height_hint)

	def setup(self):
		self.tab_widget = QtWidgets.QTabWidget()

		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(CreateGUI(), "Create"),
			"Create a list of strings (a strindex) extracted from a file."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(PatchGUI(), "Patch"),
			"Patch a file with a strindex.\n"
			"Strindex files compressed with gzip are also supported for all actions."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(UpdateGUI(), "Update"),
			"Update a strindex file pointers' with the updated version of a file."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(InferGUI(), "Infer"),
			"List the most common bytes that can prefix or suffix a pointer in a file,\n"
			"as well as the most suitable range to use."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(FilterGUI(), "Filter"),
			"Filter a strindex by detected language, wordlist or length.\n"
			"You can specify those in the strindex settings."
		)
		self.tab_widget.setTabToolTip(
			self.tab_widget.addTab(DeltaGUI(), "Delta"),
			"Create a delta file between two strindex files,\n"
			"that only contains the lines of the first strindex missing in the second one (their difference)."
		)
		if "__compiled__" not in globals():
			self.tab_widget.setTabToolTip(
				self.tab_widget.addTab(SpellcheckGUI(), "Spellcheck"),
				"Spellcheck a strindex.\n"
				"You can specify the target language in the strindex settings as an ISO 639-1 code."
			)

		version_label = QtWidgets.QLabel(f"<a href='https://github.com/zWolfrost/strindex'>v{strindex.core.VERSION}</a>")
		version_label.setOpenExternalLinks(True)
		version_label.setContentsMargins(3, 3, 3, 3)
		self.tab_widget.setCornerWidget(version_label, QtCore.Qt.Corner.TopRightCorner)
		self.tab_widget.currentChanged.connect(lambda _: QTimer.singleShot(0, self.set_custom_size))

		self.__widgets__.append(self.tab_widget)

		self.create_grid_layout(1)

		self.setWindowTitle("Strindex")

		# Horrible implementation, but really convenient for now...
		ICON_BASE64 = (
			"iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAAJ1BMVEUAAAAsLCwtLS0xMTEwMDAwMDAwMDAwMDCgoKCEhIRoaGhM"
			"TEwwMDBxvs7nAAAACHRSTlMAHSI/X3+fv7k/LJQAAAEzSURBVHjandfRqoMwEIThadPUrc77P++5sMMRdbvJ/BcWKvslRBBEHg9h"
			"NioLWZjU7cWpFlS9WdT85RXyXhzqaS+vFn9e+fPKn1fZ/Gaew0vzEd4WqMITqEzhTUt4QpGecJqPaaEL0Ni0oPeHLTRtwBYE2ILm"
			"baELsAUBriDAFwAyEyIGhA7eCfoZEMBbQYyEcUCCJksBzAS9oT4OwOMGPjENSNh0GpOAhH1ewhygk+QWEgrAfppg3oesBbCoEDpQ"
			"AytzASMAKcEGJLhALnTUQvwSMABsqSCg+wL26AoCFlYlQsM3jghxFaDamBAnAf+Rg8R2FHAV1ojQlZdr7K3f/3DsUQP7fUUmXylV"
			"QthwinMtUKaAm4z13XNoyPK3r/x59fDHVfe/GlUrV7e20TFbHxr+A+p/klbae1dWAAAAAElFTkSuQmCC"
		)
		icon = QtGui.QPixmap()
		icon.loadFromData(QtCore.QByteArray.fromBase64(ICON_BASE64.encode()), "PNG")
		self.setWindowIcon(icon)

		self.setWindowFlag(QtCore.Qt.WindowType.WindowMaximizeButtonHint, False)

		self.set_custom_appearance()

		self.resize(800, 0)

		self.tab_widget.currentChanged.emit(0)


class CreateGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file")

		self.create_lineedit("(Optional) Minimum length of strings to extract (default: 3)")
		self.create_padding(1)

		self.create_lineedit("(Optional) Prefix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424")
		self.create_padding(1)

		self.create_lineedit("(Optional) Suffix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424")
		self.create_padding(1)

		self.create_lineedit("(Optional) Range offsets hex (comma-separated) e.g.: 018bc5ec:01a09fb1,00441078:0060e501")
		self.create_padding(1)

		self.create_lineedit("(Optional) Whitelisted character sets (comma-separated) e.g.: latin,cyrillic")
		self.create_button(text="Help", callback=lambda: self.show_message(strindex.core.help_whitelist()))

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
			callback=lambda file, min_length, prefix, suffix, ranges, whitelists, force_mode, compatible:
			strindex.core.create(file, None, StrindexSettings(
				_compatible = compatible,
				force_mode = force_mode,
				min_length = min_length if min_length else 3,
				prefix_bytes = prefix.split(",") if prefix else [],
				suffix_bytes = suffix.split(",") if suffix else [],
				ranges = ranges.split(",") if ranges else [],
				whitelist = whitelists.split(",") if whitelists else []
			))
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
			callback=lambda file, strdex: strindex.core.patch(file, strdex, None)
		)

		self.create_action_button(
			text="Unpatch file",
			progress_text="Unpatching... %p%",
			callback=lambda file, _: strindex.core.unpatch(file)
		)

		self.create_grid_layout(2).setColumnStretch(0, 1)

	def update_action_button(self):
		enabled = [Path(file_select.text()).is_file() for file_select in self.__required__]
		self.__actions__[0].setEnabled(all(enabled))
		self.__actions__[1].setEnabled(enabled[0])


class UpdateGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file to update from")
		self.create_strindex_selection(line_text="*Select a strindex file to update")

		chkbox_overwrite = self.create_checkbox("Convert to overwrite")
		chkbox_overwrite.setToolTip("Convert all of the strindex entries to overwrite ones")
		self.create_padding(1)

		chkbox_compatible = self.create_checkbox("Convert to compatible")
		chkbox_compatible.setToolTip("Convert all of the strindex entries to compatible ones")
		self.create_padding(1)

		self.create_action_button(
			text="Update strindex",
			progress_text="Updating... %p%",
			callback=lambda file, strdex, overwrite, compatible:
			strindex.core.update(file, strdex, None, convert_type=(
				"overwrite" if overwrite else "compatible" if compatible else None
			))
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

		def exclusive_checkbox(chkbox: QtWidgets.QCheckBox):
			if chkbox.isChecked():
				if chkbox is chkbox_overwrite:
					chkbox_compatible.setChecked(False)
				if chkbox is chkbox_compatible:
					chkbox_overwrite.setChecked(False)

		chkbox_overwrite.stateChanged.connect(lambda _: exclusive_checkbox(chkbox_overwrite))
		chkbox_compatible.stateChanged.connect(lambda _: exclusive_checkbox(chkbox_compatible))



class InferGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a file to infer from")
		self.create_strindex_selection(line_text="*Select a strindex file to infer from")

		self.create_action_button(
			text="Infer",
			progress_text="Inferring... %p%",
			callback=lambda file, strdex: strindex.core.infer(file, strdex)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)


class FilterGUI(BaseStrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to filter")

		self.create_action_button(
			text="Filter strindex",
			progress_text="Filtering... %p%",
			callback=lambda strdex: strindex.core.filter(strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)


class DeltaGUI(BaseStrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to diff from")
		self.create_strindex_selection(line_text="*Select a strindex to diff against")

		self.create_action_button(
			text="Delta strindex",
			progress_text="Subtracting... %p%",
			callback=lambda strdex1, strdex2: strindex.core.delta(strdex1, strdex2, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)


class SpellcheckGUI(BaseStrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to spellcheck")

		self.create_action_button(
			text="Spellcheck strindex",
			progress_text="Spellchecking... %p%",
			callback=lambda strdex: strindex.core.spellcheck(strdex, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)
