import signal
import sys
from collections.abc import Callable
from pathlib import Path

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import QTimer

import strindex.core
from strindex.utils import Progress, Strindex, StrindexSettings


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
	_widgets: list[QtWidgets.QWidget]
	_required: list[QtWidgets.QWidget]
	_actions: list[QtWidgets.QWidget]
	_callback_worker: CallbackWorker

	def __init__(self):
		super().__init__()

		self._widgets = []
		self._required = []
		self._actions = []
		self._callback_worker = None

		self.setup()

	def setup(self):
		pass

	def closeEvent(self, event: QtGui.QCloseEvent):
		worker: CallbackWorker = self._callback_worker
		if worker is not None and worker.isRunning():
			reply = QtWidgets.QMessageBox.question(self, "Operation in progress", (
				"An operation is still running.\n"
				"Closing this window will terminate it and may leave files incomplete.\n"
				"Are you sure you want to exit?"
			))

			if reply == QtWidgets.QMessageBox.StandardButton.No:
				event.ignore()
				return

			worker.terminate()
			worker.wait()
		event.accept()

	@staticmethod
	def parse_widgets(args):
		parsed_args = []
		for arg in args:
			if isinstance(arg, QtWidgets.QLineEdit):
				parsed_args.append(arg.text())
			elif isinstance(arg, QtWidgets.QCheckBox):
				parsed_args.append(arg.isChecked())
			elif isinstance(arg, QtWidgets.QWidget) and arg.children():
				parsed_args.extend(BaseStrindexGUI.parse_widgets(arg.children()))
		return parsed_args

	def create_file_selection(self, line_text: str, button_text: str = "Browse files"):
		file_select = self.create_lineedit(line_text)
		file_browse = self.create_button(
			button_text,
			lambda: self.browse_files(file_select, "Select File", "All Files (*)")
		)

		self._required.append(file_select)

		return file_select, file_browse

	def create_strindex_selection(self, line_text: str, button_text: str = "Browse strindex"):
		strindex_select = self.create_lineedit(line_text)
		strindex_browse = self.create_button(
			button_text,
			lambda: self.browse_files(strindex_select, "Select Strindex", "Strindex Files (*.txt *.gz)")
		)

		self._required.append(strindex_select)

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
				return callback(*self.parse_widgets(self._widgets))

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
				self.window()._callback_worker = None
				QtWidgets.QApplication.processEvents()

			worker = CallbackWorker(callback_wrapper)
			self.window()._callback_worker = worker

			worker.sig_progress.connect(callback_progress)
			worker.sig_except.connect(callback_except)
			worker.sig_else.connect(callback_else)
			worker.start()

		action_button.clicked.connect(callback_worker_start)

		self._widgets.append(action_button)
		self._actions.append(action_button)

		return action_button

	def update_action_button(self):
		enabled = all(Path(file_select.text()).is_file() for file_select in self._required)
		for widget in self._actions:
			widget.setEnabled(enabled)

	def create_lineedit(self, text: str, tooltip: str | None = None) -> QtWidgets.QLineEdit:
		line_edit = QtWidgets.QLineEdit()
		line_edit.setPlaceholderText(text)
		if tooltip:
			line_edit.setToolTip(tooltip)
		line_edit.textChanged.connect(self.update_action_button)
		line_edit.textChanged.connect(lambda: line_edit.setStyleSheet(line_edit.styleSheet()))
		line_edit.dragEnterEvent = lambda e: e.acceptProposedAction() if e.mimeData().hasUrls() else e.ignore()
		line_edit.dropEvent = lambda e: line_edit.setText(e.mimeData().urls()[0].toLocalFile())
		line_edit.setFont(QtGui.QFont("monospace"))

		self._widgets.append(line_edit)

		return line_edit

	def create_button(self, text: str, callback: Callable) -> QtWidgets.QPushButton:
		button = QtWidgets.QPushButton(text)
		button.clicked.connect(callback)

		self._widgets.append(button)

		return button

	def create_hbox_widget(self, widgets: list[QtWidgets.QWidget]) -> QtWidgets.QWidget:
		hbox = QtWidgets.QHBoxLayout()
		for widget in widgets:
			hbox.addWidget(widget)
		hbox.setContentsMargins(0, 0, 0, 0)
		hbox.setSpacing(10)
		hbox.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)

		widget = QtWidgets.QWidget()
		widget.setLayout(hbox)

		self._widgets.append(widget)

		return widget

	def create_grid_layout(self, columns: int) -> QtWidgets.QGridLayout:
		widget_col_span = []
		i = 0
		while i < len(self._widgets):
			if self._widgets[i] is None:
				self._widgets.pop(i)
				widget_col_span[-1] += 1
			else:
				widget_col_span.append(1)
				i += 1

		i = 0
		grid_layout = QtWidgets.QGridLayout()
		for widget, col_span in zip(self._widgets, widget_col_span, strict=True):
			if widget is not None:
				grid_layout.addWidget(widget, i // columns, i % columns, 1, col_span)
				i += col_span

		grid_layout.setSpacing(10)
		for i in range(columns):
			grid_layout.setColumnMinimumWidth(i, 125)

		grid_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

		self.setLayout(grid_layout)

		return grid_layout

	def create_padding(self, padding: int):
		self._widgets += [None] * padding

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

			palette = self.app.palette()
			palette.setColor(QtGui.QPalette.ColorGroup.Inactive, QtGui.QPalette.ColorRole.Highlight, "")
			self.app.setPalette(palette)

			self.setStyleSheet(f"""QLineEdit{{padding: 3px; margin: 1px 0px;}}""") # noqa: F541
		else:
			self.setStyleSheet(f"""QLineEdit[text=""]{{color: {self.palette().windowText().color().name()};}}""")

	def set_custom_size(self):
		# 52 is the approx. height of the tab bar + other stuff
		height_hint = (
			self.tab_widget.currentWidget().sizeHint().height() + 52
			if hasattr(self, "tab_widget") else self.sizeHint().height()
		)

		self.setMinimumWidth(445)
		self.setMaximumWidth(1280)
		self.setFixedHeight(height_hint)

	def setup(self):
		self.tab_widget = QtWidgets.QTabWidget()

		gui_action_map: list[tuple[type[BaseStrindexGUI], Callable]] = [
			(CreateGUI, strindex.core.create),
			(PatchGUI, strindex.core.patch),
			(UpdateGUI, strindex.core.update),
			(InferGUI, strindex.core.infer),
			(FilterGUI, strindex.core.filter),
			(DeltaGUI, strindex.core.diff),
			(MergeGUI, strindex.core.merge)
		]

		if "__compiled__" not in globals():
			gui_action_map.append((SpellcheckGUI, strindex.core.spellcheck))

		for gui_class, function in gui_action_map:
			self.tab_widget.setTabToolTip(
				self.tab_widget.addTab(gui_class(), function.__name__.capitalize()),
				function.__doc__.strip().replace("\t", "")
			)

		version_label = QtWidgets.QLabel(
			f"<a href='https://github.com/zWolfrost/strindex'>v{strindex.core.VERSION}</a>"
			" - press F1 for help"
		)
		version_label.setOpenExternalLinks(True)
		version_label.setContentsMargins(3, 3, 3, 3)
		self.tab_widget.setCornerWidget(version_label, QtCore.Qt.Corner.TopRightCorner)
		self.tab_widget.currentChanged.connect(lambda _: QTimer.singleShot(0, self.set_custom_size))

		self._widgets.append(self.tab_widget)

		self.create_grid_layout(1)

		self.setWindowTitle("Strindex")

		# HACK
		ICON_BASE64 = (
			"iVBORw0KGgoAAAANSUhEUgAAAIAAAACAAgMAAAC+UIlYAAAADFBMVEX///+gn59lZWUwMDAr76IDAAAAAXRSTlMAQObYZgAAA0RJREFUeNq"
			"FlzFy2zAQRanxqHCVykfQEdLrCCz4Ac8wM0ifgkegL8FLOEWOQF0CVWoWSZMKhQpwI5AUIHAX9h9V9hvu4x9RXFRZvgDApSrmhCXfq0KO2F"
			"JXYg6IOYsAgB90yx9AFQb0tMTLQ4COtjhAukBLMVa4BEApM8AvYOghjpXxAsqCZt+ByYEJl92EMQfmnabVtItt8gn9HnB4yyYQSzbjJU2QZ"
			"6DjgMOjAvHMOCcFTUKGOikYCXBJAr0EeOQKPDjnClziDnw1MjDVd8fQwj/ZMjm2omVy9EqyvKyAXuixaHk0C91xwNYPPVpBwr2uwNKjU4Jl"
			"swAYqSDh1Qpsyj2xIN5EkDDSbWzAXJCw5+0ur70sMdUbYI0s4ertLq2WJfzrBjhECV4ElhJkiVlvACFK8CIUUVkCW0+bhOZNXQKQJKSmDi1"
			"lEgwIPZUlXAScEiVcvQJbCR4CcOopk2BAaLos4b9FQJbwTQCSxAQBGGkNOqIBPQNsAO4PBmA4QBQlPPYSc1MhwhidZk3oAEQJawh9GbAtet"
			"YEHgAHxCZEwEPLQAwMFUekJrrfHMiaGJUEpCbgMQpAakITOg4kCZhgUgQc0AeTIuChZpMkOEDQfiehcsB2V+QSOgfcOKN3Knv+7SMwEw2Zx"
			"By/kzFTJuE5cNVBgn3tU7xOTchAS0Ei/cyddoAz9CDh6+ooALbNHn8GRAkZ6ChKiMDU0yKRfsR0DtieooQMGIoSHNj+lySG+MqK8aAHCXCA"
			"sEokYBh3Em2S8E18r3KJIuCRmgjvZtYUwUQJV0uAVVHC3gBWBF3TC8yeA6BoF+i7xLoyYg9YjJsE4nqQxUOvEl7HBSPPgG6RuDYLcOIvImA"
			"MEq5Om9rfn+Hz/uv2md9HAKNtydZpTbKKrCaYGcajvwKAvq9JT2AATYEgxFWNATQAyquPFtIJOi57x5akBMc1z6q0kX68ss74ZOm9qk/W5q"
			"mJwDFJyNv/Qdo2/c0xBqa8/JePD6/siMMPB2wGn1CeMTQZcGSv/d1R7QntThHsKJdpejQ74DnXtPxUO2DMngzhQKoSMCTFFMCkAah4niPhC"
			"mdzi2XKPCDdwq6LmErOgR/cZeKtKscBXf6X/5/08YqTdxaKAAAAAElFTkSuQmCC"
		)
		icon = QtGui.QPixmap()
		icon.loadFromData(QtCore.QByteArray.fromBase64(ICON_BASE64.encode()), "PNG")
		self.setWindowIcon(icon)

		self.setWindowFlag(QtCore.Qt.WindowType.WindowMaximizeButtonHint, False)

		self.set_custom_appearance()

		self.resize(800, 0)

		self.tab_widget.currentChanged.emit(0)

	def keyPressEvent(self, event: QtGui.QKeyEvent):
		if event.key() == QtCore.Qt.Key.Key_F1:
			self.show_message(
				"Strindex is a program that allows you to easily "
				"extract, list and patch (replace) the strings embedded in a few filetypes.\n\n"
				"You can hover your mouse over most elements to see a tooltip explaining their purpose.",
				QtWidgets.QMessageBox.Icon.Information
			)


class CreateGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a binary file")

		self.create_lineedit(
			"(Optional) Minimum length of strings to extract (default: 3)",
			tooltip=StrindexSettings.get_doc("min_length")
		)
		self.create_padding(1)

		self.create_lineedit(
			"(Optional) Prefix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424",
			tooltip=StrindexSettings.get_doc("prefix_bytes")
		)
		self.create_padding(1)

		self.create_lineedit(
			"(Optional) Suffix bytes hex (comma-separated) e.g.: 24c7442404,ec04c70424",
			tooltip=StrindexSettings.get_doc("suffix_bytes")
		)
		self.create_padding(1)

		self.create_lineedit(
			"(Optional) Range offsets hex (comma-separated) e.g.: 018bc5ec:01a09fb1,00441078:0060e501",
			tooltip=StrindexSettings.get_doc("ranges")
		)
		self.create_padding(1)

		self.create_lineedit(
			"(Optional) Whitelisted character sets (comma-separated) e.g.: latin,cyrillic",
			tooltip=StrindexSettings.get_doc("whitelist")
		)
		self.create_button(text="Help", callback=lambda: self.show_message(strindex.core.help_whitelist()))

		chkbox_force = QtWidgets.QCheckBox("Force Mode")
		chkbox_force.setToolTip(StrindexSettings.get_doc("force_mode"))

		chkbox_dynamic = QtWidgets.QCheckBox("Dynamic Pointers")
		chkbox_dynamic.setToolTip(StrindexSettings.get_doc("_dynamic"))

		chkbox_reference = QtWidgets.QCheckBox("References")
		chkbox_reference.setToolTip(StrindexSettings.get_doc("_references"))

		chkbox_minimal = QtWidgets.QCheckBox("Minimal")
		chkbox_minimal.setToolTip(StrindexSettings.get_doc("_minimal"))

		self.create_hbox_widget([chkbox_force, chkbox_dynamic, chkbox_reference, chkbox_minimal])
		self.create_padding(1)

		self.create_action_button(
			text="Create strindex",
			progress_text="Creating... %p%",
			callback=lambda
				file, min_length, prefix, suffix, ranges, whitelists,
				force_mode, dynamic, reference, minimal:
			strindex.core.create(file, None, StrindexSettings(
				_dynamic = dynamic,
				_references = reference,
				_minimal = minimal,
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
		self.create_file_selection(line_text="*Select a binary file to patch")
		self.create_strindex_selection(line_text="*Select a strindex file to patch with")

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
		enabled = [Path(file_select.text()).is_file() for file_select in self._required]
		self._actions[0].setEnabled(all(enabled))
		self._actions[1].setEnabled(enabled[0])


class UpdateGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a binary file to update from")
		self.create_strindex_selection(line_text="*Select a strindex file to update")

		chkbox_fixed = QtWidgets.QCheckBox("Convert all to fixed")
		chkbox_fixed.setToolTip("Convert all of the dynamic pointers\nin the strindex to fixed ones.")

		chkbox_dynamic = QtWidgets.QCheckBox("Convert all to dynamic")
		chkbox_dynamic.setToolTip("Convert all of the fixed pointers\nin the strindex to dynamic ones.")

		self.create_hbox_widget([chkbox_fixed, chkbox_dynamic])

		self.create_padding(1)

		self.create_action_button(
			text="Update strindex",
			progress_text="Updating... %p%",
			callback=lambda file, strdex, fixed, dynamic:
			strindex.core.update(file, strdex, None, convert_type=(
				Strindex.Type.FIXED if fixed else Strindex.Type.DYNAMIC if dynamic else None
			))
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)

		def exclusive_checkbox(chkbox: QtWidgets.QCheckBox):
			if chkbox.isChecked():
				if chkbox is chkbox_fixed:
					chkbox_dynamic.setChecked(False)
				if chkbox is chkbox_dynamic:
					chkbox_fixed.setChecked(False)

		chkbox_fixed.stateChanged.connect(lambda _: exclusive_checkbox(chkbox_fixed))
		chkbox_dynamic.stateChanged.connect(lambda _: exclusive_checkbox(chkbox_dynamic))



class InferGUI(BaseStrindexGUI):
	def setup(self):
		self.create_file_selection(line_text="*Select a binary file to infer from")
		self.create_strindex_selection(line_text="*Select a strindex file to infer from")

		self.create_action_button(
			text="Infer information",
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
			callback=lambda strdex1, strdex2: strindex.core.diff(strdex1, strdex2, None)
		)
		self.create_padding(1)

		self.create_grid_layout(2).setColumnStretch(0, 1)


class MergeGUI(BaseStrindexGUI):
	def setup(self):
		self.create_strindex_selection(line_text="*Select a strindex to merge from")
		self.create_strindex_selection(line_text="*Select a strindex to merge into")

		self.create_action_button(
			text="Merge strindex",
			progress_text="Merging... %p%",
			callback=lambda strdex1, strdex2: strindex.core.merge(strdex1, strdex2, None)
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
