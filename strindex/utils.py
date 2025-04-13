import os, sys, json, re, gzip, hashlib
from typing import Generator, Callable


class PrintProgress():
	"""
	Extremely fast class to print progress percentage.
	Only takes ~0.1 seconds every 1'000'000 calls,
	or half of that if "iteration >= self.limit" is checked within the loop.
	"""

	total: int
	limit: int
	delta: int
	round: int
	percent: float
	print_end: str

	def __init__(self, total: int, round: int = 0):
		self.total = total
		self.limit = 0
		self.delta = total // (10 ** (round + 2))
		self.round = None if round == 0 else round
		self.percent = 0
		self.print_end = "%" + " " * (round + 3) + "\r"
		self(0)

	def __call__(self, iteration: int):
		if iteration >= self.limit:
			self.limit += self.delta
			self.percent = round(iteration / self.total * 100, self.round)
			if callable(PrintProgress.callback):
				PrintProgress.callback(self)
			else:
				print(self.percent, end=self.print_end)

	@property
	def callback() -> Callable[["PrintProgress"], None]:
		return globals().get("__print_progress_callback__")

class StrindexSettings():
	# These are really limited, so I would really like if you added your language's characters here and open a pull request <3
	CHARACTER_CLASSES = {
		"default": """\t\n !"#$%&'()*+,-./0123456789:;<=>?@[\]^_`{|}~… """,
		"latin": """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz""",
		"spanish": """¡¿ÁÉÍÓÚÜÑáéíóúüñã""",
		"italian": """ÀÈÉÌÒÓÙàèéìòóù""",
		"cyrillic": """ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁ҂҃҄҅҆҇҈҉ҊҋҌҍҎҏҐґҒғҔҕҖҗҘҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸӹӺӻӼӽӾ""",
	}

	md5: str
	whitelist: set[str]
	min_length: int
	prefix_bytes: list[bytes]
	suffix_bytes: list[bytes]
	patch_replace: dict[str, str]
	clean_pattern: str
	source_language: str
	target_language: str
	among_languages: list[str]

	def __init__(self, **kwargs):
		self.md5 = kwargs.get("md5")
		self.whitelist = StrindexSettings.handle_whitelist(kwargs.get("whitelist"))
		self.min_length = int(kwargs.get("min_length") or 1)
		self.prefix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("prefix_bytes"))
		self.suffix_bytes = StrindexSettings.handle_bytes_list(kwargs.get("suffix_bytes"))
		self.patch_replace = kwargs.get("patch_replace") or {}
		self.clean_pattern = kwargs.get("clean_pattern") or ""
		self.source_language = kwargs.get("source_language")
		self.target_language = kwargs.get("target_language")
		self.among_languages = kwargs.get("among_languages") or []

	@staticmethod
	def handle_whitelist(whitelist: str) -> set[str]:
		return set(''.join([StrindexSettings.CHARACTER_CLASSES.get(whitelist, whitelist) for whitelist in (whitelist + ["default"])])) if whitelist else None

	@staticmethod
	def handle_bytes_list(bytes_list: list[bytes]) -> list[bytes]:
		return [bytes.fromhex(prefix) for prefix in (bytes_list or [''])]

	def clean_string(self, string: str) -> str:
		return re.sub(self.clean_pattern, "", string)

	def patch_replace_string(self, string: str) -> str:
		""" Replaces the strings in the patch with the new strings. """
		for key, value in self.patch_replace.items():
			string = string.replace(key, value)
		return string

class Strindex():
	""" A class to parse and create strindex files. """

	HEADER = f"You can freely create & delete informational lines in the header like this one.\n\n{{}}\n\n"
	INFO = f"//{'=' * 78}/pointer(s)/\n"
	COMPATIBLE_INFO = f"//{'=' * 78}| reallocate pointer(s) if 1 |\n// replace this string...\n//{'-' * 78}\n// ...with this string!\n"
	ORIGINAL_DEL = f"{'=' * 80}"
	REPLACE_DEL = f"{'-' * 80}"
	POINTERS_DEL = f'/'
	POINTERS_SWITCHES_DEL = f'|'

	full_header: str
	settings: StrindexSettings

	strings: list[str | list[str, str]]
	pointers: list[list[int | bool]]
	type_order: list[str]

	@property
	def get_overwrite(self) -> list[str]:
		return [string for string, type in zip(self.strings, self.type_order) if type == "overwrite"]
	@property
	def get_original(self) -> list[str]:
		return [string[0] for string, type in zip(self.strings, self.type_order) if type == "compatible"]
	@property
	def get_replace(self) -> list[str]:
		return [string[1] for string, type in zip(self.strings, self.type_order) if type == "compatible"]
	@property
	def get_offsets(self) -> list[list[int]]:
		return [pointers for pointers, type in zip(self.pointers, self.type_order) if type == "overwrite"]
	@property
	def get_switches(self) -> list[list[bool]]:
		return [pointers for pointers, type in zip(self.pointers, self.type_order) if type == "compatible"]

	@property
	def get_strings_flat_original(self) -> list[str]:
		return [(string[0] if type == "compatible" else string) for string, type in zip(self.strings, self.type_order)]
	@property
	def get_strings_flat_replace(self) -> list[str]:
		return [(string[1] if type == "compatible" else string) for string, type in zip(self.strings, self.type_order)]


	def __init__(self):
		""" Parses a strindex file and returns a dictionary with the data. """

		self.full_header = ""
		self.settings = StrindexSettings()

		self.strings = []
		self.pointers = []
		self.type_order = []


	@classmethod
	def read(cls, filepath: str) -> "Strindex":
		""" Parses a strindex file and returns a dictionary with the data. """

		strindex = cls()

		if filepath.endswith(".gz"):
			stream = gzip.open(filepath, 'rt', encoding='utf-8')
		else:
			stream = open(filepath, 'r', encoding='utf-8')

		with stream as f:
			previous_line_pos = 0
			while line := f.readline():
				if line.lstrip().startswith("{"):
					strindex_settings_lines = line
					strindex.full_header += line
					while True:
						try:
							strindex.settings = StrindexSettings(**json.loads(strindex_settings_lines))
						except json.JSONDecodeError as e:
							line = f.readline()
							if not line:
								raise ValueError("Error parsing Strindex settings.")
							strindex.full_header += line
							if line.lstrip().startswith("//"):
								continue
							if line.startswith(Strindex.ORIGINAL_DEL):
								raise ValueError("Error parsing Strindex settings: " + str(e))
							strindex_settings_lines += line
						else:
							break
				elif line.startswith(Strindex.ORIGINAL_DEL):
					f.seek(previous_line_pos)
					break
				else:
					previous_line_pos = f.tell()
					strindex.full_header += line

			next_str_type = ""
			is_start = True
			while line := f.readline():
				line = line.rstrip('\n')
				if line.startswith(Strindex.ORIGINAL_DEL):
					is_start = True
					line = line.lstrip(Strindex.ORIGINAL_DEL)

					if next_str_type == "original":
						strindex.strings[-1][1] = strindex.strings[-1][0]

					try:
						if Strindex.POINTERS_DEL in line:
							next_str_type = "overwrite"
							strindex.strings.append('')
							strindex.pointers.append([int(p, 16) for p in line.split(Strindex.POINTERS_DEL)[1:-1] if p])
							strindex.type_order.append("overwrite")
						else:
							next_str_type = "original"
							strindex.strings.append(['', ''])
							strindex.pointers.append([bool(int(p)) for p in line.strip(Strindex.POINTERS_SWITCHES_DEL) if p])
							strindex.type_order.append("compatible")
					except Exception:
						raise ValueError(f"Error parsing Strindex pointers: {line}")
				elif line == Strindex.REPLACE_DEL and next_str_type == "original":
					is_start = True
					next_str_type = "replace"
				else:
					if not is_start:
						line = "\n" + line
					is_start = False

					if next_str_type == "overwrite":
						strindex.strings[-1] += line
					elif next_str_type == "original":
						strindex.strings[-1][0] += line
					elif next_str_type == "replace":
						strindex.strings[-1][1] += line

		if strindex.strings[-1] == ['', '']:
			strindex.strings.pop()
			strindex.pointers.pop()
			strindex.type_order.pop()

		strindex.assert_data()

		return strindex

	def write(self, filepath: str):
		""" Saves the strindex data to a file. """
		HEX_RJUST = 8

		self.assert_data()

		diff_settings = {k: v for k, v in self.settings.__dict__.items() if Strindex().settings.__dict__.get(k) != v}

		with open(filepath, 'w', encoding='utf-8') as f:
			if self.full_header:
				f.write(self.full_header)
			else:
				f.write(Strindex.HEADER.format(json.dumps(diff_settings, indent=4, default=lambda x: x.hex() if isinstance(x, bytes) else str(x))))
				f.write(Strindex.COMPATIBLE_INFO if self.type_order[0] == "compatible" else Strindex.INFO)

			for strings, pointers, type in zip(self.strings, self.pointers, self.type_order):
				if type == "compatible":
					f.write(
						Strindex.ORIGINAL_DEL + Strindex.POINTERS_SWITCHES_DEL +
						"".join(str(int(bool(p))) for p in pointers) +
						Strindex.POINTERS_SWITCHES_DEL + "\n" +
						strings[0] + "\n" +
						Strindex.REPLACE_DEL + "\n" +
						strings[1] + "\n"
					)
				else:
					f.write(
						Strindex.ORIGINAL_DEL + Strindex.POINTERS_DEL +
						Strindex.POINTERS_DEL.join(hex(p or 0).lstrip("0x").rjust(HEX_RJUST, '0') for p in pointers) +
						Strindex.POINTERS_DEL + "\n" +
						strings + "\n"
					)

			f.seek(f.tell() - 1)
			f.truncate()

	def append_strindex_index(self, strindex: "Strindex", index: int):
		self.strings.append(strindex.strings[index])
		self.pointers.append(strindex.pointers[index])
		self.type_order.append(strindex.type_order[index])

	def assert_data(self):
		assert len(self.strings) == len(self.pointers) == len(self.type_order), f"Overwrite, pointers and type order lists are not the same length ({len(self.strings)} != {len(self.pointers)} != {len(self.type_order)})."

class FileBytearray(bytearray):
	""" A class to handle bytearrays with additional methods and shorthands focused on file manipulation. """
	cursor: int = 0
	byte_length: int
	byte_order: str


	# Algorithms
	def yield_strings(self, sep=b'\x00') -> Generator[tuple[str, int], None, None]:
		print_progress = PrintProgress(len(self))
		byte_string = b''
		for offset, char in enumerate(self):
			char = bytes([char])
			if char == sep:
				try:
					string = byte_string.decode('utf-8')
				except UnicodeDecodeError:
					continue
				else:
					yield string, offset - len(byte_string)
				finally:
					byte_string = b''
					print_progress(offset)
			else:
				byte_string += char

	def indices_ordered(self, search_lst: list[bytes], prefix: bytes = b"\x00", suffix: bytes = b"\x00") -> list[int]:
		"""
		Returns the index of the first occurrence of every search list string in a bytearray.
		Extremely fast, but can only can work for search lists that are ordered by occurrence order.
		"""
		search_lst = [bytes(search, 'utf-8') if isinstance(search, str) else search for search in search_lst]
		indices = []
		prefix_length = len(prefix)
		start_index = 0
		for search_index in range(len(search_lst)):
			index = self.find(prefix + search_lst[search_index] + suffix, start_index)
			if index == -1:
				indices.append(None)
				continue
			start_index = index + prefix_length + len(search_lst[search_index])
			indices.append(index + prefix_length)
		return indices

	def indices_fixed(self, search_lst: list[bytes], prefixes: list[bytes] = [b""], suffixes: list[bytes] = [b""]) -> list[list[int]]:
		"""
		Returns a list containing the indexes of each occurrence of every search list string in a bytearray.
		Extremely fast, but can only can work for unique search strings of fixed length (length is taken from 1st element).
		"""
		if not search_lst:
			return []

		search_lst_safe = [s for s in search_lst if s is not None]

		assert len(search_lst_safe) == len(set(search_lst_safe)), "Search list is not unique."
		assert all(len(search) == len(search_lst_safe[0]) for search in search_lst_safe), "Search list is not fixed length."
		assert all(len(prefix) == len(prefixes[0]) for prefix in prefixes), "Prefix list is not fixed length."

		fixed_prefix_length = len(prefixes[0])
		fixed_length = fixed_prefix_length + len(search_lst_safe[0]) + len(suffixes[0])

		indices_dict = {}
		for search_string in search_lst_safe:
			lst = []
			for prefix in prefixes:
				for suffix in suffixes:
					indices_dict[prefix + search_string + suffix] = lst

		print_progress = PrintProgress(len(self))
		for offset in range(len(self)):
			cur_bytes = bytes(self[offset:offset + fixed_length])
			if cur_bytes in indices_dict:
				indices_dict[cur_bytes].append(offset + fixed_prefix_length)
			if offset >= print_progress.limit:
				print_progress(offset)

		indices = list(indices_dict.values())[::len(prefixes) * len(suffixes)]
		for search_index, search_string in enumerate(search_lst):
			if search_string is None:
				indices.insert(search_index, search_string)

		return indices


	# Shorthands
	def get(self, byte_length: int = None) -> bytes:
		byte_slice = self[self.cursor:self.cursor + (byte_length or self.byte_length)]
		self.cursor += byte_length or self.byte_length
		return bytes(byte_slice)

	def get_del(self, delimiter: bytes = b'\x00') -> bytes:
		byte_string = b''
		while (char := self.get(1)) != delimiter:
			byte_string += char
		return byte_string

	def put(self, value: bytes, byte_length: int = None) -> bytes:
		if not isinstance(value, bytes):
			value = bytes(value, 'utf-8')
		if byte_length is None:
			byte_length = len(value)
		self[self.cursor:self.cursor + byte_length] = value
		self.cursor += byte_length
		return value

	def get_int(self, byte_length: int = None, byte_order: str = None) -> int:
		return int.from_bytes(self.get(byte_length), byte_order or self.byte_order)

	def put_int(self, value: int, byte_length: int = None, byte_order: str = None) -> bytes:
		self[self.cursor:self.cursor + (byte_length or self.byte_length)] = self.from_int(value, byte_length, byte_order)
		return self.get(byte_length)

	def from_int(self, value: int, byte_length: int = None, byte_order: str = None) -> bytes:
		return value.to_bytes(byte_length or self.byte_length, byte_order or self.byte_order)

	def add_int(self, delta: int, byte_length: int = None, byte_order: str = None) -> bytes:
		value = self.get_int(byte_length, byte_order)
		self.cursor -= byte_length or self.byte_length
		return self.put_int(value + delta, byte_length, byte_order)


	# Macros
	def create_pointers_macro(self, settings: StrindexSettings, original_bytes_from_offset: Callable[[int], bytes]) -> Strindex:
		temp_strindex = {
			"original": [],
			"offsets": [],
			"pointers": [],
			"original_bytes": []
		}

		for string, offset in self.yield_strings():
			if len(string) >= settings.min_length and (original_bytes := original_bytes_from_offset(offset)):
				temp_strindex["original"].append(string)
				temp_strindex["offsets"].append(offset)
				temp_strindex["original_bytes"].append(original_bytes)

		if not temp_strindex["original"]:
			raise ValueError("No strings found in the file.")
		print(f"(1/2) Created search dictionary with {len(temp_strindex['original_bytes'])} strings.")

		temp_strindex["pointers"] = self.indices_fixed(temp_strindex["original_bytes"], settings.prefix_bytes, settings.suffix_bytes)

		strindex = Strindex()
		for string, offset, pointers in zip(temp_strindex["original"], temp_strindex["offsets"], temp_strindex["pointers"]):
			if pointers:
				strindex.strings.append(string)
				strindex.pointers.append(pointers)
				strindex.type_order.append("overwrite")

		print(f"(2/2) Found pointers for {len(strindex.strings)} / {len(temp_strindex['original'])} strings.")

		return strindex

	def patch_pointers_macro(self, strindex: Strindex, original_bytes_from_offset: Callable[[int], bytes], replaced_bytes_from_offset: Callable[[int], bytes], data_from_string: Callable[[str], bytearray]) -> bytearray:
		def data_from_string_wrapper(string: str) -> bytearray:
			return data_from_string(strindex.settings.patch_replace_string(string))

		new_data = bytearray()

		update_dict = {
			"original_bytes": [],
			"replaced_bytes": [],
			"pointers": [],
			"switches": []
		}

		strindex_original = strindex.get_original
		strindex_replace = strindex.get_replace
		strindex_switches = strindex.get_switches

		for index, offset in enumerate(self.indices_ordered(strindex_original)):
			if offset is None:
				print(f'String not found: "{strindex_original[index]}"')
				continue

			update_dict["original_bytes"].append(original_bytes_from_offset(offset))
			update_dict["replaced_bytes"].append(replaced_bytes_from_offset(len(new_data)))
			update_dict["switches"].append(strindex_switches[index])
			new_data += data_from_string_wrapper(strindex_replace[index])

		update_dict["pointers"] = self.indices_fixed(update_dict["original_bytes"], strindex.settings.prefix_bytes, strindex.settings.suffix_bytes)

		self.update_references(update_dict["pointers"], update_dict["replaced_bytes"], update_dict["switches"])

		update_dict = {
			"replaced_bytes": []
		}

		for overwrite in strindex.get_overwrite:
			update_dict["replaced_bytes"].append(replaced_bytes_from_offset(len(new_data)))
			new_data += data_from_string_wrapper(overwrite)

		self.update_references(strindex.get_offsets, update_dict["replaced_bytes"])

		return new_data

	def update_references(self, pointers: list[list[int]], replaced_bytes: list[bytes], switches: list[list[bool]] = None):
		if	switches is None:
			switches = [[True] * len(pointer) for pointer in pointers]

		for index, (pointers, replaced_bytes, switches) in enumerate(zip(pointers, replaced_bytes, switches)):
			if pointers:
				for pointer, switch in zip(pointers, switches):
					if switch:
						self[pointer:pointer+self.byte_length] = replaced_bytes
			else:
				print(f"No pointers found for line n.{index + 1}")


	@property
	def md5(self) -> str:
		return hashlib.md5(self).hexdigest()


try:
	from PySide6 import QtWidgets, QtGui, QtCore
except ImportError:
	pass
else:
	class StrindexGUI(QtWidgets.QWidget):
		__required__: list[QtWidgets.QWidget]
		__widgets__: list[QtWidgets.QWidget]

		def __init__(self):
			super().__init__()
			self.__required__ = []
			self.__widgets__ = []

		@staticmethod
		def execute(gui_cls):
			app = QtWidgets.QApplication([])
			gui = gui_cls()
			gui.setup()
			gui.show()
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
			self.center_window()

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
