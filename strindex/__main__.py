# nuitka-project: --standalone
# nuitka-project: --onefile
# nuitka-project: --enable-plugin=pyside6
# nuitka-project: --nofollow-import-to=lingua
# nuitka-project: --nofollow-import-to=language_tool_python
# nuitka-project: --windows-console-mode=disable
# nuitka-project: --windows-icon-from-ico=icon.png

from sys import argv
from strindex.strindex import main

if __name__ == "__main__":
	if "__compiled__" in globals() and len(argv) <= 1:
		main(["patch", "-g", "-d"])
	else:
		main()