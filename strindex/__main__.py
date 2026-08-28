# nuitka-project: --product-name=strindex
# nuitka-project: --product-version=5.0.0

# nuitka-project: --mode=app

# nuitka-project: --enable-plugin=pyside6

# nuitka-project: --noinclude-qt-plugins=iconengines
# nuitka-project: --noinclude-qt-plugins=imageformats
# nuitka-project: --noinclude-qt-plugins=platformthemes
# nuitka-project: --noinclude-qt-plugins=printsupport
# nuitka-project: --noinclude-qt-plugins=tls
# nuitka-project: --noinclude-qt-plugins=webview

# nuitka-project: --noinclude-dlls=libQt6Network*
# nuitka-project: --noinclude-dlls=libQt6OpenGL*
# nuitka-project: --noinclude-dlls=libQt6Svg*

# nuitka-project: --nofollow-import-to=lingua
# nuitka-project: --nofollow-import-to=language_tool_python

# nuitka-project: --windows-console-mode=hide
# nuitka-project: --windows-icon-from-ico=icon.png
# nuitka-project: --linux-icon=icon.png

import sys

from strindex import strindex

if __name__ == "__main__":
	if "__compiled__" in globals() and len(sys.argv) <= 1:
		strindex.main(["gui", "--verbose"])
	else:
		strindex.main()
