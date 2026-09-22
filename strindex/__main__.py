# nuitka-project: --product-name=strindex
# nuitka-project-set: STRINDEX_VERSION = __import__("strindex").__version__
# nuitka-project: --product-version={STRINDEX_VERSION}

# nuitka-project: --mode=app

# nuitka-project: --enable-plugin=pyside6
# nuitka-project: --noinclude-qt-plugins=egldeviceintegrations,iconengines,imageformats
# nuitka-project: --noinclude-qt-plugins=platformthemes,printsupport,tls,webview,xcbglintegrations
# nuitka-project: --noinclude-dlls=libQt6Network*
# nuitka-project: --noinclude-dlls=libQt6OpenGL*
# nuitka-project: --noinclude-dlls=libQt6Svg*
# nuitka-project: --noinclude-dlls=libQt6EglFS*

# nuitka-project: --nofollow-import-to=_hashlib
# nuitka-project: --noinclude-dlls=libcrypto*
# nuitka-project: --noinclude-dlls=libssl*

# nuitka-project: --nofollow-import-to=lingua
# nuitka-project: --nofollow-import-to=language_tool_python

# nuitka-project: --windows-console-mode=hide
# nuitka-project: --windows-icon-from-ico=assets/icon.ico
# nuitka-project: --linux-app-console-mode=disable
# nuitka-project: --linux-app-icon=assets/icon.png

import sys

from strindex.core import main

if __name__ == "__main__":
	if "__compiled__" in globals() and len(sys.argv) <= 1:
		main(["gui", "--verbose"])
	else:
		main()
