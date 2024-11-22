python3 -m nuitka strindex/strindex.py \
	--standalone --onefile \
	--windows-console-mode=disable \
	--windows-icon-from-ico=icon.png \
	--enable-plugin=pyside6 \
	--nofollow-import-to=lingua \
	--nofollow-import-to=language_tool_python