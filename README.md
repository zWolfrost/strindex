# strindex
A variant of the program "exestringz" written in Python, which focuses on compatibility.

This program will allow you to replace strings in PE files (".exe", ".dll" etc.) with other strings. It is useful for changing the text of a program without having to recompile it, for example, to translate a program into another language.

Instead of using offsets to replace strings, it uses the original string itself to ensure compatibility with different versions of the same program.

It also has a lot of features to help with translation, such as spellchecking & filtering strings by length and character set.

The release includes a precompiled version of the program, which ONLY does the patching. If you want to use the other features, you will need to install Python 3.6 or later and the required libraries.

## Requirements
You can install the required libraries with the command `pip install [library name]`.

**Required**:
- Python 3.6 or later.
- `pefile` library.

**Optional**:
- `lingua` library for filtering by detected language.
- `language-tool-python` library for spellchecking.
