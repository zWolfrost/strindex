# strindex
A variant of the program "exestringz" written in Python, which focuses on compatibility and translation.

This program will allow you to replace strings in PE files (".exe", ".dll" etc.) with other strings. It is useful for changing the text of a program without having to recompile it, for example, to translate a program into another language.

Apart from using offsets to replace strings, it also has an option to use the original string itself to ensure compatibility with different versions of the same program.

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

## Usage
There are four available actions:
- `create`: Create a list of strings from a PE file (a strindex). Use `-c` to create a strindex that uses the original strings.
- `patch`: Patch a PE file with a strindex.
- `filter`: Filter a strindex by detected language and delete strings already present in another strindex (as a blacklist).
- `spellcheck`: Spellcheck a strindex. Use `-l` to specify the language (ISO 639-1 code).

You can run the program with the command `python strindex.py -h` to show all available arguments.

## Examples
- Create a strindex from a PE file:
  ```
  python strindex.py create program.exe -o strindex.txt -w latin
  ```
- Patch a PE file with a strindex:
  ```
  python strindex.py patch program.exe strindex.txt
  ```