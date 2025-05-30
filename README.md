# strindex
[![PyPI version](https://img.shields.io/pypi/v/strindex?label=PyPI%20version)](https://pypi.org/project/strindex/)
[![PyPI downloads](https://img.shields.io/pypi/dm/strindex?label=PyPI%20downloads)](https://pypi.org/project/strindex/)
[![GitHub downloads](https://img.shields.io/github/downloads/zWolfrost/strindex/total?label=GitHub%20downloads)](https://github.com/zWolfrost/strindex/releases/latest)
[![license](https://img.shields.io/github/license/zWolfrost/strindex)](LICENSE)

A command line utility to extract and patch strings of some filetypes, with a focus on compatibility and translation.

This utility will allow you to replace strings in supported filetypes with other strings. It's useful to change the text of a program without having to recompile it, for example, to translate a program into another language.

Aside from using pointers to replace strings, there's also an option to use the original string itself to ensure compatibility with different versions of the same program.

It features various built-in features to help with translation, such as spellchecking & filtering strings by length and character set.

## Supported filetypes
*Support for more types is not planned.*
- PE files (".exe", ".dll"...) *(direct pointers only)*
- Gamemaker data files ("data.win")
- Forceful replacement in every filetype...

## Installation
You can install the program with the command `pip install strindex`.

Alternatively, the releases tab includes a precompiled version of the program, which by default opens the gui mode (unless executed with arguments). Warning: the precompiled version has a high chance of being detected as a **false positive** by antivirus software. You can compile the program yourself to avoid this.<br>Also, the apt package `libxcb-cursor0` is **required** for the linux build.

## Usage
You can run the program with the command `strindex <action> <input file(s)> [arguments]`.

`strindex -h` will show the available arguments.

These are the available actions:
- `create`: Create a list of strings (a strindex) extracted from a file. Use `-f` to enable "force" mode, and replace strings at the same offset they were found. Use `-c` to create a strindex that uses the original strings as references, instead of pointers.
- `patch`: Patch a file with a strindex. Strindexes compressed with gzip are also supported for all actions.
- `update` Update a strindex file pointers' with the updated version of a file.
- `filter`: Filter a strindex by detected language, wordlist or length. You can specify those in the strindex settings.
- `delta`: Create a delta file between two strindexes, that only contains the lines of the first strindex missing in the second one (their difference).
- `spellcheck`: Spellcheck a strindex. You can specify the target language in the strindex settings as an ISO 639-1 code.
- `gui`: Open Strindex in GUI mode.

## Usage Examples
- Open strindex in GUI mode:
  ```sh
  strindex gui
  ```
- Create a strindex from a PE file, considering only pointers prefixed by the bytes "24c7442404" or "ec04c70424".
  ```sh
  strindex create program.exe -p "24c7442404" -p "ec04c70424"
  ```
- Patch a PE file with a strindex:
  ```sh
  strindex patch program.exe strindex.txt
  ```

## Strindex Example
You can find an example of a strindex file and an explanation of its settings [here](strindex_example.txt).
