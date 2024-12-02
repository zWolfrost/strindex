# strindex
[![PyPI version](https://img.shields.io/pypi/v/strindex?label=PyPI%20version)](https://pypi.org/project/strindex/)
[![PyPI downloads](https://img.shields.io/pypi/dm/strindex?label=PyPI%20downloads)](https://pypi.org/project/strindex/)
[![GitHub downloads](https://img.shields.io/github/downloads/zWolfrost/strindex/total?label=GitHub%20downloads)](https://github.com/zWolfrost/strindex/releases/latest)
[![license](https://img.shields.io/github/license/zWolfrost/strindex)](LICENSE)

A command line utility to extract and patch strings of some filetypes, with a focus on compatibility and translation.

This utility will allow you to replace strings in supported filetypes with other strings. It's useful to change the text of a program without having to recompile it, for example, to translate a program into another language.

Apart from using offsets to replace strings, there's also an option to use the original string itself to ensure compatibility with different versions of the same program.

There are a lot of features to help with translation, such as spellchecking & filtering strings by length and character set.

The release includes a precompiled version of the program, which by default does the patching (unless executed with arguments). Warning: the precompiled version has a high chance of being detected as a false positive by antivirus software. You can compile the program yourself to avoid this.

## Supported filetypes
*Support for more types is not planned.*
- PE files (".exe, ".dll"...)
- Gamemaker data files ("data.win")

## Installation
You can install the program with the command `pip install strindex`.

## Usage
You can run the program with the command `strindex <action> <input file(s)> [options]`.

You can run `strindex -h` to see the available arguments.

These are the available actions:
- `create`: Create a list of strings from a PE file (a strindex). Use `-c` to create a strindex that uses the original strings as references.
- `patch`: Patch a PE file with a strindex. Strindexes compressed with gzip are also supported for all actions.
- `update` Update a strindex pointers' with the updated version of a file.
- `filter`: Filter a strindex by detected language, wordlist or length. You can specify those in the strindex settings.
- `delta`: Create a delta file between two strindexes, that only contains the lines of the first strindex missing in the second one.
- `spellcheck`: Spellcheck a strindex. You can specify the target language in the strindex settings as an ISO 639-1 code.

## Usage Examples
- Create a strindex from a PE file:
  ```sh
  strindex create program.exe -o strindex.txt
  ```
- Patch a PE file with a strindex:
  ```sh
  strindex patch program.exe strindex.txt
  ```

## Strindex Example
You can find an example of a strindex file and an explanation of its settings [here](strindex_example.txt).