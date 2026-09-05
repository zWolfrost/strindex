# strindex
[![PyPI version](https://img.shields.io/pypi/v/strindex?label=PyPI%20version)](https://pypi.org/project/strindex/)
[![GitHub downloads](https://img.shields.io/github/downloads/zWolfrost/strindex/total?label=GitHub%20downloads)](https://github.com/zWolfrost/strindex/releases/latest)
[![license](https://img.shields.io/github/license/zWolfrost/strindex)](LICENSE)

A command line utility program (with GUI support) that allows you to easily extract, list and patch (replace) the strings embedded in a few filetypes.

It's useful to change the text of a program without having to recompile it; for example, to translate it into another language.

A string can be referenced not only by its pointer / offset, but also by the original string itself to ensure compatibility with different versions of the same program.

It features various built-in features to help with translation, such as spellchecking & filtering strings by length and character set.

## Supported filetypes
*Support for more filetypes is possible, but not planned*

- PE files (".exe", ".dll"...) *(direct pointers only!)*
- Gamemaker data files ("data.win")
- Unreal Engine localization files (".locres")
- Every filetype, if using force mode*...

**Force mode doesn't allow the replaced strings to be bigger in length than the original strings.*

## Installation
You can install the program with the command `pip install strindex`.

Alternatively, the [releases tab](https://github.com/zWolfrost/strindex/releases/latest) includes a precompiled version of the program, which by default opens in gui mode (unless executed with arguments). Warning: the precompiled version has a high chance of being detected as a **false positive** by antivirus software. You can compile the program yourself to avoid this.

## Usage
You can run the program with the command `strindex <action> <input file(s)> [arguments]`.

`strindex -h` will show more information about the available actions and arguments.

These are the available actions:
- `gui`: Open Strindex in GUI mode.
- `create`: Create a list of string replacement instructions (a strindex) extracted from a file. Use `-f` to enable "force" mode, and replace strings at the same offset they were found. Use `-C` to create a strindex that uses the original strings as references, instead of pointers.
- `patch`: Patch a file using a strindex. Strindex files compressed with gzip are also supported for all actions.
- `unpatch`: Unpatch a file that was patched with a strindex, using the backup file.
- `update` Update a strindex file pointers' with another version of a file.
- `infer`: List the most common bytes that can prefix or suffix a pointer in a file, as well as the most suitable range to use.
- `filter`: Filter a strindex by detected language, wordlist or length. You can specify those in the strindex settings.
- `diff`: Subtract the entries of a strindex file from another, creating a strindex file with their differences.
- `merge`: Merge two strindex files into one, prioritizing the first one in case of conflicts.
- `spellcheck`: Spellcheck a strindex, and write the results to a file. You can specify the target language in the strindex settings as an ISO 639-1 code.

## Usage Examples
- Open strindex in GUI mode:
  ```sh
  strindex gui
  ```
- Create a strindex from a PE file, considering only pointers prefixed by the bytes "24c7442404" or "ec04c70424".
  ```sh
  strindex create program.exe -p "24c7442404" -p "ec04c70424"
  ```
- Create a strindex from a PE file, considering only pointers in the range from 0x018bc5ec to 0x01a09fb1.
  ```sh
  strindex create program.exe -m 3 -r "018bc5ec:01a09fb1"
  ```
- Patch a PE file with a strindex:
  ```sh
  strindex patch program.exe strindex.txt
  ```

## Strindex Example
You can find an example of a strindex file and an explanation of its settings [here](strindex_example.txt).
