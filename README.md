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
- `create`: Create a list of strings from a PE file (a strindex). Use `-c` to create a strindex that uses the original strings as references.
- `patch`: Patch a PE file with a strindex.
- `filter`: Filter a strindex by detected language, wordlist or length. You can specify those in the strindex settings.
- `update`: Update a strindex pointers to match the new ones of a file, useful for when the file is modified (e.g. update)
- `delta`: Create a delta file between two strindexes, that only contains the lines of the first strindex missing in the second one.
- `spellcheck`: Spellcheck a strindex. You can specify the target language in the strindex settings as an ISO 639-1 code.

You can run the program with the command `python strindex.py -h` to show all available arguments.

## Usage Examples
- Create a strindex from a PE file:
  ```sh
  python strindex.py create program.exe -o strindex.txt
  ```
- Patch a PE file with a strindex:
  ```sh
  python strindex.py patch program.exe strindex.txt
  ```

## Strindex Settings example
```json
{
    "md5": "29ed1f9e450d43815c2d1a0cab168da3",

    "prefix_bytes": ["24c7442404", "ec04c70424"],

    "patch_replace": {
        "ì": "í",
        "Ì": "Í",
        "ò": "ó",
        "Ò": "Ó"
    },

    "clean_pattern": "\\[.*?\\]|\\*",
    "whitelist": ["latin", "spanish", "cyrillic"],

    "source_language": "es",
    "target_language": "it",
    "among_languages": ["en", "ja", "ko", "de", "fr", "es", "pt", "ru", "zh"]
}
```