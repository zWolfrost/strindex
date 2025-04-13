import os
from setuptools import setup

setup(
	name = "strindex",
	version = "3.6.0",
	author = "zWolfrost",
	author_email = "zwolfrost@gmail.com",
	description = "A command line utility to extract and patch strings of some filetypes, with a focus on compatibility and translation.",
	long_description = open(os.path.join(os.path.dirname(__file__), "README.md")).read(),
	long_description_content_type = "text/markdown",
	license = "MIT",
	keywords = "PE strings patching translation",
	url = "https://github.com/zWolfrost/strindex",
	packages = ["strindex", "strindex.filetypes"],
	install_requires=[
		"pefile>=2024.8.26",
	],
	extras_require = {
		"filter_language": ["lingua-language-detector"],
		"spellcheck": ["language-tool-python"],
		"patch_gui": ["pyside6"],
	},
	classifiers = [
		"Development Status :: 5 - Production/Stable",
		"Topic :: Utilities",
		"License :: OSI Approved :: MIT License",
	],
	entry_points = {
		"console_scripts": [
			"strindex = strindex.strindex:main",
		],
	},
)
