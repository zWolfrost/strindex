rm -rf build
rm -rf dist
python3 -m build
python3 -m twine upload dist/*.tar.gz