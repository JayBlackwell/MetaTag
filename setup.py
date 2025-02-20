# setup.py
from setuptools import setup

# Adjust the path to your main Python file if it is not in the repo root
# For example, if it's at src/MetaTagBackoffGui.py, include that path:
APP = ['src/MetaTagBackoffGui.py']

# If you have any data files (images, icons, etc.) that you want bundled,
# list them here as tuples: (source_file, target_folder_inside_app)
DATA_FILES = [
    # Example of including an icon:
    # ('src/solsticelogo.ico', ''),
]

# Basic py2app options. You can add more if needed.
OPTIONS = {
    'argv_emulation': True,
    # If you have a .icns file for a macOS icon, you can add something like:
    # 'iconfile': 'src/solsticelogo.icns',
    #
    # If you rely on certain packages not automatically detected by py2app,
    # you can specify them in 'packages' or 'includes'.
    # 'packages': ['some_package'],
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)

