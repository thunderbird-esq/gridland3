# In gridland/setup.py

from setuptools import setup, find_packages
from pathlib import Path

# The root of the project is one level up from this file's directory
# This allows the script to be run from anywhere
PROJECT_ROOT = Path(__file__).parent.parent
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"

def get_requirements():
    """Reads the requirements.txt file and returns a list of dependencies."""
    if not REQUIREMENTS_FILE.is_file():
        return []
    with open(REQUIREMENTS_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='gridland',
    version='3.0.0',
    packages=find_packages(),
    include_package_data=True,
    # This is the critical line. It tells pip what to install.
    install_requires=get_requirements(),
    entry_points={
        'console_scripts': [
            'gridland=gridland.cli.main:main',
        ],
    },
    python_requires='>=3.8',
    description='GRIDLAND: A comprehensive network device analysis toolkit.',
    long_description=(PROJECT_ROOT / "README.md").read_text(),
    long_description_content_type='text/markdown',
    author='Jules',
    url='https://github.com/thunderbird-esq/gridland3',
)