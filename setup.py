from setuptools import setup, find_packages
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"

def get_requirements():
    if not REQUIREMENTS_FILE.is_file(): return []
    with open(REQUIREMENTS_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='gridland',
    version='3.0.0',
    # --- THIS IS THE FIX ---
    # Tell setuptools that our package lives in the 'src' directory
    package_dir={'': 'src'},
    # find_packages() will now look inside 'src' to find 'gridland'
    packages=find_packages(where='src'),
    # --- END OF FIX ---
    include_package_data=True,
    install_requires=get_requirements(),
    entry_points={'console_scripts': ['gridland=main:main']},
    python_requires='>=3.8',
    # ... other metadata ...
)