"""
Setup script for GRIDLAND - Professional Camera Reconnaissance Toolkit
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open('README.md', 'r', encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='gridland',
    version='3.0.0',
    author='Security Research Team',
    author_email='security@gridland.dev',
    description='Professional camera reconnaissance toolkit for authorized security testing',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/gridland/gridland',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: System :: Networking :: Monitoring',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
        'Environment :: Console',
    ],
    python_requires='>=3.8',
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'gl-discover=gridland.cli.discover_cli:discover',
            'gl-analyze=gridland.cli.analyze_cli:analyze',
            'gl-stream=gridland.cli.stream_cli:stream',
            'gridland=gridland.cli.main:main',
        ],
    },
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'black>=22.0.0',
            'flake8>=4.0.0',
            'mypy>=0.991',
        ],
        'docs': [
            'sphinx>=4.0.0',
            'sphinx-rtd-theme>=1.0.0',
        ],
    },
    include_package_data=True,
    package_data={
        'gridland': [
            'data/*.json',
            'data/*.txt',
        ],
    },
    keywords='security reconnaissance camera cctv penetration-testing',
    project_urls={
        'Bug Reports': 'https://github.com/gridland/gridland/issues',
        'Source': 'https://github.com/gridland/gridland',
        'Documentation': 'https://gridland.readthedocs.io/',
    },
)