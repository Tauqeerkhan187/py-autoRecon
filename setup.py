# Author:TK
# Date: 24-04-2026
# Purpose: Define package metadata and installation settings so project can be installed and run as a python package.

from setuptools import setup, find_packages

setup(
    name="autorecon",
    version="1.0.0",
    author="TK",
    description="A modular Python-based automated reconnaissance toolkit",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "dnspython>=2.4.0",
        "python-whois>=0.9.4",
        "rich>=13.7.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "autorecon=autorecon.cli:main",
        ],
    },
)