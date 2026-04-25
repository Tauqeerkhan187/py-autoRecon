from setuptools import setup, find_packages

setup(
    name="py-autorecon-tk",
    version="1.0.0",
    author="TK",
    author_email="tauqeerkhan1888@gmail.com",
    description="A modular Python-based automated reconnaissance toolkit",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Tauqeerkhan187/py-autoRecon",
    packages=find_packages(exclude=["tests*"]),
    package_data={
        "autorecon": [
            "wordlists/*.txt",
            "reporting/templates/*.html",
        ],
    },
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "dnspython>=2.4.0",
        "python-whois>=0.9.4",
        "rich>=13.7.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=9.0.0",
            "pytest-asyncio>=1.3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "autorecon=autorecon.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Operating System :: OS Independent",
    ],
)