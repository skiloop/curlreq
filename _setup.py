import os
import re
from codecs import open as copen

from setuptools import find_packages
from setuptools import setup

# Based on https://github.com/pypa/sampleproject/blob/main/setup.py
# and https://python-packaging-user-guide.readthedocs.org/

here = os.path.abspath(os.path.dirname(__file__))

with copen(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()
long_description_content_type = "text/markdown"

with copen(os.path.join(here, "curlreq/version.py")) as f:
    match = re.search(r'VERSION = "(.+?)"', f.read())
    assert match
    VERSION = match.group(1)

setup(
    name="curlreq",
    version=VERSION,
    description="A requests-like http client base on pycurl",
    long_description=long_description,
    long_description_content_type=long_description_content_type,
    url="https://github.com/skiloop/curlreq",
    author="Jason Stone",
    author_email="skiloop@gmail.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console :: Curses",
        "Operating System :: MacOS",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
        "Typing :: Typed",
    ],
    project_urls={
        "Source": "https://github.com/skiloop/curlreq/",
        "Tracker": "https://github.com/skiloop/curlreq/issues",
    },
    packages=find_packages(
        include=[
            "curlreq",
        ]
    ),
    include_package_data=True,

    python_requires=">=3.7",
    # https://packaging.python.org/en/latest/discussions/install-requires-vs-requirements/#install-requires
    # It is not considered best practice to use install_requires to pin dependencies to specific versions.
    install_requires=[
    ],
    extras_require={

    },
)
