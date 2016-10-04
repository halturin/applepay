import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "applepay",
    version = "0.3.0",
    author = "Taras Halturin",
    author_email = "halturin@gmail.com",
    description = ("a Python library for decrypting Apple Pay payment tokens."),
    license = "BSD",
    keywords = "applepay payment tokens",
    url = "https://github.com/halturin/applepay",
    packages=['applepay', 'tests'],
    install_requires=[
        'cryptography',
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: BSD License",
    ],
)
