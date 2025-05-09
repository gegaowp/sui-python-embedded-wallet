"""
Setup script for sui-embedded-wallet-py library.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="sui-embedded-wallet",
    version="0.1.0",
    author="Sui Embedded Wallet Contributors",
    author_email="your.email@example.com",
    description="A simple Python library for Sui blockchain wallets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/sui-embedded-wallet-py",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Utilities",
    ],
    python_requires=">=3.7",
    install_requires=[
        "pysui>=0.50.0",
    ],
) 