"""
Setup script for Bounster Policy.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bounster-policy",
    version="1.0.0",
    author="laoboatpeople",
    description="A simple and flexible policy-based access control system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/laoboatpeople/bounster-policy",
    py_modules=["bounster_policy"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    keywords="policy access-control authorization rbac security",
)
