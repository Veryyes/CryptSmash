#!/usr/bin/env python

from setuptools import setup

setup(
    name="cryptsmash",
    version='1.0',
    description="auto break non-modern crypto problems",
    author="Brandon Wong",
    url="",
    packages=["cryptsmash"],
    install_requires=[
        'rich',
        'typer'
    ],
    entry_points = {
        'console_scripts': ['smash = cryptsmash.run:main']
    }
)
