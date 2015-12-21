#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
import logging
from os import walk
from setuptools import setup, Command

logging.basicConfig(level=logging.DEBUG)
logging.getLogger("nose").setLevel(logging.DEBUG)

setup(
    name="ublkdev",
    version="0.1",
    packages=['ublkdev'],
    entry_points={
        "console_scripts": [
            "ubd-s3=ublkdev.s3:main",
            "ubd-unregister=ublkdev.ublkdev:unregister",
        ]
    },
    install_requires=["boto>=2.0", "six>=1.0"],
    #setup_requires=["nose>=1.0"],

    # PyPI information
    author="David Cuthbert",
    author_email="dacut@kanga.org",
    description="Userspace block device utilities",
    license="BSD",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    zip_safe=False,
)
