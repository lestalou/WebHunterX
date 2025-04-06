#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="webhunterx",
    version="1.0.0",
    author="WebHunterX Team",
    author_email="contact@webhunterx.com",
    description="Un framework d'analyse de vulnérabilités web",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/webhunterx/webhunterx",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'webhunterx': ['payloads/*.txt'],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=[
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.3",
        "colorama>=0.4.4",
        "urllib3>=1.26.0",
    ],
    entry_points={
        'console_scripts': [
            'webhunterx=webhunterx.webhunterx:main',
            'webhunterx-xss=webhunterx.xss:main',
            'webhunterx-sqli=webhunterx.sqli:main',
        ],
    },
) 