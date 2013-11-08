# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from setuptools import setup


with open('README.rst', 'rb') as infile:
    long_description = infile.read()

with open('requirements.txt', 'rb') as infile:
    install_requires = infile.read().split()

setup(
    name='txsocksx',
    description='Twisted client endpoints for SOCKS{4,4a,5}',
    long_description=long_description,
    author='Aaron Gallagher',
    author_email='_@habnab.it',
    url='https://github.com/habnabit/txsocksx',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Framework :: Twisted',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Internet',
    ],
    license='ISC',

    setup_requires=['vcversioner>=1'],
    vcversioner={
        'version_module_paths': ['txsocksx/_version.py'],
    },
    install_requires=install_requires,
    packages=['txsocksx', 'txsocksx.test'],
)
