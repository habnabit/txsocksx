# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

try:
    from txsocksx._version import __version__, __sha__
except ImportError:
    __version__ = __sha__ = None

__author__ = 'Aaron Gallagher <_@habnab.it>'
