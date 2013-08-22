# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from __future__ import print_function

from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.task import react
from twisted.web.client import readBody

from txsocksx.http import SOCKS5Agent


def main(reactor):
    torEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
    agent = SOCKS5Agent(reactor, proxyEndpoint=torEndpoint)
    d = agent.request('GET', 'http://api.externalip.net/ip/')
    d.addCallback(readBody)
    d.addCallback(print)
    return d

react(main, [])
