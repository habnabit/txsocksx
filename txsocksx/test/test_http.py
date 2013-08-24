# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from twisted.python.versions import Version
from twisted.trial import unittest
import twisted

from txsocksx.test.util import FakeEndpoint
from txsocksx.http import SOCKS4Agent, SOCKS5Agent


if twisted.version < Version('twisted', 12, 1, 0):
    skip = 'txsocksx.http requires Twisted 12.1 or newer'
else:
    skip = None


class TestSOCKS5Agent(unittest.TestCase):
    skip = skip

    def test_HTTPRequest(self):
        endpoint = FakeEndpoint()
        agent = SOCKS5Agent(None, proxyEndpoint=endpoint)
        agent.request('GET', 'http://spam.com/eggs')
        endpoint.proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        received = endpoint.transport.value()
        self.assertEqual(received[:18], '\x05\x01\x00\x05\x01\x00\x03\x08spam.com\x00\x50')
        request = received[18:].splitlines()
        self.assert_('GET /eggs HTTP/1.1' in request)
        self.assert_('Host: spam.com' in request)
        self.assertFalse(endpoint.tlsStarts)

    def test_HTTPSRequest(self):
        endpoint = FakeEndpoint()
        agent = SOCKS5Agent(None, proxyEndpoint=endpoint)
        agent.request('GET', 'https://spam.com/eggs')
        endpoint.proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        received = endpoint.transport.value()
        self.assertEqual(received[:18], '\x05\x01\x00\x05\x01\x00\x03\x08spam.com\x01\xbb')
        request = received[18:].splitlines()
        self.assert_('GET /eggs HTTP/1.1' in request)
        self.assert_('Host: spam.com' in request)
        self.assert_(endpoint.tlsStarts)


class TestSOCKS4Agent(unittest.TestCase):
    skip = skip

    def test_HTTP4Request(self):
        endpoint = FakeEndpoint()
        agent = SOCKS4Agent(None, proxyEndpoint=endpoint)
        agent.request('GET', 'http://127.0.0.1/eggs')
        endpoint.proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        received = endpoint.transport.value()
        self.assertEqual(received[:9], '\x04\x01\x00\x50\x7f\x00\x00\x01\x00')
        request = received[9:].splitlines()
        self.assert_('GET /eggs HTTP/1.1' in request)
        self.assert_('Host: 127.0.0.1' in request)
        self.assertFalse(endpoint.tlsStarts)

    def test_HTTP4aRequest(self):
        endpoint = FakeEndpoint()
        agent = SOCKS4Agent(None, proxyEndpoint=endpoint)
        agent.request('GET', 'http://spam.com/eggs')
        endpoint.proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        received = endpoint.transport.value()
        self.assertEqual(received[:18], '\x04\x01\x00\x50\x00\x00\x00\x01\x00spam.com\x00')
        request = received[18:].splitlines()
        self.assert_('GET /eggs HTTP/1.1' in request)
        self.assert_('Host: spam.com' in request)
        self.assertFalse(endpoint.tlsStarts)

    def test_HTTPSRequest(self):
        endpoint = FakeEndpoint()
        agent = SOCKS4Agent(None, proxyEndpoint=endpoint)
        agent.request('GET', 'https://spam.com/eggs')
        endpoint.proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        received = endpoint.transport.value()
        self.assertEqual(received[:18], '\x04\x01\x01\xbb\x00\x00\x00\x01\x00spam.com\x00')
        request = received[18:].splitlines()
        self.assert_('GET /eggs HTTP/1.1' in request)
        self.assert_('Host: spam.com' in request)
        self.assert_(endpoint.tlsStarts)
