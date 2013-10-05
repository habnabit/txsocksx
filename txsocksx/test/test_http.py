# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from twisted.python.versions import Version
from twisted.trial import unittest
import twisted

from txsocksx.test.util import FakeEndpoint, UppercaseWrapperFactory
from txsocksx.http import SOCKS4Agent, SOCKS5Agent
from txsocksx.tls import TLSWrapClientEndpoint


if twisted.version < Version('twisted', 12, 1, 0):
    skip = 'txsocksx.http requires Twisted 12.1 or newer'
else:
    skip = None


class AgentTestCase(unittest.TestCase):
    def setUp(self):
        self.endpoint = FakeEndpoint()
        self.agent = self.agentType(None, proxyEndpoint=self.endpoint)
        self.agent._tlsWrapper = self._tlsWrapper

    def _tlsWrapper(self, *a):
        wrapper = TLSWrapClientEndpoint(*a)
        wrapper._wrapper = UppercaseWrapperFactory
        return wrapper


class TestSOCKS5Agent(AgentTestCase):
    skip = skip
    agentType = SOCKS5Agent

    def test_HTTPRequest(self):
        self.agent.request('GET', 'http://spam.com/eggs')
        self.endpoint.proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        received = self.endpoint.transport.value()
        self.assertEqual(received[:18], '\x05\x01\x00\x05\x01\x00\x03\x08spam.com\x00\x50')
        request = received[18:].splitlines()
        self.assert_('GET /eggs HTTP/1.1' in request)
        self.assert_('Host: spam.com' in request)

    def test_HTTPSRequest(self):
        self.agent.request('GET', 'https://spam.com/eggs')
        self.endpoint.proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        received = self.endpoint.transport.value()
        self.assertEqual(received[:18], '\x05\x01\x00\x05\x01\x00\x03\x08spam.com\x01\xbb')
        request = received[18:].splitlines()
        self.assert_('GET /EGGS HTTP/1.1' in request)
        self.assert_('HOST: SPAM.COM' in request)


class TestSOCKS4Agent(AgentTestCase):
    skip = skip
    agentType = SOCKS4Agent

    def test_HTTP4Request(self):
        self.agent.request('GET', 'http://127.0.0.1/eggs')
        self.endpoint.proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        received = self.endpoint.transport.value()
        self.assertEqual(received[:9], '\x04\x01\x00\x50\x7f\x00\x00\x01\x00')
        request = received[9:].splitlines()
        self.assert_('GET /eggs HTTP/1.1' in request)
        self.assert_('Host: 127.0.0.1' in request)

    def test_HTTP4aRequest(self):
        self.agent.request('GET', 'http://spam.com/eggs')
        self.endpoint.proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        received = self.endpoint.transport.value()
        self.assertEqual(received[:18], '\x04\x01\x00\x50\x00\x00\x00\x01\x00spam.com\x00')
        request = received[18:].splitlines()
        self.assert_('GET /eggs HTTP/1.1' in request)
        self.assert_('Host: spam.com' in request)

    def test_HTTPSRequest(self):
        self.agent.request('GET', 'https://spam.com/eggs')
        self.endpoint.proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        received = self.endpoint.transport.value()
        self.assertEqual(received[:18], '\x04\x01\x01\xbb\x00\x00\x00\x01\x00spam.com\x00')
        request = received[18:].splitlines()
        self.assert_('GET /EGGS HTTP/1.1' in request)
        self.assert_('HOST: SPAM.COM' in request)
