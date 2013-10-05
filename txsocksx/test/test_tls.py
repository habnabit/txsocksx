# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from twisted.protocols.basic import NetstringReceiver
from twisted.internet import defer, protocol
from twisted.test import proto_helpers

from txsocksx.test.util import UppercaseWrapperFactory, SyncDeferredsTestCase
from txsocksx.tls import TLSWrapClientEndpoint


class NetstringTracker(NetstringReceiver):
    def __init__(self):
        self.strings = []

    def stringReceived(self, string):
        self.strings.append(string)

class NetstringFactory(protocol.ClientFactory):
    protocol = NetstringTracker


class FakeError(Exception):
    pass

class FakeDisconnectedError(Exception):
    pass


class FakeEndpoint(object):
    def __init__(self, deferred=None, fail=False):
        self.deferred = deferred
        self.fail = fail
        self.connected = False

    def connect(self, fac):
        if self.deferred:
            return self.deferred
        if self.fail:
            return defer.fail(FakeError())
        self.proto = fac.buildProtocol(None)
        self.transport = proto_helpers.StringTransport()
        self.transport.abortConnection = self.transport.loseConnection = (
            lambda: self.disconnect(FakeDisconnectedError()))
        self.proto.makeConnection(self.transport)
        self.connected = True
        return defer.succeed(self.proto)

    def disconnect(self, reason):
        self.connected = False
        self.proto.connectionLost(reason)
        self.proto = self.transport = None


class TLSWrapClientEndpointTestCase(SyncDeferredsTestCase):
    def setUp(self):
        self.endpoint = FakeEndpoint()
        self.context = object()
        self.wrapper = TLSWrapClientEndpoint(self.context, self.endpoint)
        self.wrapper._wrapper = UppercaseWrapperFactory
        self.factory = NetstringFactory()

    def test_wrappingBehavior(self):
        """
        Any modifications performed by the underlying ProtocolWrapper
        propagate through to the wrapped Protocol.
        """
        proto = self.successResultOf(self.wrapper.connect(self.factory))
        self.endpoint.proto.dataReceived('5:hello,')
        self.assertEqual(proto.strings, ['HELLO'])

    def test_methodsAvailable(self):
        """
        Methods defined on the Protocol are accessible from the Protocol
        returned from connect's Deferred.
        """
        proto = self.successResultOf(self.wrapper.connect(self.factory))
        proto.sendString('spam')
        self.assertEqual(self.endpoint.transport.value(), '4:SPAM,')

    def test_connectionFailure(self):
        """
        Connection failures propagate upward to connect's Deferred.
        """
        self.endpoint.deferred = defer.Deferred()
        d = self.wrapper.connect(self.factory)
        self.assertNoResult(d)
        self.endpoint.deferred.errback(FakeError())
        self.failureResultOf(d, FakeError)

    def test_connectionCancellation(self):
        """
        Cancellation propagates upward to connect's Deferred.
        """
        canceled = []
        self.endpoint.deferred = defer.Deferred(canceled.append)
        d = self.wrapper.connect(self.factory)
        self.assertNoResult(d)
        d.cancel()
        self.assert_(canceled)
        self.failureResultOf(d, defer.CancelledError)
