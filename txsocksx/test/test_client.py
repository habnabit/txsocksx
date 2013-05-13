from twisted.internet.error import ConnectionLost
from twisted.internet import protocol
from twisted.python import failure
from twisted.trial import unittest
from twisted.test import proto_helpers

from txsocksx import client, errors

connectionLostFailure = failure.Failure(ConnectionLost())

class FakeSOCKS5ClientFactory(protocol.ClientFactory):
    protocol = client.SOCKS5Client

    def __init__(self, host='', port=0, anonymousAuth=True, loginAuth=None):
        self.host = host
        self.port = port
        self.anonymousAuth = anonymousAuth
        self.loginAuth = loginAuth
        self.reason = None
        self.accum = proto_helpers.AccumulatingProtocol()

    def proxyConnectionFailed(self, reason):
        self.reason = reason

    def proxyConnectionEstablished(self, proxyProtocol):
        proxyProtocol.proxyEstablished(self.accum)

class TestSOCKS5Client(unittest.TestCase):
    def makeProto(self, *a, **kw):
        fac = FakeSOCKS5ClientFactory(*a, **kw)
        proto = fac.buildProtocol(None)
        transport = proto_helpers.StringTransport()
        transport.abortConnection = lambda: None
        proto.makeConnection(transport)
        return fac, proto

    def test_initialHandshake(self):
        fac, proto = self.makeProto()
        self.assertEqual(proto.transport.value(), '\x05\x01\x00')

        fac, proto = self.makeProto(loginAuth=True)
        self.assertEqual(proto.transport.value(), '\x05\x02\x00\x02')

        fac, proto = self.makeProto(anonymousAuth=False, loginAuth=True)
        self.assertEqual(proto.transport.value(), '\x05\x01\x02')

    def test_failedMethodSelection(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x05\xff')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(
            fac.reason.value, errors.MethodsNotAcceptedError)
        self.assertEqual(fac.reason.value.args[2], '\xff')

    def test_loginAuth(self):
        fac, proto = self.makeProto(loginAuth=('spam', 'eggs'))
        proto.transport.clear()
        proto.dataReceived('\x05\x02')
        self.assertEqual(proto.transport.value(), '\x01\x04spam\x04eggs')

    def test_loginAuthAccepted(self):
        fac, proto = self.makeProto(loginAuth=('spam', 'eggs'))
        proto.dataReceived('\x05\x02')
        proto.transport.clear()
        proto.dataReceived('\x01\x00')
        self.assert_(proto.transport.value())

    def test_loginAuthFailed(self):
        fac, proto = self.makeProto(loginAuth=('spam', 'eggs'))
        proto.dataReceived('\x05\x02\x01\x01')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(
            fac.reason.value, errors.LoginAuthenticationFailed)

    def test_connectionRequest(self):
        fac, proto = self.makeProto('host', 0x47)
        proto.transport.clear()
        proto.dataReceived('\x05\x00')
        self.assertEqual(proto.transport.value(),
                         '\x05\x01\x00\x03\x04host\x00\x47')

        fac, proto = self.makeProto('longerhost', 0x9494)
        proto.transport.clear()
        proto.dataReceived('\x05\x00')
        self.assertEqual(proto.transport.value(),
                         '\x05\x01\x00\x03\x0alongerhost\x94\x94')

    def test_handshakeEatsEnoughBytes(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x04666666666666666622xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x03\x08somehost22xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x03\x0022xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_connectionRequestError(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x01\x00\x03\x0022')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(fac.reason.value, errors.ConnectionError)
        self.assertEqual(fac.reason.value.args[1], 0x01)

    def test_buffering(self):
        fac, proto = self.makeProto()
        for c in '\x05\x00\x05\x00\x00\x01444422xxxxx':
            proto.dataReceived(c)
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_connectionLostEarly(self):
        wholeRequest = '\x05\x00\x05\x00\x00\x01444422'
        for e in xrange(len(wholeRequest)):
            partialRequest = wholeRequest[:e]
            fac, proto = self.makeProto()
            if partialRequest:
                proto.dataReceived(partialRequest)
            proto.connectionLost(connectionLostFailure)
            self.failUnlessIsInstance(fac.reason.value, ConnectionLost)

    def test_connectionLostAfterNegotiation(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)

        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422xxxxx')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)
        self.assertEqual(fac.accum.data, 'xxxxx')
