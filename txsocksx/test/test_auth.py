from twisted.internet import defer
from twisted.trial import unittest
from twisted.test import proto_helpers

from txsocksx import auth, client

class TestAuth(unittest.TestCase):
    def setUp(self):
        self.proto = client.SOCKS5Client()
        self.proto.transport = proto_helpers.StringTransport()

    def test_anonymous(self):
        meth = auth.Anonymous()
        self.assertEqual(meth.method, '\x00')
        d = meth.negotiate(self.proto)
        @d.addCallback
        def _cb(_):
            self.assertEqual(self.proto.transport.value(), '')
        return d

    def test_usernamePassword(self):
        meth = auth.UsernamePassword('spam', 'egg')
        self.assertEqual(meth.method, '\x02')
        self.proto.unpack = lambda _: defer.succeed((0,))
        d = meth.negotiate(self.proto)
        @d.addCallback
        def _cb(_):
            self.assertEqual(self.proto.transport.value(),
                             '\x01\x04spam\x03egg')
        return d

    def test_usernamePasswordFailure(self):
        meth = auth.UsernamePassword('spam', 'egg')
        self.proto.unpack = lambda _: defer.succeed((9,))
        d = meth.negotiate(self.proto)
        def _eb(f):
            f.trap(auth.UsernamePasswordAuthFailed)
            self.assertEqual(f.value.args[0], 9)
        d.addCallbacks(lambda _: self.fail(), _eb)
        return d
