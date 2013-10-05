# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from twisted.internet import defer
from twisted.protocols import policies
from twisted.test import proto_helpers


class FakeEndpoint(object):
    def __init__(self, failure=None):
        self.failure = failure

    def connect(self, fac):
        if self.failure:
            return defer.fail(self.failure)
        self.proto = fac.buildProtocol(None)
        transport = proto_helpers.StringTransport()
        self.aborted = []
        transport.abortConnection = lambda: self.aborted.append(True)
        self.tlsStarts = []
        transport.startTLS = lambda ctx: self.tlsStarts.append(ctx)
        self.proto.makeConnection(transport)
        self.transport = transport
        return defer.succeed(self.proto)


class UppercaseWrapperProtocol(policies.ProtocolWrapper):
    def dataReceived(self, data):
        policies.ProtocolWrapper.dataReceived(self, data.upper())

    def write(self, data):
        policies.ProtocolWrapper.write(self, data.upper())

    def writeSequence(self, seq):
        for data in seq:
            self.write(data)

class UppercaseWrapperFactory(policies.WrappingFactory):
    protocol = UppercaseWrapperProtocol

    def __init__(self, context, ign, factory):
        self.context = context
        policies.WrappingFactory.__init__(self, factory)
