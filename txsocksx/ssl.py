# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

"""SSL/TLS convenience wrappers for endpoints.

"""


from twisted.protocols import tls
from twisted.internet import interfaces
from zope.interface import implements


class SSLWrapClientEndpoint(object):
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, contextFactory, wrappedEndpoint):
        self.contextFactory = contextFactory
        self.wrappedEndpoint = wrappedEndpoint

    def connect(self, fac):
        fac = tls.TLSMemoryBIOFactory(self.contextFactory, True, fac)
        return self.wrappedEndpoint.connect(fac)


class TLSStarterClientEndpointWrapper(object):
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, contextFactory, wrappedEndpoint):
        self.contextFactory = contextFactory
        self.wrappedEndpoint = wrappedEndpoint

    def _startTLS(self, proto):
        proto.transport.startTLS(self.contextFactory)
        return proto

    def connect(self, fac):
        return self.wrappedEndpoint.connect(fac).addCallback(self._startTLS)
