# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

"""SSL/TLS convenience wrappers for endpoints.

This module is deprecated; please use ``txsocksx.tls`` instead.
"""


from twisted.protocols import tls
from twisted.internet import interfaces
from zope.interface import implementer


@implementer(interfaces.IStreamClientEndpoint)
class SSLWrapClientEndpoint(object):
    def __init__(self, contextFactory, wrappedEndpoint):
        self.contextFactory = contextFactory
        self.wrappedEndpoint = wrappedEndpoint

    def connect(self, fac):
        fac = tls.TLSMemoryBIOFactory(self.contextFactory, True, fac)
        return self.wrappedEndpoint.connect(fac)


@implementer(interfaces.IStreamClientEndpoint)
class TLSStarterClientEndpointWrapper(object):
    """An endpoint which automatically starts TLS.

    :param contextFactory: A `ContextFactory`__ instance.
    :param wrappedEndpoint: The endpoint to wrap.

    __ http://twistedmatrix.com/documents/current/api/twisted.internet.protocol.ClientFactory.html

    """

    def __init__(self, contextFactory, wrappedEndpoint):
        self.contextFactory = contextFactory
        self.wrappedEndpoint = wrappedEndpoint

    def _startTLS(self, proto):
        proto.transport.startTLS(self.contextFactory)
        return proto

    def connect(self, fac):
        """Connect to the wrapped endpoint, then start TLS.

        ``wrappedEndpoint.connect(fac)`` must return a ``Deferred`` which will
        fire with a ``Protocol`` whose transport implements `ITLSTransport`__
        for the ``startTLS`` method. ``startTLS`` will be called immediately
        after the ``Deferred`` fires.

        :returns: A ``Deferred`` which fires with the same ``Protocol`` as
            ``wrappedEndpoint.connect(fac)`` fires with. If that ``Deferred``
            errbacks, so will the returned deferred.

        __ http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.ITLSTransport.html

        """

        return self.wrappedEndpoint.connect(fac).addCallback(self._startTLS)
