# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

"""TLS convenience wrappers for endpoints.

"""


from twisted.protocols import tls
from twisted.internet import interfaces
from zope.interface import implementer


@implementer(interfaces.IStreamClientEndpoint)
class TLSWrapClientEndpoint(object):
    """An endpoint which automatically starts TLS.

    :param contextFactory: A `ContextFactory`__ instance.
    :param wrappedEndpoint: The endpoint to wrap.

    __ http://twistedmatrix.com/documents/current/api/twisted.internet.protocol.ClientFactory.html

    """

    _wrapper = tls.TLSMemoryBIOFactory

    def __init__(self, contextFactory, wrappedEndpoint):
        self.contextFactory = contextFactory
        self.wrappedEndpoint = wrappedEndpoint

    def connect(self, fac):
        """Connect to the wrapped endpoint, then start TLS.

        The TLS negotiation is done by way of wrapping the provided factory
        with `TLSMemoryBIOFactory`__ during connection.

        :returns: A ``Deferred`` which fires with the same ``Protocol`` as
            ``wrappedEndpoint.connect(fac)`` fires with. If that ``Deferred``
            errbacks, so will the returned deferred.

        __ http://twistedmatrix.com/documents/current/api/twisted.protocols.tls.html

        """
        fac = self._wrapper(self.contextFactory, True, fac)
        return self.wrappedEndpoint.connect(fac).addCallback(self._unwrapProtocol)

    def _unwrapProtocol(self, proto):
        return proto.wrappedProtocol
