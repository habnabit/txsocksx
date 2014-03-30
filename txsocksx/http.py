# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

"""``twisted.web.client`` adapters for SOCKS4/4a and SOCKS5 connections.

This requires Twisted 12.1 or greater to use.

"""


from twisted.web.client import Agent, SchemeNotSupported

from txsocksx.client import SOCKS4ClientEndpoint, SOCKS5ClientEndpoint
from txsocksx.tls import TLSWrapClientEndpoint


class _SOCKSAgent(Agent):
    endpointFactory = None
    _tlsWrapper = TLSWrapClientEndpoint

    def __init__(self, *a, **kw):
        if not hasattr(Agent, '_getEndpoint'):
            raise NotImplementedError('txsocksx.http requires twisted 12.1 or greater')
        self.proxyEndpoint = kw.pop('proxyEndpoint')
        self.endpointArgs = kw.pop('endpointArgs', {})
        super(_SOCKSAgent, self).__init__(*a, **kw)

    def _getEndpoint(self, scheme, host, port):
        if scheme not in ('http', 'https'):
            raise SchemeNotSupported('unsupported scheme', scheme)
        endpoint = self.endpointFactory(
            host, port, self.proxyEndpoint, **self.endpointArgs)
        if scheme == 'https':
            endpoint = self._tlsWrapper(
                self._wrapContextFactory(host, port), endpoint)
        return endpoint

class SOCKS4Agent(_SOCKSAgent):
    """An `Agent`__ which connects over SOCKS4.

    See |SOCKS5Agent| for details.

    __ http://twistedmatrix.com/documents/current/api/twisted.web.client.Agent.html
    .. |SOCKS5Agent| replace:: ``SOCKS5Agent``

    """

    endpointFactory = SOCKS4ClientEndpoint

class SOCKS5Agent(_SOCKSAgent):
    """An ``Agent`` which connects over SOCKS5.

    :param proxyEndpoint: The same as *proxyEndpoint* for
        |SOCKS5ClientEndpoint|: the endpoint of the SOCKS5 proxy server. This
        argument must be passed as a keyword argument.
    :param endpointArgs: A dict of keyword arguments which will be passed when
        constructing the |SOCKS5ClientEndpoint|. For example, this could be
        ``{'methods': {'anonymous': ()}}``.

    The rest of the parameters, methods, and overall behavior is identical to
    `Agent`__. The ``connectTimeout`` and ``bindAddress`` arguments will be
    ignored and should be specified when constructing the *proxyEndpoint*.

    __ http://twistedmatrix.com/documents/current/api/twisted.web.client.Agent.html
    .. |SOCKS5ClientEndpoint| replace:: ``SOCKS5ClientEndpoint``

    """

    endpointFactory = SOCKS5ClientEndpoint
