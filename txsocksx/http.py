# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

"""``twisted.web.client`` adapters for SOCKS4/4a and SOCKS5 connections.

This requires Twisted 12.1 or greater to use.

"""


import twisted
from twisted.python.versions import Version
from twisted.web.client import Agent, SchemeNotSupported

from txsocksx.client import SOCKS4ClientEndpoint, SOCKS5ClientEndpoint
from txsocksx.tls import TLSWrapClientEndpoint


_twisted_12_1 = Version('twisted', 12, 1, 0)
_twisted_14_0 = Version('twisted', 14, 0, 0)
_twisted_15_0 = Version('twisted', 15, 0, 0)


if twisted.version >= _twisted_15_0:
    from twisted.web.client import BrowserLikePolicyForHTTPS
    from twisted.web.iweb import IAgentEndpointFactory, IAgent, IPolicyForHTTPS
    from zope.interface import implementer

    _Agent = Agent

    @implementer(IAgentEndpointFactory, IAgent)
    class Agent(object):
        def __init__(self, reactor, contextFactory=BrowserLikePolicyForHTTPS(),
                     connectTimeout=None, bindAddress=None, pool=None):
            if not IPolicyForHTTPS.providedBy(contextFactory):
                raise NotImplementedError(
                    'contextFactory must implement IPolicyForHTTPS')
            self._policyForHTTPS = contextFactory
            self._wrappedAgent = _Agent.usingEndpointFactory(
                reactor, self, pool=pool)

        def request(self, *a, **kw):
            return self._wrappedAgent.request(*a, **kw)

        def endpointForURI(self, uri):
            return self._getEndpoint(uri.scheme, uri.host, uri.port)


class _SOCKSAgent(Agent):
    endpointFactory = None
    _tlsWrapper = TLSWrapClientEndpoint

    def __init__(self, *a, **kw):
        if twisted.version < _twisted_12_1:
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
            if _twisted_12_1 <= twisted.version < _twisted_14_0:
                tlsPolicy = self._wrapContextFactory(host, port)
            elif _twisted_14_0 <= twisted.version:
                tlsPolicy = self._policyForHTTPS.creatorForNetloc(host, port)
            else:
                raise NotImplementedError("can't figure out how to make a context factory")
            endpoint = self._tlsWrapper(tlsPolicy, endpoint)
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

    If used with Twisted 15.0 or greater, this class will also implement
    `IAgentEndpointFactory`__.

    __ http://twistedmatrix.com/documents/current/api/twisted.web.iweb.IAgentEndpointFactory.html

    .. |SOCKS5ClientEndpoint| replace:: ``SOCKS5ClientEndpoint``

    """

    endpointFactory = SOCKS5ClientEndpoint
