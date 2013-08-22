# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from twisted.web.client import Agent, SchemeNotSupported

from txsocksx.client import SOCKS4ClientEndpoint, SOCKS5ClientEndpoint
from txsocksx.ssl import TLSStarterClientEndpointWrapper


class _SOCKSAgent(Agent):
    endpointFactory = None

    def __init__(self, *a, **kw):
        self.proxyEndpoint = kw.pop('proxyEndpoint')
        self.endpointArgs = kw.pop('endpointArgs', {})
        super(_SOCKSAgent, self).__init__(*a, **kw)

    def _getEndpoint(self, scheme, host, port):
        if scheme not in ('http', 'https'):
            raise SchemeNotSupported('unsupported scheme', scheme)
        endpoint = self.endpointFactory(
            host, port, self.proxyEndpoint, **self.endpointArgs)
        if scheme == 'https':
            endpoint = TLSStarterClientEndpointWrapper(
                self._wrapContextFactory(host, port), endpoint)
        return endpoint

class SOCKS4Agent(_SOCKSAgent):
    endpointFactory = SOCKS4ClientEndpoint

class SOCKS5Agent(_SOCKSAgent):
    endpointFactory = SOCKS5ClientEndpoint
