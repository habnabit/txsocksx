========
txsocksx
========

``txsocksx`` is SOCKS4/4a and SOCKS5 client endpoints for `Twisted`_ 10.1 or
greater.


Examples
========

These examples assume familiarity with how to use `Twisted endpoints`_. For
simplicity, most of the examples will use SOCKS5.


Authenticating
--------------

One specifies authentication methods to a |SOCKS5ClientEndpoint| via the
*methods* parameter. For example, to connect using the username ``spam`` and
password ``eggs``::

  exampleEndpoint = SOCKS5ClientEndpoint(
      'example.com', 6667, proxyEndpoint, methods={'login': ('spam', 'eggs')})

However, this will disable anonymous authentication. To use either login or
anonymous authentication, specify both methods::

  exampleEndpoint = SOCKS5ClientEndpoint(
      'example.com', 6667, proxyEndpoint, methods={'login': ('spam', 'eggs'),
                                                   'anonymous': ()})

The ``methods`` dict must always map from a string to a tuple.


SOCKS4
~~~~~~

SOCKS4 has no authentication, but does have a configurable "user ID" which
defaults to an empty string::

  exampleEndpoint = SOCKS4ClientEndpoint(
      'example.com', 6667, proxyEndpoint, user='spam')


Connecting to a thing over tor
------------------------------

To connect to ``example.com`` on port 6667 over tor, one creates a
|SOCKS5ClientEndpoint| wrapping the endpoint of the tor server::

  torServerEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
  exampleEndpoint = SOCKS5ClientEndpoint('example.com', 6667, torServerEndpoint)

Establishing the connection from there proceeds like usual::

  deferred = exampleEndpoint.connect(someFactory)

``txsocksx`` will not do any DNS resolution, so the hostname ``example.com``
will not leak; tor will receive the hostname directly and do the DNS lookup
itself.

Tor allows connections by SOCKS4 or SOCKS5, and does not expect a user ID to be
sent when using the SOCKS4 client.


Cancelling a connection
-----------------------

Sometimes one tires of waiting and wants to abort the connection attempt. For
example, to abort the whole connection attempt after ten seconds::

  torServerEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
  exampleEndpoint = SOCKS5ClientEndpoint('example.com', 6667, torServerEndpoint)
  deferred = exampleEndpoint.connect(someFactory)
  reactor.callLater(10, deferred.cancel)

This is a trivial example; real code should cancel the `IDelayedCall`_ returned
by ``reactor.callLater`` when the deferred fires. The code would then look like
this::

  torServerEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
  exampleEndpoint = SOCKS5ClientEndpoint('example.com', 6667, torServerEndpoint)
  deferred = exampleEndpoint.connect(someFactory)
  canceler = reactor.callLater(10, deferred.cancel)

  def cancelCanceler(result):
      if canceler.active():
          canceler.cancel()
      return result
  deferred.addBoth(cancelCanceler)


Making HTTP requests
--------------------

Twisted's builtin `Agent`_ HTTP client does not support being handed an
arbitrary endpoint. (Yet. `Ticket #6634`_ was filed to make this an API
directly supported by Twisted.) ``txsocksx`` provides an ``Agent`` as a
workaround, but it uses a private API. There are no guarantees that this
approach will run in newer versions of Twisted, but |txsocksx.http| will
attempt to provide a consistent API.

While ``txsocksx`` requires only Twisted 10.1, |txsocksx.http| requires Twisted
12.1 or greater. Its usage is almost identical to normal ``Agent`` usage::

  torServerEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
  agent = SOCKS5Agent(reactor, proxyEndpoint=torServerEndpoint)
  deferred = agent.request('GET', 'http://example.com/')

Note that the ``proxyEndpoint`` parameter *must* be passed as a keyword
argument. There is a second, optional, keyword-only argument for passing
additional arguments to the |SOCKS5ClientEndpoint| as |SOCKS5Agent|
constructs it::

  torServerEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
  agent = SOCKS5Agent(reactor, proxyEndpoint=torServerEndpoint,
                      endpointArgs=dict(methods={'login': ('spam', 'eggs')}))
  deferred = agent.request('GET', 'http://example.com/')

|SOCKS5Agent| transparently supports HTTPS as via
|TLSStarterClientEndpointWrapper|.


Upgrading to TLS
----------------

Sometimes one wants to switch to speaking TLS as soon as the proxy negotiation
is finished. For that, there is |txsocksx.ssl| [#]_. After wrapping an
endpoint with |TLSStarterClientEndpointWrapper|, the connection will be
upgraded to using TLS immediately after proxy negotiation finishes::

  torServerEndpoint = TCP4ClientEndpoint(reactor, '127.0.0.1', 9050)
  exampleEndpoint = SOCKS5ClientEndpoint('example.com', 6667, torServerEndpoint)
  tlsEndpoint = TLSStarterClientEndpointWrapper(exampleEndpoint)
  deferred = tlsEndpoint.connect(someFactory)

.. [#] A more appropriate name might be ``txsocksx.tls``, but the name remains
       |txsocksx.ssl| for backward compatibility.

.. _Twisted: http://twistedmatrix.com/
.. _Twisted endpoints: http://twistedmatrix.com/documents/current/core/howto/endpoints.html
.. _IDelayedCall: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IDelayedCall.html
.. _Agent: http://twistedmatrix.com/documents/current/web/howto/client.html
.. _Ticket #6634: https://twistedmatrix.com/trac/ticket/6634

.. |SOCKS5ClientEndpoint| replace:: ``SOCKS5ClientEndpoint``
.. |SOCKS5Agent| replace:: ``SOCKS5Agent``
.. |TLSStarterClientEndpointWrapper| replace:: ``TLSStarterClientEndpointWrapper``
.. |txsocksx.http| replace:: ``txsocksx.http``
.. |txsocksx.ssl| replace:: ``txsocksx.ssl``
