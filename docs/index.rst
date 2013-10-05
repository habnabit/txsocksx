.. include:: ../README.rst
   :start-line: 7

API
===

``txsocksx.client``
-------------------

.. automodule:: txsocksx.client
   :members: SOCKS4ClientEndpoint, SOCKS5ClientEndpoint

``txsocksx.http``
-----------------

.. module:: txsocksx.http

.. autoclass:: SOCKS4Agent(*a, proxyEndpoint, endpointArgs={}, **kw)
   :members:

.. autoclass:: SOCKS5Agent(*a, proxyEndpoint, endpointArgs={}, **kw)
   :members:

``txsocksx.tls``
-----------------

.. automodule:: txsocksx.tls
   :members: TLSWrapClientEndpoint


.. |SOCKS5ClientEndpoint| replace:: :class:`.SOCKS5ClientEndpoint`
.. |SOCKS5Agent| replace:: :class:`.SOCKS5Agent`
.. |TLSWrapClientEndpoint| replace:: :class:`.TLSWrapClientEndpoint`
.. |txsocksx.http| replace:: :mod:`txsocksx.http`
.. |txsocksx.tls| replace:: :mod:`txsocksx.tls`
