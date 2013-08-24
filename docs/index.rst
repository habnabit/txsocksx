.. include:: ../README.rst

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

``txsocksx.ssl``
-----------------

.. automodule:: txsocksx.ssl
   :members: TLSStarterClientEndpointWrapper


.. |SOCKS5ClientEndpoint| replace:: :class:`.SOCKS5ClientEndpoint`
.. |SOCKS5Agent| replace:: :class:`.SOCKS5Agent`
.. |TLSStarterClientEndpointWrapper| replace:: :class:`.TLSStarterClientEndpointWrapper`
.. |txsocksx.http| replace:: :mod:`txsocksx.http`
.. |txsocksx.ssl| replace:: :mod:`txsocksx.ssl`
