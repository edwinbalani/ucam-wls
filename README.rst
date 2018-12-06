ucam-wls: a generic Raven-like login service engine
===================================================

``ucam-wls`` is a library to implement the 'web login service' (WLS) component
of the `WAA2WLS protocol`_, used primarily at the University of Cambridge as
part of the `Raven SSO service`_.

Numerous implementations of the 'web authentication agent' (WAA) part, run by
the party requesting a user's identity, already exist for various platforms and
applications.  These include:

- the officially-supported `mod_ucam_webauth`_ that is very popular (at least
  within Cambridge)
- `ucam-webauth-php`_, published by the University also but "not (officially) supported"
- Daniel Richman's `python-ucam-webauth`_
- `django-ucamwebauth`_

However, no known implementations of the WLS component exist apart from the
official Raven production and test servers.

For those hoping to run an internal authentication service that integrates well
with existing popular WAA implementations, this project is a first attempt at
a solution.

.. _WAA2WLS protocol: https://raven.cam.ac.uk/project/waa2wls-protocol.txt
.. _Raven SSO service: https://raven.cam.ac.uk/project/
.. _mod_ucam_webauth: https://github.com/cambridgeuniversity/mod_ucam_webauth
.. _ucam-webauth-php: https://github.com/cambridgeuniversity/ucam-webauth-php
.. _python-ucam-webauth: https://github.com/DanielRichman/python-ucam-webauth
.. _django-ucamwebauth: https://github.com/uisautomation/django-ucamwebauth


What this library does and doesn't do
-------------------------------------

``ucam-wls`` will:

* Provide a compliant implementation of its side of the WAA2WLS protocol.
* Accept authentication requests as URL query strings, a Python `dict` of
  parameters, or as keyword arguments to an `__init__` function.
* Generate signed authentication responses asserting a given principal (if
  successful) and appropriate status code, using a given RSA private key.

``ucam-wls`` won't:

* Serve a web interface for users to authenticate.
* Manage your RSA private keys for you.
