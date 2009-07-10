.. PyECC documentation master file, created by
   sphinx-quickstart on Thu Jul  9 20:27:14 2009.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to PyECC's documentation!
=================================

Introduction
-------------
**PyECC** is a small, simple and fast solution for incorporating `Elliptical Curve Cryptography <http://en.wikipedia.org/wiki/Elliptic_curve_cryptography>`_
into any Python project. The benefits to using :abbr:`ECC (Elliptical Curve Crypto)` in your
Python projects is that it's small and very fast, meaning it's ideal for real-time
cryptography of both large and small pieces of data. PyECC itself is split into 
effectively three primary components:

* :doc:`libseccure` is the lower level C-library that was built utilizing the source from the `seccure(1) <http://point-at-infinity.org/seccure/>`_ binary. 
* :doc:`_pyecc` wraps :doc:`libseccure` with a series of *pythonic* functions that provide a series of less-than-user-friendly hooks into the underlying crypto primitives
* :doc:`pyecc` provides the `ECC` class which can be instantiated with a few options and provides simple access to encrypt/decrypt/sign/verify functionality

For the average user, knowledge of what :doc:`pyecc` can do for you is more than likely
sufficient to get basic :abbr:`ECC (Elliptical Curve Crypto)` incorporated into your
Python application(s). 


Attribution
^^^^^^^^^^^

**PyECC** was developed and maintained by R. Tyler Ballance <`tyler@slide.com`> for 
`Slide, Inc. <http://www.slide.com>`_. It is based on `seccure(1) <http://point-at-infinity.org/seccure/>`_ 
which was originally developed by `B. Poettering <http://point-at-infinity.org>`_. If you 
have found bugs or would like to suggest features, please visit the `GitHub Issues page <http://github.com/rtyler/PyECC/issues>`_.

.. toctree::
   :hidden:

   libseccure.rst
   _pyecc.rst
   pyecc.rst

