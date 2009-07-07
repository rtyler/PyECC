PyECC: Python Elliptical Curve Cryptography
============================================

PyECC is a Python module wrapped around the ``libseccure`` library which itself is 
based off of code developed originally for the `seccure(1) utility <http://point-at-infinity.org/seccure/>`_.

Build and Install
-----------------

Since PyECC uses `setuptools <http://pypi.python.org/pypi/setuptools>`_ to build and 
install the PyECC module and corresponding library, you need to run:: 
    
    % sudo python setup.py install


Author(s)
---------

PyECC was developed by R. Tyler Ballance (``tyler@slide.com``) at `Slide, Inc. <http://slide.com>`_. 
The original seccure(1) binary however was developed by B. Poettering.
