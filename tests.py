#!/usr/bin/env python
'''
    Copyright 2009 Slide, Inc.

'''

import unittest

import pyecc

DEFAULT_DATA = 'This message will be signed\n'
DEFAULT_SIG = '$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq'
DEFAULT_PUBKEY = '8W;>i^H0qi|J&$coR5MFpR*Vn'
DEFAULT_PRIVKEY = 'my private key'

class ECC_Verify_Tests(unittest.TestCase):
    def test_BasicVerification(self):
        ecc = pyecc.ECC(public=DEFAULT_PUBKEY, private=DEFAULT_PRIVKEY)
        
        assert ecc.verify(DEFAULT_DATA, DEFAULT_SIG), ('Failed to verify signature',
                DEFAULT_DATA, DEFAULT_SIG, DEFAULT_PUBKEY, DEFAULT_PRIVKEY)



if __name__ == '__main__':
    unittest.main()
