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
DEFAULT_PLAINTEXT = 'This is a very very secret message!\n'

class ECC_Verify_Tests(unittest.TestCase):
    def setUp(self):
        super(ECC_Verify_Tests, self).setUp()
        self.ecc = pyecc.ECC(public=DEFAULT_PUBKEY, private=DEFAULT_PRIVKEY)

    def test_BasicVerification(self):
        assert self.ecc.verify(DEFAULT_DATA, DEFAULT_SIG), ('Failed to verify signature',
                DEFAULT_DATA, DEFAULT_SIG, DEFAULT_PUBKEY, DEFAULT_PRIVKEY)

    def test_BadVerification(self):
        assert self.ecc.verify(DEFAULT_DATA, "FAIL") == False , ('Verified on a bad sig',
                DEFAULT_DATA, DEFAULT_SIG, DEFAULT_PUBKEY, DEFAULT_PRIVKEY)

class ECC_Sign_Tests(unittest.TestCase):
    def setUp(self):
        super(ECC_Sign_Tests, self).setUp()
        self.ecc = pyecc.ECC(public=DEFAULT_PUBKEY, private=DEFAULT_PRIVKEY)

    def test_BasicSign(self):
        signature = self.ecc.sign(DEFAULT_DATA)

        assert signature == DEFAULT_SIG, ('Failed to generate a legit signature',
                DEFAULT_SIG, signature)

    def test_SignNone(self):
        signature = self.ecc.sign(None)

        assert signature == None, ('Should have a None sig')

class ECC_Encrypt_Tests(unittest.TestCase):
    def setUp(self):
        super(ECC_Encrypt_Tests, self).setUp()
        self.ecc = pyecc.ECC(public=DEFAULT_PUBKEY, private=DEFAULT_PRIVKEY)

    def test_BasicEncrypt(self):
        encrypted = self.ecc.encrypt(DEFAULT_PLAINTEXT)
        assert encrypted
        decrypted = self.ecc.decrypt(encrypted)
        assert decrypted == DEFAULT_PLAINTEXT

class ECC_Decrypt_Tests(unittest.TestCase):
    def setUp(self):
        super(ECC_Decrypt_Tests, self).setUp()
        self.ecc = pyecc.ECC(public=DEFAULT_PUBKEY, private=DEFAULT_PRIVKEY)

    def test_BasicDecrypt(self):
        encrypted = "\x01\xabT\x8e\xeb\x8e\xbf\xd8\xf5\x0c\xfePp\xe5t\x9b[\xc1O\xa3\xef\x19U\xa0g\x8db\r\x81Pm\xdd\x85'7v\xc9\xaf\xb2\x96\xc0\x01b\x9dn\xdc\xe7)\x0c\xcb\x90O\xb7\xb9z\x9f\xf3\n\xf2\xc0\xc4l)\xf7\xc6\xcb\xb3"
        decrypted = self.ecc.decrypt(encrypted)
        assert decrypted  == DEFAULT_PLAINTEXT
        

if __name__ == '__main__':
    unittest.main()
