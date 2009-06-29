#!/usr/bin/env python
'''
    Copyright 2009 Slide, Inc.

'''
import copy
import sys
import types
import unittest

import pyecc

#
# These values are built by running the seccure binary 
# and assume the curve of DEFAULT_CURVE (currently p384)
#
DEFAULT_DATA = 'This message will be signed\n'
DEFAULT_SIG = '$=gXkAjkWjA*>FF*eW@xo6>=B:F3X24$M-L:Pg(5O1SE@zs[cskaTh1K?p+O1G=;L~@slSs{v^6[V9oW/HkzJ+OS]q5ml4=iV(+xR~7>rS+y/TpgL~f[&,c'
DEFAULT_PUBKEY = '$BWJ_^0>R8,U~/$DZs#@r|-gt}&5|h*U{J_L^lvWk&X-K;R{*&qR(z+zE/xC'
DEFAULT_PRIVKEY = 'my private key'
DEFAULT_PLAINTEXT = 'This is a very very secret message!\n'

class ECC_KeyGen_Tests(unittest.TestCase):
    def test_GenerateWithPrivkey(self):
        pubkey = pyecc.ECC.public_keygen(DEFAULT_PRIVKEY)
        assert pubkey == DEFAULT_PUBKEY, ('Mismatch', pubkey, DEFAULT_PUBKEY)

    def test_GenerateBoth(self):
        ecc = pyecc.ECC.generate()

        encrypted = ecc.encrypt(DEFAULT_PLAINTEXT)
        assert encrypted, ('Failed to encrypt?', encrypted, ecc)

        decrypted = ecc.decrypt(encrypted)
        assert decrypted, ('Failed to decrypt?', decrypted, ecc)
        
        assert decrypted == DEFAULT_PLAINTEXT, ('Decrypted wrong',
            decrypted, DEFAULT_PLAINTEXT)

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
        self.ecc = pyecc.ECC(public=DEFAULT_PUBKEY)

    def test_BasicEncrypt(self):
        encrypted = self.ecc.encrypt(DEFAULT_PLAINTEXT)
        assert encrypted

        # Resetup self.ecc with a private key so I can decrypt
        self.ecc = pyecc.ECC(public=DEFAULT_PUBKEY, private=DEFAULT_PRIVKEY)
        decrypted = self.ecc.decrypt(encrypted)
        assert decrypted == DEFAULT_PLAINTEXT

class ECC_Decrypt_Tests(unittest.TestCase):
    def setUp(self):
        super(ECC_Decrypt_Tests, self).setUp()
        self.ecc = pyecc.ECC(public=DEFAULT_PUBKEY, private=DEFAULT_PRIVKEY)

    def test_BasicDecrypt(self):
        encrypted = "\x01\xdb?\xb7|-\x93EF\x16\xa2~\x96\x04\x15\xbaA\xef\x81!\xe8\xaa\x85,\xc8\x13\x86\x8ao'\x98\xee\xa8\xa3\xe0\x07J=6G\xba\\\xf3\xce\xa3\x9e~\xf5\x9d0\xdb\x11}e\xf0\x82\xd0\x92\xfc$S\xd4\xad\xe6\xf0Y\x15\xfe\xadw_+\xff@\x1a \xba\x01N\x95\x9d\x08\xe4\xe1\xcbl\xc5=\xbb\x0e\xacQ\x1e\xd8Q"
        decrypted = self.ecc.decrypt(encrypted)
        assert decrypted  == DEFAULT_PLAINTEXT
        

if __name__ == '__main__':
    suites = []
    items = copy.copy(locals())
    for k, v in items.iteritems():
        if isinstance(v, types.TypeType) and issubclass(v, unittest.TestCase):
            suites.append(unittest.makeSuite(v))

    runner = unittest.TextTestRunner()
    if 'xml' in sys.argv:
        import xmlrunner
        runner = xmlrunner.XMLTestRunner(filename='Pyecc.pytests.xml')

    results = runner.run(unittest.TestSuite(suites))
