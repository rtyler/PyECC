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
DEFAULT_SIG = '#cE/UfJ@]qte8w-ajzi%S%tO<?$?@QK_hTL&pk-ES1L~C9~4lpm+P7ZXu[mXTJ:%tdhQa:z~~q)BAw{.3dvt!ub+s?sXyxk;S%&+^P-~%}+G3G?Oj-nSDc/'
DEFAULT_PUBKEY = '#&M=6cSQ}m6C(hUz-7j@E=>oS#TL3F[F[a[q9S;RhMh+F#gP|Q6R}lhT_e7b'
DEFAULT_PRIVKEY = '!!![t{l5N^uZd=Bg(P#N|PH#IN8I0,Jq/PvdVNi^PxR,(5~p-o[^hPE#40.<|'
DEFAULT_PLAINTEXT = 'This is a very very secret message!\n'

class ECC_KeyGen_Tests(unittest.TestCase):
    def test_GenerateBoth(self):
        ecc = pyecc.ECC.generate()
        print ('private', 'public', ecc._private, len(ecc._private), 
                ecc._public, len(ecc._public))

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
        encrypted = "\x01\xa9\xc0\x1a\x03\\h\xd8\xea,\x8f\xd6\x91W\x8d\xe74x:\x1d\xa8 \xee\x0eD\xfe\xb6\xb0P\x04\xbf\xd5=\xf1?\x00\x9cDw\xae\x0b\xc3\x05BuX\xf1\x9a\x05f\x81\xd1\x15\x8c\x80Q\xa6\xf9\xd7\xf0\x8e\x99\xf2\x11<t\xff\x92\x14\x1c%0W\x8e\x8f\n\n\x9ed\xf8\xff\xc7p\r\x03\xbbw|\xb1h\xc9\xbd+\x02\x87"
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
