'''
Copyright 2009 Slide, Inc.
'''

import _pyecc

class KeyPair(object):
    '''
        KeyPair object contains the references to 
        an encrypted private key, and an unencrypted
        public key
    '''
    def __init__(self, *args, **kwargs):
        self._private = kwargs.get('private_key')
        self._public = kwargs.get('public_key')

    @staticmethod
    def generate(private_key=None):
        '''
            Generate a new KeyPair object, if specified
            the `private_key` will be used to generate a
            valid ECC public key.

            If `private_key` is not specified, then a 
            private key will also be generated
        '''
        pass


class ECC(object):
    '''
        The ECC object must be instantiated to work with
        any encrypted data, as some amount of state is required
        at once
    '''
    def __init__(self, *args, **kwargs):
        pass

    def encrypt(self, plaintext):
        pass

    def decrypt(self, ciphertext):
        pass

    def sign(self, data):
        pass

    def verify(self, data, signature):
        pass
