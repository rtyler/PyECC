'''
Copyright 2009 Slide, Inc.
'''

import _pyecc

class ECC(object):
    '''
        The ECC object must be instantiated to work with
        any encrypted data, as some amount of state is required
        at once
    '''
    def __init__(self, *args, **kwargs):
        self._private = kwargs.get('private')
        self._public = kwargs.get('public')
        assert self._private and self._public
        self._state = _pyecc.new_state()
        self._kp = _pyecc.new_keypair(self._public, self._private, self._state)

    def encrypt(self, plaintext):
        assert plaintext, 'You cannot encrypt "nothing"'
        return _pyecc.encrypt(plaintext, len(plaintext), self._kp, self._state)

    def decrypt(self, ciphertext):
        assert ciphertext, 'You cannot decrypt "nothing"'
        return _pyecc.decrypt(ciphertext, self._kp, self._state)

    def sign(self, data):
        if not self._kp:
            print 'You need a keypair object to verify a signature'
            return False

        if not self._state:
            print 'ECC object should have an internal _state member'
            return False

        return _pyecc.sign(data, self._kp, self._state)

    def verify(self, data, signature):
        if not self._kp:
            print 'You need a keypair object to verify a signature'
            return False

        if not self._state:
            print 'ECC object should have an internal _state member'
            return False

        return _pyecc.verify(data, signature, self._kp, self._state)
