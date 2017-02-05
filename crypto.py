#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nacl.encoding
import nacl.signing
import nacl.secret
import nacl.utils
from nacl.exceptions import BadSignatureError


class Crypto:
    def __init__(self, seed, group_key):
        """
        :param seed: Password used to seed the signing key
        :param group_key: Group key used to encrypt and decrypt messages
        """
        self.signing_key = nacl.signing.SigningKey(seed=seed.encode('UTF-8')).generate()  # PRIVATE KEY ARRRRR MATEY
        self.verify_key = self.signing_key.verify_key  # PUBLIC KEY
        self.box = nacl.secret.SecretBox(key=group_key.encode('UTF-8'))

    def gen_signature(self, timestamp):
        """
        Adds digital signature to a message by encrypting timestamp with private key
        :param timestamp: String of timestamp
        :return:
        """
        return self.signing_key.sign(timestamp.encode(encoding='UTF-8'))

    def verify(self, signed, timestamp):
        """
        Verify a signed message
        :param signed: Signed version of timestamp
        :param timestamp: Plaintext timestamp to compare against
        :return: Bytes or None (The NaCL package writers really like exceptions...)
        """
        try:
            return self.verify_key.verify(signed, timestamp)
        except BadSignatureError as e:
            print("UNVERIFIED MESSAGE! {}".format(e))
            return None

    def encrypt(self, message):
        """
        Encrypts a message using the Group key
        :param message: Serialized message
        :return: Tuple of Ciphertext and Nonce
        """
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        return self.box.encrypt(message, nonce), nonce

    def decrypt(self, message, nonce):
        """
        Decrypts a message using the Group key
        :param message: Serialized message
        :param nonce:
        :return:
        """
        return self.box.decrypt(message, nonce)
