#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nacl.encoding
import nacl.signing
import nacl.secret


class Crypto:
    def __init__(self, seed, group_key):
        """
        :param seed: Password used to seed the signing key
        :param group_key: Group key used to encrypt and decrypt messages
        """
        self.signing_key = nacl.signing.SigningKey(seed=seed).generate()
        self.group_key = group_key
        assert len(group_key) == nacl.secret.SecretBox.KEY_SIZE
        self.box = nacl.secret.SecretBox(key=group_key)


    def gen_signature(self, timestamp):
        """
        Adds digital signature to a message by encrypting timestamp with private key
        :param timestamp: String of timestamp
        :return:
        """
        return self.signing_key.sign(timestamp.encode(encoding='UTF-8'))

    def encrypt(self, message, timestamp, signature):
        """
        Encrypts a message using the Group key
        :param message:
        :return:
        """
        encrypted = {}
        encrypted["signature"] = signature
        return encrypted
