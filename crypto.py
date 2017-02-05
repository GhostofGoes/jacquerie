#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nacl.encoding
import nacl.signing


class Crypto:
    def __init__(self, seed):
        """
        :param seed: Password used to seed the signing key
        """
        assert type(seed) is tuple
        self.signing_key = nacl.signing.SigningKey(seed=seed).generate()

    def add_signature(self, message):
        """
        Adds digital signature to a message by encrypting timestamp with private key
        :param message: Message
        :return:
        """
        assert type(message) is dict
        message["signature"] = self.signing_key.sign(message["timestamp"].encode(encoding='UTF-8'))
        return message
