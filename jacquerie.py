#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import Crypto
import nacl.secret as lol
from input import get_chat_message, get_password
from json import loads, dumps
from time import time


def serialize(message):
    return dumps(message, ensure_ascii=False)


def deserialize(message):
    return loads(message)


def build_message(message, crypt):
    """
    Builds a message to send to a group
    :param message: Plaintext of message being sent
    :param crypt: Crypto class object
    :return: Serialized packet containing: encrypted payload, nonce, signature
    """
    # Ultimately, a message is composed of thus:
    #   Plaintext message
    #   Timestamp in Unix Epoch time
    #   Signature (timestamp encrypted with private key)
    #   Nonce

    plaintext = message
    timestamp = str(time())  # Unix Epoch time
    packed_message = serialize({"message": plaintext, "timestamp": timestamp})

    # As sent across wire:
    #   Encrypted payload
    #   Nonce
    #   Signature
    enc = crypt.encrypt(packed_message)
    package = {}
    package["payload"] = enc[0]
    package["nonce"] = enc[1]
    package["signature"] = crypt.gen_signature(timestamp)
    return serialize(package)


def main():
    crypt = Crypto(seed=get_password("Enter your private key: "),
                   group_key=get_password("Enter the group key of length {}: ".format(lol.SecretBox.KEY_SIZE)))
    chatting = True
    blacklist = {}  # List of signatures that we drop message from

    while chatting:
        plaintext = str(get_chat_message(private=False))  # Unicode String
        packet = build_message(message=plaintext, crypt=crypt)


if __name__ == '__main__':
    main()
