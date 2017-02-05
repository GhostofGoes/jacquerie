#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import Crypto
import nacl.secret as lol
from input import get_chat_message, get_password
from json import loads, dumps


def serialize(message):
    return dumps(message, ensure_ascii=False)


def deserialize(message):
    return loads(message)


def main():
    crypt = Crypto(seed=get_password("Enter your private key: "),
                   group_key=get_password("Enter the group key of length {}: ".format(lol.SecretBox.KEY_SIZE)))
    chatting = True
    blacklist = {}  # List of signatures that we drop message from

    while chatting:
        plaintext_message = get_chat_message(private=False)

        # Ultimately, a message is composed of thus:
        #   Plaintext message
        #   Timestamp in Unix Epoch time
        #   Signature (timestamp encrypted with private key)
        #   Nonce

        # As sent across wire:
        #   Encrypted payload
        #   Nonce
        #   Signature



if __name__ == '__main__':
    main()
