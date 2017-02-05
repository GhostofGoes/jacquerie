#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import Crypto
import nacl.secret as lol
import nacl.utils
from user_input import get_chat_message, get_password
# from json import loads, dumps
from pickle import loads, dumps
from time import time
from com import send_message, get_message


def serialize(message):
    return dumps(message) #, ensure_ascii=False)


# todo: POSSIBLE DECODE?
def deserialize(message):
    return loads(message)


def build_message(message, handle, crypt):
    """
    Builds a message to send to a group
    :param message: Plaintext of message being sent
    :param handle: Handle of message being sent
    :param crypt: Crypto class object
    :return: Serialized packet containing: encrypted payload, nonce, signature
    """
    # Ultimately, a message is composed of thus:
    #   Plaintext message
    #   Timestamp in Unix Epoch time
    #   Signature (timestamp encrypted with private key)
    #   Nonce

    timestamp = str(time())  # Unix Epoch time
    packed_message = serialize({"message": message, "handle": handle, "timestamp": timestamp})

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


def unpack_message(message, crypt, blacklist):
    """
    Unpacks a received message
    :param message: Serialized message
    :param crypt: Crypto class object
    :param blacklist: Dictionary of signatures to ignore
    :return: Deserialized message as dict containing: message, timestamp, signature, (HANDLE??), (LETTER NAME??)
    """

    # Deserialize message into a dict
    package = deserialize(message)

    # Check if signature is in the blacklist
    if package["signature"] in blacklist:
        print("(DEBUG) Blacklisted message received!")  # TODO: debugging
        return {}  # EMPTY DICT FOR INVALID MESSAGES

    # Decrypt payload
    dec = crypt.decrypt(package["payload"], package["nonce"])

    # Deserialize decrypted payload into a dict
    unpacked = deserialize(dec)

    # Verify signature
    crypt.verify(signed=package["signature"], timestamp=unpacked["timestamp"])

    return unpacked


def main():
    crypt = Crypto(seed=get_password("Enter your private key: "),
                   group_key=get_password("Enter the group key of length {}: ".format(lol.SecretBox.KEY_SIZE)))
    handle = get_password("Enter a handle you want to be known as: ")
    print("Chat format: (Handle : Letter(s)) [Timestamp] Message")

    chatting = True
    blacklist = {}  # List of signatures that we drop message from

    while chatting:
        # TODO: chat output format
        plaintext = str(get_chat_message(private=False))  # Unicode String
        packet = build_message(message=plaintext, handle=handle, crypt=crypt)
        send_message(packet)

        received_msg = packet # get_message()
        good = unpack_message(received_msg, crypt, blacklist)
        # TODO: determine letters from signatures
        temp_letters = "Q"
        print("({0} : {1}) [{2}] {3}".format(good["handle"], temp_letters, good["timestamp"], good["message"]))


if __name__ == '__main__':
    main()
