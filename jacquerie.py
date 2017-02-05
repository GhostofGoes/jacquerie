#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import Crypto
import nacl.utils
import nacl.secret
from user_input import get_chat_message, get_password
from pickle import loads, dumps
from time import time
from com import send_message, get_message
from datetime import datetime


# TODO: docopt for command line arguments


def serialize(message):
    return dumps(message)


def deserialize(message):
    return loads(message, encoding='UTF-8')


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
    enc = crypt.simple_encrypt(packed_message)
    package = {}
    package["payload"] = enc[0]
    package["nonce"] = enc[1]
    package["signature"] = crypt.gen_signature(timestamp)

    return serialize(package)
    # return package


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
    dec = crypt.simple_decrypt(package["payload"])

    # Deserialize decrypted payload into a dict
    unpacked = deserialize(dec)

    # Verify signature
    crypt.verify(signed=package["signature"])

    return unpacked


def main():
    chatting = True
    blacklist = {}  # List of signatures that we drop messages from

    group_key = get_password("Enter the group key of length {}: ".format(nacl.secret.SecretBox.KEY_SIZE))
    # group_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    seed = get_password("Enter your private key: ")
    crypt = Crypto(seed, group_key)

    handle = get_password("Enter a handle you want to be known as: ")
    print("Chat format: (Handle : Letter(s)) [Timestamp] Message")

    while chatting:
        try:
            plaintext = get_chat_message(private=False)  # Unicode String
        except KeyboardInterrupt:
            print("\nSecurely exiting...")
            break

        packet = build_message(message=str(plaintext), handle=handle, crypt=crypt)
        send_message(packet)

        received_msg = packet # get_message()
        good = unpack_message(received_msg, crypt, blacklist)
        # TODO: determine letters from signatures
        temp_letters = "Q"
        message_time = datetime.utcfromtimestamp(int(float(good["timestamp"]))).strftime('%H:%M:%S')
        message_text = eval(good["message"])
        message_text = str(message_text["Message"])
        print("({0} : {1}) [{2}] {3}".format(good["handle"], temp_letters,
                                             message_time, message_text))


if __name__ == '__main__':
    main()
