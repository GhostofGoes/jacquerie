#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import Crypto
from input import get_chat_message, get_password


def main():
    crypt = Crypto(seed=get_password("Enter your private key: "),
                   group_key=get_password("Enter the group key: "))
    chatting = True
    while chatting:
        msg = get_chat_message(private=False)


if __name__ == '__main__':
    main()
