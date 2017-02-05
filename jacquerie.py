#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from crypto import Crypto
import input


def main():
    crypt = Crypto(seed=input.get_password())
    chatting = True
    while chatting:
        input.get_chat_message(private=False)


if __name__ == '__main__':
    main()
