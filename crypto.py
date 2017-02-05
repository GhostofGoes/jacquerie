#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nacl.utils
from nacl.public import PrivateKey, Box

skbob = PrivateKey.generate()

pkbob = skbob.public_key


