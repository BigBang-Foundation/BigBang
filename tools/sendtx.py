#!/usr/bin/env python

# -*- coding: utf-8 -*-

import json
import subprocess
import sys
import csv

forkid = '00000001f90de448a1b44af5c8be561fcf74f541e4c7f5ee97a1b1547d5ff713'
forkid_f = '-f=' + forkid
balance_address = '1g66h2r2zmwdq6avx0vp31tjvxc6vys0h3bd39vxre95k30vb3rhv0yeh'
password = '123'
datadir = '-datadir=/home/ubuntu/mainnet-test/v2.1-test'
bigbang_bin = '/home/ubuntu/mainnet-test/v2.1-test/bigbang'


def unlockkey(addr, password):
    json_str = subprocess.check_output(
        [bigbang_bin, datadir, 'unlockkey', addr, password])
    return json_str


def makekeypair():
    json_str = subprocess.check_output([bigbang_bin, datadir, 'makekeypair'])
    json_obj = json.loads(json_str)
    return (json_obj['privkey'], json_obj['pubkey'])


def getpubkeyaddress(pubkey):
    json_str = subprocess.check_output(
        [bigbang_bin, datadir, 'getpubkeyaddress', pubkey])
    return json_str


def sendfrom(forkid, from_addr, to_addr, value):
    json_str = subprocess.check_output([
        bigbang_bin, datadir, 'sendfrom', forkid_f, from_addr, to_addr, value
    ])
    return json_str


def main():

    title = ('forkid', 'privkey', 'pubkey', 'address', 'txid')

    f = open('test.csv', 'w')
    writer = csv.writer(f)
    writer.writerow(title)
    unlockkey(balance_address, password)
    for i in range(2000):
        (privkey, pubkey) = makekeypair()
        to_address = getpubkeyaddress(pubkey)
        txid = sendfrom(forkid.strip(), balance_address.strip(), to_address.strip(), 1000)
        if len(txid) > 0:
            print "tx send success, txid: %s, to_addr: %s" % (txid, to_address)
            writer.writerow((forkid, privkey, pubkey, to_address, txid))

    f.close()


if __name__ == '__main__':
    main()