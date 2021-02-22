#!/usr/bin/env python

import time
import requests
import json
from collections import OrderedDict
import os
import sys
import random
from pprint import pprint

COIN = 1000000
TX_FEE = 0.01

rpcurl = 'http://127.0.0.1:9902'

genesis_privkey = '9df809804369829983150491d1086b99f6493356f91ccc080e661a76a976a4ee'
genesis_addr = '1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm'
dpos_privkey = '9f1e445c2a8e74fabbb7c53e31323b2316112990078cbd8d27b2cd7100a1648d'
dpos_pubkey = 'fe8455584d820639d140dad74d2644d742616ae2433e61c0423ec350c2226b78'
password = '123'
blackhole_addr = '100000000000000000000000000000000000000000000000000000000'

GENERATE_ADDR_MODE = 0
CREATE_NODE_MODE = 1
CHECK_MODE = 2
mode = None


def bytesToHexString(bs):
    return ''.join(['%02X' % b for b in bs])


# RPC HTTP request
def call(body):
    req = requests.post(rpcurl, json=body)

    if mode != GENERATE_ADDR_MODE:
        print('DEBUG: request: {}'.format(body))
        print('DEBUG: response: {}'.format(req.content))

    resp = json.loads(req.content.decode('utf-8'))
    return resp.get('result'), resp.get('error')


# RPC: makekeypair
def makekeypair():
    result, error = call({
        'id': 0,
        'jsonrpc': '1.0',
        'method': 'makekeypair',
        'params': {}
    })

    if result:
        pubkey = result.get('pubkey')
        privkey = result.get('privkey')
        # print('makekeypair success, pubkey: {}'.format(pubkey))
        return pubkey, privkey
    else:
        raise Exception('makekeypair error: {}'.format(error))


# RPC: getnewkey
def getnewkey():
    result, error = call({
        'id': 0,
        'jsonrpc': '1.0',
        'method': 'getnewkey',
        'params': {
            'passphrase': password
        }
    })

    if result:
        pubkey = result
        # print('getnewkey success, pubkey: {}'.format(pubkey))
        return pubkey
    else:
        raise Exception('getnewkey error: {}'.format(error))


# RPC: getpubkeyaddress
def getpubkeyaddress(pubkey):
    result, error = call({
        'id': 0,
        'jsonrpc': '1.0',
        'method': 'getpubkeyaddress',
        'params': {
            "pubkey": pubkey
        }
    })

    if result:
        address = result
        # print('getpubkeyaddress success, address: {}'.format(address))
        return address
    else:
        raise Exception('getpubkeyaddress error: {}'.format(error))


# RPC: importprivkey
def importprivkey(privkey, synctx=True):
    result, error = call({
        'id': 0,
        'jsonrpc': '1.0',
        'method': 'importprivkey',
        'params': {
            'privkey': privkey,
            'passphrase': password,
            'synctx': synctx
        }
    })

    if result:
        pubkey = result
        # print('importprivkey success, pubkey: {}'.format(pubkey))
        return pubkey
    else:
        raise Exception('importprivkey error: {}'.format(error))


# RPC: getbalance
def getbalance(addr, forkid=None):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'getbalance',
        'params': {
            'address': addr,
            'fork': forkid
        }
    })

    if result and len(result) == 1:
        avail = result[0].get('avail')
        # print('getbalance success, avail: {}'.format(avail))
        return avail
    else:
        raise Exception('getbalance error: {}'.format(error))


# RPC: unlockkey
def unlockkey(key):
    call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'unlockkey',
        'params': {
            'pubkey': key,
            'passphrase': password
        }
    })


# RPC: sendfrom
def sendfrom(from_addr, to, amount, fork=None, type=0, data=None):
    unlockkey(from_addr)

    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'sendfrom',
        'params': {
            'from': from_addr,
            'to': to,
            'amount': amount,
            'fork': fork,
            'type': type,
            'data': data
        }
    })

    if result:
        txid = result
        # print('sendfrom success, txid: {}'.format(txid))
        return txid
    else:
        raise Exception('sendfrom error: {}'.format(error))


# RPC: makeorigin
def makeorigin(prev, owner, amount, name, symbol, reward, halvecycle, forktype=None, uee=None):
    unlockkey(owner)

    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'makeorigin',
        'params': {
            'prev': prev,
            'owner': owner,
            'amount': amount,
            'name': name,
            'symbol': symbol,
            'reward': reward,
            'halvecycle': halvecycle,
            'forktype': forktype,
            'uee': uee
        }
    })

    if result:
        forkid = result.get('hash')
        data = result.get('hex')
        # print('makeorigin success, forkid: {}, data: {}'.format(forkid, data))
        return forkid, data
    else:
        print(error)
        raise Exception('makeorgin error: {}'.format(error))


# RPC: addnewtemplate fork
def addforktemplate(redeem, forkid):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'addnewtemplate',
        'params': {
            'type': 'fork',
            'fork': {
                'redeem': redeem,
                'fork': forkid,
            }
        }
    })

    if result:
        addr = result
        # print('addforktemplate success, template address: {}'.format(addr))
        return addr
    else:
        raise Exception('addforktemplate error: {}'.format(error))


# RPC: addnewtemplate delegate
def adddelegatetemplate(delegate, owner):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'addnewtemplate',
        'params': {
            'type': 'delegate',
            'delegate': {
                'delegate': delegate,
                'owner': owner,
            }
        }
    })

    if result:
        addr = result
        # print('adddelegatetemplate success, template address: {}'.format(addr))
        return addr
    else:
        raise Exception('adddelegatetemplate error: {}'.format(error))

# RPC: addnewtemplate ueesign
def addueesigntemplate(owner, admin):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'addnewtemplate',
        'params': {
            'type': 'ueesign',
            'ueesign': {
                'owner': owner,
                'admin': admin,
            }
        }
    })

    if result:
        addr = result
        # print('addueesigntemplate success, template address: {}'.format(addr))
        return addr
    else:
        raise Exception('addueesigntemplate error: {}'.format(error))


# RPC: getforkheight
def getforkheight(forkid=None):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'getforkheight',
        'params': {
            'fork': forkid,
        }
    })

    if result:
        height = result
        # print('getforkheight success, height: {}'.format(height))
        return height
    else:
        return None


# RPC: getblockhash
def getblockhash(height, forkid=None):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'getblockhash',
        'params': {
            'height': height,
            'fork': forkid,
        }
    })

    if result:
        block_hash = result
        # print('getblockhash success, block hash: {}'.format(block_hash))
        return block_hash
    else:
        return None


# RPC: getblock
def getblock(blockid):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'getblock',
        'params': {
            'block': blockid,
        }
    })

    if result:
        block = result
        # print('getblock success, block: {}'.format(block))
        return block
    else:
        raise Exception('getblock error: {}'.format(error))


# RPC: getblockdetail
def getblockdetail(blockid):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'getblockdetail',
        'params': {
            'block': blockid,
        }
    })

    if result:
        block = result
        # print('getblockdetail success, block: {}'.format(block))
        return block
    else:
        raise Exception('getblockdetail error: {}'.format(error))


# RPC: gettransaction
def gettransaction(txid):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'gettransaction',
        'params': {
            'txid': txid,
        }
    })

    if result:
        tx = result['transaction']
        # print('gettransaction success, tx: {}'.format(tx))
        return tx
    else:
        raise Exception('gettransaction error: {}'.format(error))


# RPC: getgenealogy
def getgenealogy(forkid):
    result, _ = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'getgenealogy',
        'params': {
            'fork': forkid,
        }
    })

    if result:
        return True
    else:
        return False

# RPC: listfork
def listfork():
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'listfork',
        'params': {
        }
    })

    if result:
        forklist = result
        # print('listfork success, forklist: {}'.format(forklist))
        return forklist
    else:
        raise Exception('listfork error: {}'.format(error))

# createtransaction
def createtransaction(from_addr, to, amount, fork=None, type=0, data=None):
    unlockkey(from_addr)

    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'createtransaction',
        'params': {
            'from': from_addr,
            'to': to,
            'amount': amount,
            'fork': fork,
            'type': type,
            'data': data
        }
    })

    if result:
        txdata = result
        print('createtransaction success, txdata: {}'.format(txdata))
        return txdata
    else:
        raise Exception('createtransaction error: {}'.format(error))

# signtransaction
def signtransaction(txdata, appenddata, appendsign):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'signtransaction',
        'params': {
            'txdata': txdata,
            'appenddata': appenddata,
            'appendsign': appendsign
        }
    })

    if result:
        hex = result['hex']
        print('signtransaction success, hex: {}'.format(hex))
        return hex
    else:
        raise Exception('signtransaction error: {}'.format(error))

# signtransactiondata
def signtransactiondata(address, txdata):
    unlockkey(address)

    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'signtransactiondata',
        'params': {
            'address': address,
            'txdata': txdata
        }
    })

    if result:
        txdata = result
        print('signtransactiondata success, txdata: {}'.format(txdata))
        return txdata
    else:
        raise Exception('signtransactiondata error: {}'.format(error))

# sendtransaction
def sendtransaction(txdata):
    result, error = call({
        'id': 1,
        'jsonrpc': '2.0',
        'method': 'sendtransaction',
        'params': {
            'txdata': txdata
        }
    })

    if result:
        txid = result
        print('sendtransaction success, txid: {}'.format(txid))
        return txid
    else:
        raise Exception('sendtransaction error: {}'.format(error))


# create dpos node
def dpos():
    # import genesis key
    genesis_pubkey = importprivkey(genesis_privkey)

    # check genesis addr balance
    addr = getpubkeyaddress(genesis_pubkey)
    if genesis_addr != getpubkeyaddress(genesis_pubkey):
        raise Exception(
            'genesis addr [{}] is not equal {}'.format(addr, genesis_addr))

    genesis_balance = getbalance(genesis_addr)
    if genesis_balance <= 0:
        raise Exception('No genesis balance: {}'.format(genesis_balance))

    # create delegate
    delegate_addr = adddelegatetemplate(dpos_pubkey, genesis_addr)
    sendfrom(genesis_addr, delegate_addr, 250000000)
    print('Create dpos node success')
    return delegate_addr


# create fork
def create_fork(prev, amount, name, symbol, uee):
    prev = getblockhash(0)[0]
    forkid, data = makeorigin(
        prev, genesis_addr, amount, name, symbol, 0, 0, 'uee', uee)

    fork_addr = addforktemplate(genesis_addr, forkid)
    sendfrom(genesis_addr, fork_addr, 100000, None, 0, data)
    print('Create uee fork success, forkid: {}'.format(forkid))
    return forkid



# print mode
def print_mode():
    if mode == GENERATE_ADDR_MODE:
        print("###### Generate address mode")
    elif mode == CREATE_NODE_MODE:
        print("###### Create node mode")
    elif mode == CHECK_MODE:
        print("###### Check mode")
    else:
        print("###### Unknown mode")


# create uee fork
def create_uee_fork(path):
    input = {}
    # load json
    with open(path, 'r') as r:
        content = json.loads(r.read())
        input = content["input"]

    # create fork
    if 'makeorigin' not in input:
        raise Exception('Can not create fork, no "makeorigin" in input')

    fork = input['makeorigin']
    print("fork json: {}".format(fork))
    forkid = create_fork(getblockhash(0), fork['amount'],
                         fork['name'], fork['symbol'], fork['uee'])

    print("create forkid: {}".format(forkid))

    # wait fork
    while True:
        print("Waitting fork...")
        if getgenealogy(forkid):
            break
        time.sleep(10)
        
    print("create fork success, forkid: {}".format(forkid))

    importprivkey("cb412ba9b0910e0a53a33afce3ae42a833889521d97079da9e9f83679623eca9")
    ueesignaddress = addueesigntemplate("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm","1gd0pzm763kjma975t1ndcfg96yyczsgkg7bef28g20redxy9z3pv6mr0")
    print("addueesigntemplate success ,ueesignaddress: {}".format(ueesignaddress))

    unlockkey("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm")
    txid = sendfrom("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm", ueesignaddress, 1, forkid)
    print("sendfrom success, txid: {}".format(txid))

# send uee rule1 tx
def send_uee_rule1_tx(path):
    unlockkey("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm")
    unlockkey("1gd0pzm763kjma975t1ndcfg96yyczsgkg7bef28g20redxy9z3pv6mr0")

    forklist = listfork()
    ueeforkid = "null"
    for fork in forklist:
        if fork["forktype"]=="uee":
            ueeforkid = fork["fork"]
            break

    if ueeforkid == "null":
        raise Exception('No create uee fork')
    
    rule = bytesToHexString(b"{\"rule\":\"rule1\",\"signaddress\": \"21g0f96thcqf3qjgybyj0jnyg971c69znwkne9a56q0ydd2p6tzermj4d\",\"param1\": \"6601\",\"param2\": \"1001\",\"var1\": 3}")

    txdata = createtransaction("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm", "1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm", 1, ueeforkid, 5, rule)

    admin_sign_data = signtransactiondata("1gd0pzm763kjma975t1ndcfg96yyczsgkg7bef28g20redxy9z3pv6mr0", txdata)

    send_txdata = signtransaction(txdata, "0c0001498b63009dfb70f7ee0902ba95cc171f7d7a97ff16d89fd96e1f1b9e7d5f91da0183416fd0e61ce54524e5d06ad63e0937bccfe61381d6e789101030e6f7c9f8ed", admin_sign_data)

    send_txid = sendtransaction(send_txdata)

    print('send success, txid: {}'.format(send_txid))

# send uee rule2 tx
def send_uee_rule2_tx(path):
    unlockkey("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm")
    unlockkey("1gd0pzm763kjma975t1ndcfg96yyczsgkg7bef28g20redxy9z3pv6mr0")

    forklist = listfork()
    ueeforkid = "null"
    for fork in forklist:
        if fork["forktype"]=="uee":
            ueeforkid = fork["fork"]
            break

    if ueeforkid == "null":
        raise Exception('No create uee fork')
    
    rule = bytesToHexString(b"{\"rule\":\"rule2\",\"signaddress\": \"21g0f96thcqf3qjgybyj0jnyg971c69znwkne9a56q0ydd2p6tzermj4d\",\"param1\": \"6601\",\"param2\": \"1001\",\"var1\": 2,\"var2\": 4}")

    txdata = createtransaction("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm", "1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm", 1, ueeforkid, 5, rule)

    admin_sign_data = signtransactiondata("1gd0pzm763kjma975t1ndcfg96yyczsgkg7bef28g20redxy9z3pv6mr0", txdata)

    send_txdata = signtransaction(txdata, "0c0001498b63009dfb70f7ee0902ba95cc171f7d7a97ff16d89fd96e1f1b9e7d5f91da0183416fd0e61ce54524e5d06ad63e0937bccfe61381d6e789101030e6f7c9f8ed", admin_sign_data)

    send_txid = sendtransaction(send_txdata)

    print('send success, txid: {}'.format(send_txid))


def test(path):
    forklist = listfork()
    #print(forklist)
    for forkinfo in forklist:
        print(forkinfo["forktype"])


if __name__ == "__main__":
    # json path
    if len(sys.argv) < 2:
        raise Exception('No json file')

    path = os.path.join(os.getcwd(), sys.argv[1])
    print('work path: {}'.format(path))

    calltype = 0
    callcount = 1
    if len(sys.argv) >= 3:
        if sys.argv[2] == '-sendueetx1':
            calltype = 0
            if len(sys.argv) >= 4:
                callcount = int(sys.argv[3])
        elif sys.argv[2] == '-sendueetx2':
            calltype = 1
            if len(sys.argv) >= 4:
                callcount = int(sys.argv[3])
        elif sys.argv[2] == '-sendueetx0':
            calltype = 2
            if len(sys.argv) >= 4:
                callcount = int(sys.argv[3])
        elif sys.argv[2] == '-createfork':
            calltype = 3
        elif sys.argv[2] == '-test':
            calltype = 9

    if calltype == 0:
        for i in range(0, callcount):
            send_uee_rule1_tx(path)
    elif calltype == 1:
        for i in range(0, callcount):
            send_uee_rule2_tx(path)
    elif calltype == 2:
        for i in range(0, callcount):
            send_uee_rule1_tx(path)
            send_uee_rule2_tx(path)
    elif calltype == 3:
        create_uee_fork(path)
    elif calltype == 9:
        test(path)
    else:
        test(path)
        