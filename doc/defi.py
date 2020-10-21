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

rpcurl = 'http://127.0.0.1:9902'

genesis_privkey = '9df809804369829983150491d1086b99f6493356f91ccc080e661a76a976a4ee'
genesis_addr = '1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm'
dpos_privkey = '9f1e445c2a8e74fabbb7c53e31323b2316112990078cbd8d27b2cd7100a1648d'
dpos_pubkey = 'fe8455584d820639d140dad74d2644d742616ae2433e61c0423ec350c2226b78'
password = '123'

GENERATE_ADDR_MODE = 0
CREATE_NODE_MODE = 1
CHECK_MODE = 2
mode = None


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
def makeorigin(prev, owner, amount, name, symbol, reward, halvecycle, forktype=None, defi=None):
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
            'defi': defi,
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
    sendfrom(genesis_addr, delegate_addr, 280000000)
    print('Create dpos node success')


# create fork
def create_fork(prev, amount, name, symbol, defi):
    prev = getblockhash(0)[0]
    forkid, data = makeorigin(
        prev, genesis_addr, amount, name, symbol, 0, 0, 'defi', defi)

    fork_addr = addforktemplate(genesis_addr, forkid)
    sendfrom(genesis_addr, fork_addr, 100000, None, 0, data)
    print('Create fork success, forkid: {}'.format(forkid))
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


# generate address mode
def generate_addr():
    generate_count = 50000 if len(sys.argv) < 4 else int(sys.argv[3])
    root_count = min(generate_count / 100, 1000)
    privkey_map = {}
    stake_map = {}
    relation_map = {}
    for i in range(0, generate_count):
        pubkey, privkey = makekeypair()
        addr = getpubkeyaddress(pubkey)
        addr = addr.encode('raw_unicode_escape')
        if i < root_count:
            privkey_map[addr] = privkey
        else:
            if len(privkey_map) == 0:
                upper = genesis_addr
            else:
                upper = privkey_map.keys()[int(
                    random.random() * len(privkey_map))]
            relation_map[addr] = upper
            if len(privkey_map) < 1000:
                privkey_map[addr] = privkey
        stake_map[addr] = int(random.random() * 20000000 + 100000000)

    privkey_list = [v for _, v in privkey_map.items()]
    print(json.dumps({
        'privkey': privkey_list,
        'stake': stake_map,
        'relation': relation_map
    }))


# create node mode
def create_node(path):
    input = {}
    # load json
    with open(path, 'r') as r:
        content = json.loads(r.read())
        input = content["input"]

    # compute balance by stake and relation
    addrset = {}
    for addr, stake in input['stake'].items():
        addrset[addr] = {
            'stake': float(stake) / COIN,
            'upper': None,
            'lower': []
        }

    for lower_addr, upper_addr in input['relation'].items():
        if lower_addr not in addrset:
            addrset[lower_addr] = {
                'stake': 0,
                'upper': None,
                'lower': []
            }

        if upper_addr not in addrset:
            addrset[upper_addr] = {
                'stake': 0,
                'upper': None,
                'lower': []
            }

        addrset[lower_addr]['upper'] = upper_addr
        addrset[upper_addr]['lower'].append(lower_addr)

    for addr, obj in addrset.items():
        obj['stake'] = obj['stake'] - \
            (0.01 if obj['upper'] else 0) + 0.02 * len(obj['lower'])

    # import priv key
    for privkey in input['privkey']:
        if privkey != genesis_privkey:
            importprivkey(privkey, False)

    # delegate dpos
    dpos()

    # create fork
    if 'makeorigin' not in input:
        raise Exception('Can not create fork, no "makeorigin" in input')

    fork = input['makeorigin']
    forkid = create_fork(getblockhash(0), fork['amount'],
                         fork['name'], fork['symbol'], fork['defi'])

    # wait fork
    while True:
        print("Waitting fork...")
        if getgenealogy(forkid):
            break
        time.sleep(10)

    time.sleep(10)
    # send token to addrset
    for addr, obj in addrset.items():
        if addr != genesis_addr:
            sendfrom(genesis_addr, addr, obj['stake'], forkid)

    # send relation tx
    for addr, obj in addrset.items():
        for lower_addr in obj['lower']:
            sendfrom(addr, lower_addr, 0.01, forkid, 2)

    print("forkid: {}".format(forkid))
    genesis_balance = getbalance(genesis_addr, forkid)
    print("genesis_balance: {}".format(int(round(genesis_balance * COIN))))


# check mode
def check(path):
    input = {}
    output = []
    # load json
    with open(path, 'r') as r:
        content = json.loads(r.read())
        input = content["input"]
        output = content["output"]

    # compute balance by stake and relation
    addrset = {}
    for addr, stake in input['stake'].items():
        addrset[addr] = {
            'stake': float(stake) / COIN,
            'upper': None,
            'lower': []
        }

    for lower_addr, upper_addr in input['relation'].items():
        if lower_addr not in addrset:
            addrset[lower_addr] = {
                'stake': 0,
                'upper': None,
                'lower': []
            }

        if upper_addr not in addrset:
            addrset[upper_addr] = {
                'stake': 0,
                'upper': None,
                'lower': []
            }

        addrset[lower_addr]['upper'] = upper_addr
        addrset[upper_addr]['lower'].append(lower_addr)

    # check mode
    fork = input['makeorigin']
    forkid = fork['forkid']

    # mint height & reward cycle
    mint_height = 2 if ('mintheight' not in fork['defi']) or (
        fork['defi'] == -1) else fork['defi']['mintheight']
    reward_cycle = fork['defi']['rewardcycle']

    # check reward
    for result in output:
        height = result['height']
        reward = result['reward']
        # remove 0 reward
        for addr in reward.keys():
            if reward[addr] == 0:
                del(reward[addr])

        print('Checking height [{}]...'.format(height))

        if ((height - mint_height) % reward_cycle != 0):
            print('ERROR: height [{}] is not a reward height'.format(height))
            continue

        # query reward tx beginning with height
        h = height
        while True:
            blockids = None
            # loop to query the block of height
            while True:
                print('Waiting block of height: {}...'.format(h))
                blockids = getblockhash(h, forkid)
                if blockids:
                    break
                print('fork height is {}'.format(getforkheight(forkid)))
                time.sleep(60)
            print('blockids of height: {}, blockids: {}'.format(height, blockids))

            error = False
            # loop to get every block of blockid array
            for hash in blockids:
                block = getblock(hash)

                # if block is vacant, continue to get next height block
                if block['type'] == 'vacant':
                    h = h + 1
                    break

                # if no tx in block, print error
                if len(block['tx']) == 0:
                    print('ERROR: no reward tx in height: {}'.format(height))

                # loop to check every tx in block
                for txid in block['tx']:
                    tx = gettransaction(txid)

                    if len(reward) == 0:
                        break

                    # miss reward tx in height
                    if tx['type'] != 'defi-reward':
                        print('ERROR: miss reward tx in height: {}, left reward: {}'.format(
                            height, reward))
                        reward, error = {}, True
                        break

                    anchor = int(tx['anchor'][:8], 16)
                    # previous sectin reward tx
                    if anchor < height - 1:
                        continue
                    # next sectin reward tx
                    elif anchor > height - 1:
                        print('ERROR: no reward tx in height: {}, left reward: {}'.format(
                            height, reward))
                        reward, error = {}, True
                        break

                    # check the reward of address correct or not
                    if tx['sendto'] in reward:
                        should_reward = int(reward[tx['sendto']])
                        actrual_reward = int(round(
                            (tx['amount'] + tx['txfee']) * COIN))
                        if should_reward != actrual_reward:
                            print('ERROR: addr reward error in height, addr: {}, height: {} should be: {}, actrual: {}'.format(
                                tx['sendto'], height, should_reward, actrual_reward))
                            error = True
                        del(reward[tx['sendto']])

                if len(reward) == 0:
                    break

            if error:
                print('Checking failed height: {}'.format(height))
                break
            elif len(reward) == 0:
                print('Checking success height: {}'.format(height))
                break


if __name__ == "__main__":
    # json path
    if len(sys.argv) < 2:
        raise Exception('No json file')

    path = os.path.join(os.getcwd(), sys.argv[1])

    mode = CREATE_NODE_MODE
    if len(sys.argv) >= 3:
        if sys.argv[2] == '-generate':
            mode = GENERATE_ADDR_MODE
        elif sys.argv[2] == '-check':
            mode = CHECK_MODE
    print_mode()

    # generate address and relation mode
    if mode == GENERATE_ADDR_MODE:
        generate_addr()
        exit(0)
    elif mode == CREATE_NODE_MODE:
        create_node(path)
        exit(0)
    elif mode == CHECK_MODE:
        check(path)
        exit(0)
