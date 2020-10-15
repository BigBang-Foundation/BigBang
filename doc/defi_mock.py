#!/usr/bin/env python
# encoding: utf-8

import time
import json
from collections import OrderedDict
import os
import sys
from functools import cmp_to_key
from pprint import pprint

COIN = 1000000

# Mark tree node level recursively


def MarkTreeLevel(root_addr, root_level, addrset):
    addrset[root_addr]['level'] = root_level
    # get childs
    childs = addrset[root_addr]['lower']
    for child in childs:
        MarkTreeLevel(child, root_level - 1, addrset)

# Compute DeFi rewards


def Compute(addrset, total_level, input, output, count):
    makeorigin = input['makeorigin']
    amount = makeorigin['amount'] * COIN
    defi = makeorigin['defi']
    rewardcycle = defi['rewardcycle']
    supplycycle = defi['supplycycle']
    mintheight = defi['mintheight']
    maxsupply = defi['maxsupply'] * COIN
    coinbasetype = defi['coinbasetype']
    decaycycle = defi['decaycycle']
    coinbasedecaypercent = float(defi['coinbasedecaypercent']) / 100
    initcoinbasepercent = float(defi['initcoinbasepercent']) / 100
    #mapcoinbasepercent = float(defi['mapcoinbasepercent']) / 100
    stakerewardpercent = float(defi['stakerewardpercent']) / 100
    promotionrewardpercent = float(defi['promotionrewardpercent']) / 100
    stakemintoken = defi['stakemintoken'] * COIN
    mappromotiontokentimes = defi['mappromotiontokentimes']

    reward_count = supplycycle / rewardcycle
    supply = amount
    next_supply = amount
    reward_percent = initcoinbasepercent
    coinbase = 0

    for i in range(0, count):
        # to upper limit
        if supply >= maxsupply:
            break

        height = mintheight + (i + 1) * rewardcycle
        result = {}
        for addr in addrset:
            result[addr] = 0

        if (height - mintheight) % decaycycle == 0:
            reward_percent *= coinbasedecaypercent

        if i == 0 or (height - mintheight) % supplycycle == 0:
            supply = next_supply
            next_supply = int(supply * (1 + reward_percent))
            coinbase = float(next_supply - supply) / supplycycle
            # too lower reward
            if next_supply - supply < COIN:
                break

        total_reward = int(round(coinbase * rewardcycle))
        # to upper limit
        if next_supply > maxsupply:
            last_reward = 0 if i == 0 else int(
                round(coinbase * (i % reward_count) * rewardcycle))
            max_reward = max(0, maxsupply - supply - last_reward)
            total_reward = min(total_reward, max_reward)

        # to upper limit
        if total_reward <= 0:
            break
        print("height:", height, "total_reward: ", total_reward)

        # compute stake reward
        stake_reward = int(total_reward * stakerewardpercent)
        print("stake_reward:", stake_reward)

        stake_addrset = [
            {'addr': k, 'info': v} for k, v in addrset.items() if v['stake'] >= stakemintoken]

        def cmp_stake(l, r):
            if l['info']['stake'] < r['info']['stake']:
                return -1
            elif l['info']['stake'] > r['info']['stake']:
                return 1
            else:
                return 0
        stake_addrset.sort(key=cmp_to_key(cmp_stake))

        real_rank = 0
        rank = 0
        prev = -1
        total = 0
        for v in stake_addrset:
            real_rank = real_rank + 1

            addr = v['addr']
            info = v['info']
            if info['stake'] > prev:
                prev = info['stake']
                rank = real_rank

            info['rank'] = rank
            print("addr:", addr, "rank:", rank, "stake:", info['stake'])
            total += rank

        stake_unit_reward = float(stake_reward) / total
        stake_addrset.sort()
        for v in stake_addrset:
            addr = v['addr']
            info = v['info']
            result[addr] += int(info['rank'] * stake_unit_reward)
            print('stake reward, addr: ', addr, ', reward: ', result[addr])

        # compute promotion reward
        promotion_reward = int(
            total_reward * promotionrewardpercent)
        print("promotion_reward:", promotion_reward)

        total_power = 0

        for j in range(0, total_level + 1):
            for addr, info in addrset.items():
                if info['level'] == j:
                    addrset[addr]['power'] = 0
                    addrset[addr]['sub_stake'] = info['stake'] / COIN
                    sub_stake_list = []
                    for sub_addr in addrset[addr]['lower']:
                        sub_stake_list.append(addrset[sub_addr]['sub_stake'])
                        addrset[addr]['sub_stake'] += addrset[sub_addr]['sub_stake']

                    if len(sub_stake_list) == 0:
                        continue

                    max_sub_stake = max(sub_stake_list)
                    sub_stake_list.remove(max_sub_stake)

                    addrset[addr]['power'] += round(max_sub_stake ** (1.0 / 3))
                    for sub_stake in sub_stake_list:
                        prev_token = 0
                        for times in mappromotiontokentimes:
                            if sub_stake <= times['token']:
                                addrset[addr]['power'] += (sub_stake -
                                                           prev_token) * times['times']
                                prev_token = times['token']
                                break
                            else:
                                addrset[addr]['power'] += (times['token'] -
                                                           prev_token) * times['times']
                                prev_token = times['token']

                        if sub_stake > prev_token:
                            addrset[addr]['power'] += sub_stake - prev_token

                    total_power += addrset[addr]['power']

        promotion_unit_reward = float(promotion_reward) / total_power
        for addr, info in addrset.items():
            result[addr] += int(info['power'] * promotion_unit_reward)
        
        promo_addrlist =  [
            {'addr': k, 'info': v} for k, v in addrset.items()]
        promo_addrlist.sort()
        for v in promo_addrlist:
            print ("promotion reward address:", v['addr'], 'reward:', int(v['info']['power'] * promotion_unit_reward))

        for addr, reward in result.items():
            addrset[addr]['stake'] += reward

        output.append({'height': height, 'reward': result})


if __name__ == "__main__":
    # json path
    if len(sys.argv) < 4:
        raise Exception(
            'Not enough param, should be "python defi_mock.py input.json output.json count"')

    input_path = os.path.join(os.getcwd(), sys.argv[1])
    output_path = os.path.join(os.getcwd(), sys.argv[2])
    count = int(sys.argv[3])

    input = {}
    output = []
    # load json
    with open(input_path, 'r') as r:
        content = json.loads(r.read())
        input = content["input"]

    # compute balance by stake and relation
    addrset = {}
    for addr, stake in input['stake'].items():
        addrset[addr] = {
            'stake': stake * COIN,
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

    # level
    total_level = 0
    root_addr_level = {}
    # calc root level of every tree
    for addr, info in addrset.items():
        if len(info['lower']) == 0:
            level = 0
            upper = addrset[addr]['upper']
            root_addr = addr
            while upper:
                level += 1
                root_addr = upper
                upper = addrset[upper]['upper']

            if not root_addr_level.has_key(root_addr):
                root_addr_level[root_addr] = level
            else:
                if level > root_addr_level[root_addr]:
                    root_addr_level[root_addr] = level

    # calc non-root level of every tree
    for root_addr, root_level in root_addr_level.items():
        MarkTreeLevel(root_addr, root_level, addrset)
        if root_level > total_level:
            total_level = root_level

    #print ("root level:", total_level)
    #print ("addrset:", addrset)

    # compute reward
    Compute(addrset, total_level, input, output, count)

    # output
    result = {
        'input': input,
        'output': output
    }

    pprint(result, indent=2)
    with open(output_path, 'w') as w:
        w.write(json.dumps(result))
