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
TX_FEE = 10000


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
    delegate_addr = makeorigin['delegate_addr']
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
    mapcoinbasepercent = [{'height': v['height'], 'percent': v['percent']}
                          for v in defi['mapcoinbasepercent']]
    if coinbasetype == 1:
        mapcoinbasepercent = sorted(
            mapcoinbasepercent, key=lambda x: x['height'])
        for v in mapcoinbasepercent:
            v['percent'] = float(v['percent']) / 100
    stakerewardpercent = float(defi['stakerewardpercent']) / 100
    promotionrewardpercent = float(defi['promotionrewardpercent']) / 100
    stakemintoken = defi['stakemintoken'] * COIN
    mappromotiontokentimes = defi['mappromotiontokentimes']

    reward_count = supplycycle / rewardcycle
    supply = amount
    next_supply = amount
    reward_percent = initcoinbasepercent if coinbasetype == 0 else mapcoinbasepercent[
        0]['percent']
    next_reward_percent_height = mintheight + \
        decaycycle if coinbasetype == 0 else mintheight + \
        mapcoinbasepercent[0]['height']
    coinbase = 0

    for i in range(0, count):
        # to upper limit
        if supply >= maxsupply:
            break

        height = mintheight + (i + 1) * rewardcycle
        result = {}
        for addr in addrset:
            result[addr] = 0

        if height == next_reward_percent_height:
            if coinbasetype == 0:
                reward_percent *= coinbasedecaypercent
                next_reward_percent_height = next_reward_percent_height + decaycycle
            elif coinbasetype == 1:
                for j in range(0, len(mapcoinbasepercent)):
                    if next_reward_percent_height == mintheight + mapcoinbasepercent[j]['height']:
                        if j < len(mapcoinbasepercent) - 1:
                            next_reward_percent_height = mintheight + \
                                mapcoinbasepercent[j+1]['height']
                            reward_percent = mapcoinbasepercent[j+1]['percent']
                        else:
                            next_reward_percent_height = -1
                        break
                if next_reward_percent_height < 0:
                    break

        if (height - mintheight - rewardcycle) % supplycycle == 0:
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
        # print("height: %d, reward: %d" % (height, total_reward))

        addrset_addrlist = [
            {'addr': k, 'info': v} for k, v in addrset.items()]
        addrset_addrlist = sorted(addrset_addrlist, key=lambda x: x['addr'])
        # for v in addrset_addrlist:
        #     print("begin addr: %s, stake: %d" %
        #           (v['addr'], v['info']['stake']))

        # compute stake reward
        stake_reward = int(total_reward * stakerewardpercent)

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
        # print("stake reward: %d, size: %d" %
        #       (stake_reward, len(stake_addrset)))

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
            # print("addr:", addr, "rank:", rank, "stake:", info['stake'])
            total += rank

        stake_unit_reward = float(stake_reward) / total
        stake_addrset = sorted(stake_addrset, key=lambda x: x['addr'])
        for v in stake_addrset:
            addr = v['addr']
            info = v['info']
            result[addr] += int(info['rank'] * stake_unit_reward)
            # print('stake reward addr: %s, reward: %d' % (addr, result[addr]))

        # compute promotion reward
        promotion_reward = int(
            total_reward * promotionrewardpercent)

        total_power = 0

        for j in range(0, total_level + 1):
            for addr, info in addrset.items():
                if info['level'] == j:
                    addrset[addr]['power'] = 0
                    addrset[addr]['sub_stake'] = int(info['stake'] / COIN)
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
        promo_count = 0
        promo_addrlist = []
        for addr, info in addrset.items():
            result[addr] += int(info['power'] * promotion_unit_reward)
            if info['power'] > 0:
                promo_count += 1
                promo_addrlist.append({'addr': addr, 'info': int(
                    info['power'] * promotion_unit_reward)})

        # print("promotion reward: %d, size: %d" %
        #       (promotion_reward, promo_count))
        # promo_addrlist = sorted(promo_addrlist, key=lambda x: x['addr'])
        # for v in promo_addrlist:
        #     print('promotion reward addr: %s, reward: %d' %
        #           (v['addr'], v['info']))

        # result_addrlist = [
        #     {'addr': k, 'info': v} for k, v in result.items()]
        # result_addrlist = sorted(result_addrlist, key=lambda x: x['addr'])
        # for v in result_addrlist:
        #     print("addr: %s, reward: %d" % (v['addr'], v['info']))

        # delete the reward less than TX_FEE
        for addr in list(result.keys()):
            if result[addr] <= TX_FEE:
                del(result[addr])
        for addr, reward in result.items():
            addrset[addr]['stake'] += reward - TX_FEE

        # dpos mint
        addrset[delegate_addr]['stake'] += (TX_FEE * len(result))

        output.append({'height': height, 'reward': result})

        print("computed count: %d, now: %d, height: %d" % (count, i, height))

    addrlist = [
        {'addr': k, 'info': v['stake']} for k, v in addrset.items()]
    addrlist = sorted(addrlist, key=lambda x: x['addr'])
    for v in addrlist:
        print("addr: %s, reward: %d" % (v['addr'], v['info']))


if __name__ == "__main__":
    # json path
    if len(sys.argv) < 3:
        raise Exception(
            'Not enough param, should be "python defi_mock.py file.json count"')

    path = os.path.join(os.getcwd(), sys.argv[1])
    count = int(sys.argv[2])

    input = {}
    output = []
    # load json
    with open(path, 'r') as r:
        content = json.loads(r.read())
        input = content["input"]

    # compute balance by stake and relation
    addrset = {}
    for addr, stake in input['stake'].items():
        addrset[addr] = {
            'stake': stake,
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

            if root_addr not in root_addr_level:
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

    # pprint(result, indent=2)
    with open(path, 'w') as w:
        json.dump(result, w, indent=4, sort_keys=True)
