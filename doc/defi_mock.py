#!/usr/bin/env python

import time
import json
from collections import OrderedDict
import os
import sys
from functools import cmp_to_key

COIN = 1000000


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
    for i in mappromotiontokentimes:
        mappromotiontokentimes[i]['token'] *= COIN

    reward_count = supplycycle / rewardcycle
    supply = amount
    reward_percent = initcoinbasepercent
    total_reward = 0

    for i in range(0, count):
        height = mintheight + i * rewardcycle
        result = {}
        for addr in addrset:
            result[addr] = 0

        if (height - mintheight) % decaycycle == 0:
            reward_percent *= coinbasedecaypercent

        if (height - mintheight) % supplycycle == 0:
            total_reward = int(supply * reward_percent)
            supply += total_reward

        # compute stake reward
        stake_reward = int(total_reward / reward_count * stakerewardpercent)
        sorted_addrset = dict(
            sorted(addrset.items(), key=lambda item: item[1].stake))

        stake_addrset = {
            k: v for k, v in sorted_addrset.items() if v[1].stake >= stakemintoken}

        rank = 0
        prev = -1
        total = 0
        for _, info in stake_addrset.items():
            if info.stake > prev:
                prev = info.stake
                rank = rank + 1

            info['rank'] = rank
            total += rank

        stake_unit_reward = float(stake_reward) / total
        for addr, info in stake_addrset.items():
            result[addr] += int(info['rank'] * stake_unit_reward)
            print('stake reward, addr: ', addr, ', reward: ', result[addr])

        # compute promotion reward
        promotion_reward = int(
            total_reward / reward_count * promotionrewardpercent)

        total_power = 0
        for j in range(0, total_level + 1):
            for addr, info in addrset.items():
                if info['level'] == j:
                    info['power'] = 0
                    info['sub_stake'] = info['stake']
                    sub_stake_list = []
                    for sub_addr in info['lower']:
                        sub_stake_list.append(addrset[sub_addr]['sub_stake'])
                        info['sub_stake'] += addrset[sub_addr]['sub_stake']

                    if len(sub_stake_list) == 0:
                        continue

                    max_sub_stake = max(sub_stake_list)
                    sub_stake_list.remove(sub_stake_list.index(max_sub_stake))
                    info['power'] += round(max_sub_stake ** (1.0 / 3))
                    for sub_stake in sub_stake_list:
                        prev_token = 0
                        for times in mappromotiontokentimes:
                            if sub_stake <= times['token']:
                                info['power'] += (sub_stake -
                                                  prev_token) * times['times']
                                prev_token = times['token']
                                break
                            else:
                                info['power'] += (times['token'] -
                                                  prev_token) * times['times']
                                prev_token = times['token']

                        if sub_stake > prev_token:
                            info['power'] += sub_stake['token'] - prev_token

                        total_power += info['power']

        promotion_unit_reward = float(promotion_reward) / total_power
        for addr, info in addrset.items():
            result[addr] += int(info['power'] * promotion_unit_reward)
            print('promotion reward, addr: ', addr, ', reward: ', result[addr])

        output.append(result)


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
    for addr, info in addrset.items():
        if len(info['lower']) == 0:
            info['level'] = 0
            upper = info['upper']
            level = 0
            while upper:
                level += 1
                addrset[upper]['level'] = level
                upper = addrset[upper]['upper']

            if total_level < level:
                total_level = level

    # compute reward
    Compute(addrset, total_level, input, output, count)

    # output
    result = {
        'input': input,
        'output': output
    }

    with open(output_path, 'w') as w:
        json.dumps(result)
