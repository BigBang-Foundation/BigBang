// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "defi.h"

#include "param.h"

using namespace std;
using namespace xengine;
using namespace bigbang::storage;

namespace bigbang
{

//////////////////////////////
// CDeFiForkReward
CDeFiRewardSet CDeFiForkReward::null;

bool CDeFiForkReward::ExistFork(const uint256& forkid) const
{
    return forkReward.count(forkid);
}

void CDeFiForkReward::AddFork(const uint256& forkid, const CProfile& profile)
{
    CForkReward fr;
    fr.profile = profile;
    fr.nMaxRewardHeight = GetMaxRewardHeight(profile);
    forkReward.insert(std::make_pair(forkid, fr));
}

CProfile CDeFiForkReward::GetForkProfile(const uint256& forkid)
{
    auto it = forkReward.find(forkid);
    return (it == forkReward.end()) ? CProfile() : it->second.profile;
}

int32 CDeFiForkReward::GetForkMaxRewardHeight(const uint256& forkid)
{
    auto it = forkReward.find(forkid);
    return (it == forkReward.end()) ? -1 : it->second.nMaxRewardHeight;
}

int32 CDeFiForkReward::PrevRewardHeight(const uint256& forkid, const int32 nHeight)
{
    auto it = forkReward.find(forkid);
    if (it != forkReward.end())
    {
        CProfile& profile = it->second.profile;
        if (!profile.defi.IsNull())
        {
            int32 nMintHeight = (profile.defi.nMintHeight < 0) ? (profile.nJointHeight + 2) : profile.defi.nMintHeight;
            int32 nRewardCycle = profile.defi.nRewardCycle;
            if (nHeight >= nMintHeight && nRewardCycle > 0)
            {
                return ((nHeight - nMintHeight) / nRewardCycle) * nRewardCycle + nMintHeight - 1;
            }
        }
    }
    return -1;
}

int64 CDeFiForkReward::GetSectionReward(const uint256& forkid, const uint256& hash)
{
    CProfile profile = GetForkProfile(forkid);
    if (profile.IsNull())
    {
        return -1;
    }

    int32 nMaxRewardHeight = GetForkMaxRewardHeight(forkid);
    if (nMaxRewardHeight < 0)
    {
        return -1;
    }

    int32 nMintHeight = (profile.defi.nMintHeight < 0) ? (profile.nJointHeight + 2) : profile.defi.nMintHeight;

    // begin height
    int32 nBeginHeight = PrevRewardHeight(forkid, CBlock::GetBlockHeightByHash(hash)) + 1;
    if (nBeginHeight < nMintHeight)
    {
        nBeginHeight = nMintHeight;
    }
    // to the max reward height
    if (nBeginHeight > nMaxRewardHeight)
    {
        return 0;
    }

    // end height
    int32 nEndHeight = CBlock::GetBlockHeightByHash(hash) + 1;
    // to the max reward height
    if (nEndHeight > nMaxRewardHeight + 1)
    {
        nEndHeight = nMaxRewardHeight + 1;
    }

    if (profile.defi.nCoinbaseType == FIXED_DEFI_COINBASE_TYPE)
    {
        return GetFixedDecayReward(profile, nBeginHeight, nEndHeight);
    }
    else if (profile.defi.nCoinbaseType == SPECIFIC_DEFI_COINBASE_TYPE)
    {
        return GetSpecificDecayReward(profile, nBeginHeight, nEndHeight);
    }
    else
    {
        return 0;
    }
}

bool CDeFiForkReward::ExistForkSection(const uint256& forkid, const uint256& section)
{
    auto it = forkReward.find(forkid);
    if (it != forkReward.end())
    {
        return it->second.reward.count(section);
    }
    return false;
}

const CDeFiRewardSet& CDeFiForkReward::GetForkSection(const uint256& forkid, const uint256& section)
{
    auto it = forkReward.find(forkid);
    if (it != forkReward.end())
    {
        auto im = it->second.reward.find(section);
        if (im != it->second.reward.end())
        {
            return im->second;
        }
    }
    return null;
}

void CDeFiForkReward::AddForkSection(const uint256& forkid, const uint256& hash, CDeFiRewardSet&& reward)
{
    auto it = forkReward.find(forkid);
    if (it != forkReward.end())
    {
        it->second.reward[hash] = std::move(reward);
    }
    while (forkReward.size() > MAX_REWARD_CACHE)
    {
        if (forkReward.begin()->first != hash)
        {
            forkReward.erase(forkReward.begin());
        }
        else
        {
            break;
        }
    }
}

CDeFiRewardSet CDeFiForkReward::ComputeStakeReward(const int64 nMin, const int64 nReward,
                                                   const std::map<CDestination, int64>& mapAddressAmount)
{
    CDeFiRewardSet rewardSet;

    if (nReward == 0)
    {
        return rewardSet;
    }

    // sort by token
    multimap<int64, pair<CDestination, uint64>> mapRank;
    for (auto& p : mapAddressAmount)
    {
        if (p.second >= nMin)
        {
            mapRank.insert(make_pair(p.second, make_pair(p.first, 0)));
        }
    }

    // tag rank
    uint64 nRank = 1;
    uint64 nPos = 0;
    uint64 nTotal = 0;
    int64 nToken = -1;
    for (auto& p : mapRank)
    {
        ++nPos;
        if (p.first != nToken)
        {
            p.second.second = nPos;
            nRank = nPos;
            nToken = p.first;
        }
        else
        {
            p.second.second = nRank;
        }

        nTotal += p.second.second;
    }

    // reward
    double fUnitReward = (double)nReward / nTotal;
    for (auto& p : mapRank)
    {
        CDeFiReward reward;
        reward.dest = p.second.first;
        reward.nAmount = p.first;
        reward.nRank = p.second.second;
        reward.nStakeReward = fUnitReward * p.second.second;
        reward.nReward = reward.nStakeReward;
        rewardSet.insert(std::move(reward));
    }

    return rewardSet;
}

CDeFiRewardSet CDeFiForkReward::ComputePromotionReward(const int64 nReward,
                                                       const map<CDestination, int64>& mapAddressAmount,
                                                       const std::map<int64, uint32>& mapPromotionTokenTimes,
                                                       CForest<CDestination, CDeFiRelationRewardNode>& relation)
{
    typedef typename CForest<CDestination, CDeFiRelationRewardNode>::NodePtr NodePtr;

    CDeFiRewardSet rewardSet;

    if (nReward == 0)
    {
        return rewardSet;
    }

    // compute promotion power
    multimap<uint64, pair<CDestination, int64>> mapPower;
    uint64 nTotal = 0;
    relation.PostorderTraversal([&](NodePtr pNode) {
        // amount
        auto it = mapAddressAmount.find(pNode->key);
        int64 nAmount = (it == mapAddressAmount.end()) ? 0 : (it->second / COIN);

        // power
        pNode->data.nPower = 0;
        pNode->data.nAmount = nAmount;
        if (!pNode->setChildren.empty())
        {
            int64 nMax = -1;
            for (auto& p : pNode->setChildren)
            {
                pNode->data.nAmount += p->data.nAmount;
                int64 n = 0;
                if (p->data.nAmount <= nMax)
                {
                    n = p->data.nAmount;
                }
                else
                {
                    n = nMax;
                    nMax = p->data.nAmount;
                }

                if (n < 0)
                {
                    continue;
                }

                uint64 nLastToken = 0;
                uint64 nChildPower = 0;
                for (auto& tokenTimes : mapPromotionTokenTimes)
                {
                    if (n > tokenTimes.first)
                    {
                        nChildPower += (tokenTimes.first - nLastToken) * tokenTimes.second;
                        nLastToken = tokenTimes.first;
                    }
                    else
                    {
                        nChildPower += (n - nLastToken) * tokenTimes.second;
                        nLastToken = n;
                        break;
                    }
                }
                nChildPower += (n - nLastToken);
                pNode->data.nPower += nChildPower;
            }
            pNode->data.nPower += llround(pow(nMax, 1.0 / 3));
        }

        if (pNode->data.nPower > 0)
        {
            nTotal += pNode->data.nPower;
            mapPower.insert(make_pair(pNode->data.nPower, make_pair(pNode->key, nAmount)));
        }

        return true;
    });

    // reward
    if (nTotal > 0)
    {
        double fUnitReward = (double)nReward / nTotal;
        for (auto& p : mapPower)
        {
            CDeFiReward reward;
            reward.dest = p.second.first;
            reward.nAmount = p.second.second;
            reward.nPower = p.first;
            reward.nPromotionReward = fUnitReward * p.first;
            reward.nReward = reward.nPromotionReward;
            rewardSet.insert(std::move(reward));
        }
    }

    return rewardSet;
}

int64 CDeFiForkReward::GetFixedDecayReward(const CProfile& profile, const int32 nBeginHeight, const int32 nEndHeight)
{
    int32 nMintHeight = (profile.defi.nMintHeight < 0) ? (profile.nJointHeight + 2) : profile.defi.nMintHeight;
    if (nBeginHeight < nMintHeight)
    {
        return -1;
    }

    int64 nMaxSupply = (profile.defi.nMaxSupply < 0) ? MAX_MONEY : profile.defi.nMaxSupply;
    int32 nDecayCycle = profile.defi.nDecayCycle;
    int32 nSupplyCycle = profile.defi.nSupplyCycle;
    uint8 nCoinbaseDecayPercent = profile.defi.nCoinbaseDecayPercent;
    uint32 nInitCoinbasePercent = profile.defi.nInitCoinbasePercent;
    int32 nSupplyCount = (nDecayCycle <= 0) ? 0 : (nDecayCycle / nSupplyCycle);

    // for example:
    // [2] nJoint height
    // [3] origin height
    // [4, 5, 6] the first supply cycle of the first decay cycle
    // [7, 8, 9] the second sypply cycle of the first decay cycle
    // [10, 11, 12] the first supply cycle of the second decay cycle
    // [13, 14, 15] the second supply cycle of the second decay cycle
    int32 nDecayCount = (nDecayCycle <= 0) ? 0 : ((nBeginHeight - nMintHeight) / nDecayCycle);
    int32 nDecayHeight = nDecayCount * nDecayCycle + nMintHeight;
    int32 nCurSupplyCount = (nBeginHeight - nDecayHeight) / nSupplyCycle;
    int64 nSupply = profile.nAmount;
    double fCoinbaseIncreasing = (double)nInitCoinbasePercent / 100;
    for (int i = 0; i <= nDecayCount; i++)
    {
        if (i < nDecayCount)
        {
            for (int j = 0; j < nSupplyCount; j++)
            {
                nSupply *= 1 + fCoinbaseIncreasing;
            }
            fCoinbaseIncreasing = fCoinbaseIncreasing * nCoinbaseDecayPercent / 100;
        }
        else
        {
            for (int i = 0; i < nCurSupplyCount; i++)
            {
                nSupply *= 1 + fCoinbaseIncreasing;
            }
        }
    }

    int64 nReward = 0;
    int32 nHeight = nBeginHeight;
    // loop per supply cycle
    while (nHeight < nEndHeight)
    {
        if (nSupply >= nMaxSupply)
        {
            return nReward;
        }

        int64 nNextSupply = nSupply * (1 + fCoinbaseIncreasing);
        if (nNextSupply < nSupply + COIN)
        {
            return nReward;
        }

        double fCoinbase = (double)(nNextSupply - nSupply) / nSupplyCycle;
        int32 nNextSupplyHeight = nDecayHeight + (nCurSupplyCount + 1) * nSupplyCycle;
        int32 nNextHeight = min(nEndHeight, nNextSupplyHeight);

        int64 nNextReward = (int64)llround(fCoinbase * (nNextHeight - nHeight));
        if (nMaxSupply >= nNextSupply)
        {
            nReward += nNextReward;
        }
        else
        {
            int64 nLastReward = (int64)llround(fCoinbase * (nHeight - (nNextSupplyHeight - nSupplyCycle)));
            int64 nMaxReward = max((int64)0, nMaxSupply - nSupply - nLastReward);
            nReward += min(nMaxReward, nNextReward);
        }

        nHeight = nNextHeight;
        nSupply = nNextSupply;
        ++nCurSupplyCount;
        if ((nSupplyCount > 0) && (nCurSupplyCount % nSupplyCount == 0))
        {
            nDecayHeight = nNextHeight;
            nCurSupplyCount = 0;
            fCoinbaseIncreasing = fCoinbaseIncreasing * nCoinbaseDecayPercent / 100;
        }
    }

    return nReward;
}

int64 CDeFiForkReward::GetSpecificDecayReward(const CProfile& profile, const int32 nBeginHeight, const int32 nEndHeight)
{
    int32 nMintHeight = (profile.defi.nMintHeight < 0) ? (profile.nJointHeight + 2) : profile.defi.nMintHeight;
    if (nBeginHeight < nMintHeight)
    {
        return -1;
    }

    int64 nMaxSupply = (profile.defi.nMaxSupply < 0) ? MAX_MONEY : profile.defi.nMaxSupply;
    int32 nSupplyCycle = profile.defi.nSupplyCycle;
    const map<int32, uint32>& mapCoinbasePercent = profile.defi.mapCoinbasePercent;

    // for example:
    // [2] nJoint height
    // [3] origin height
    // [4, 5] the first supply cycle of the first decay cycle
    // [6, 7] the second sypply cycle of the first decay cycle
    // [8, 9] the third sypply cycle of the first decay cycle
    // [10, 11] the first supply cycle of the second decay cycle
    // [12, 13] the second supply cycle of the second decay cycle
    // [14, 15] the first supply cycle of the third decay cycle
    int32 nHeight = nBeginHeight;
    int64 nSupply = profile.nAmount;
    int32 nLastDecayHeight = 0;
    int64 nReward = 0;
    for (auto it = mapCoinbasePercent.begin(); it != mapCoinbasePercent.end(); it++)
    {
        if (nHeight >= nEndHeight)
        {
            break;
        }

        double fCoinbaseIncreasing = (double)it->second / 100;
        if (nHeight - nMintHeight + 1 > it->first)
        {
            int32 nSupplyCount = (it->first - nLastDecayHeight) / nSupplyCycle;
            for (int j = 0; j < nSupplyCount; j++)
            {
                nSupply *= 1 + fCoinbaseIncreasing;
            }
        }
        else
        {
            int32 nCurSupplyCount = (nHeight - nLastDecayHeight - 1) / nSupplyCycle;
            for (int j = 0; j < nCurSupplyCount; j++)
            {
                nSupply *= 1 + fCoinbaseIncreasing;
            }

            int32 nSupplyCount = (it->first - nLastDecayHeight) / nSupplyCycle;
            // loop per supply cycle
            while (nHeight < nEndHeight && nCurSupplyCount < nSupplyCount)
            {
                if (nSupply >= nMaxSupply)
                {
                    return nReward;
                }

                int64 nNextSupply = nSupply * (1 + fCoinbaseIncreasing);
                if (nNextSupply < nSupply + COIN)
                {
                    return nReward;
                }

                double fCoinbase = (double)(nNextSupply - nSupply) / nSupplyCycle;
                int32 nNextSupplyHeight = nMintHeight + nLastDecayHeight + (nCurSupplyCount + 1) * nSupplyCycle;
                int32 nNextHeight = min(nEndHeight, nNextSupplyHeight);

                int64 nNextReward = (int64)llround(fCoinbase * (nNextHeight - nHeight));
                if (nMaxSupply >= nNextSupply)
                {
                    nReward += nNextReward;
                }
                else
                {
                    int64 nLastReward = (int64)llround(fCoinbase * (nHeight - (nNextSupplyHeight - nSupplyCycle)));
                    int64 nMaxReward = max((int64)0, nMaxSupply - nSupply - nLastReward);
                    nReward += min(nMaxReward, nNextReward);
                }

                nHeight = nNextHeight;
                nSupply = nNextSupply;
                ++nCurSupplyCount;
            }
        }

        nLastDecayHeight = it->first;
    }

    return nReward;
}

int32 CDeFiForkReward::GetMaxRewardHeight(const CProfile& profile)
{
    int64 nMaxSupply = (profile.defi.nMaxSupply < 0) ? MAX_MONEY : profile.defi.nMaxSupply;
    int32 nMintHeight = (profile.defi.nMintHeight < 0) ? (profile.nJointHeight + 2) : profile.defi.nMintHeight;
    int32 nSupplyCycle = profile.defi.nSupplyCycle;
    if (profile.defi.nCoinbaseType == FIXED_DEFI_COINBASE_TYPE)
    {
        int32 nDecayCycle = profile.defi.nDecayCycle;
        uint8 nCoinbaseDecayPercent = profile.defi.nCoinbaseDecayPercent;
        uint32 nInitCoinbasePercent = profile.defi.nInitCoinbasePercent;
        int32 nSupplyCount = (nDecayCycle <= 0) ? 0 : (nDecayCycle / nSupplyCycle);

        int64 nSupply = profile.nAmount;
        int64 nNextSupply = 0;
        double fCoinbaseIncreasing = (double)nInitCoinbasePercent / 100;
        int32 count = 0;
        while (true)
        {
            nNextSupply = nSupply * (1 + fCoinbaseIncreasing);
            if (nNextSupply < nSupply + COIN)
            {
                printf("nNextSupply < nSupply + COIN, count: %d, next: %ld, supply: %ld\n", count, nNextSupply, nSupply);
                return nMintHeight + count * nSupplyCycle - 1;
            }
            if (nNextSupply >= nMaxSupply)
            {
                double fCoinbase = nSupply * fCoinbaseIncreasing / nSupplyCycle;
                printf("nNextSupply >= nMaxSupply, count: %d, next: %ld, supply: %ld\n", count, nNextSupply, nSupply);
                return nMintHeight + count * nSupplyCycle + ceil((nMaxSupply - nSupply) / fCoinbase) - 1;
            }

            nSupply = nNextSupply;
            ++count;
            if (nSupplyCount > 0 && (count % nSupplyCount == 0))
            {
                fCoinbaseIncreasing = fCoinbaseIncreasing * nCoinbaseDecayPercent / 100;
            }
        }

        return count * nSupplyCycle + nMintHeight - 1;
    }
    else if (profile.defi.nCoinbaseType == SPECIFIC_DEFI_COINBASE_TYPE)
    {
        int32 nSupplyCycle = profile.defi.nSupplyCycle;
        const map<int32, uint32>& mapCoinbasePercent = profile.defi.mapCoinbasePercent;

        int64 nSupply = profile.nAmount;
        int64 nNextSupply = 0;
        double fCoinbaseIncreasing = 0;
        int32 nLastDecayHeight = 0;
        int32 count = 0;
        for (auto it = mapCoinbasePercent.begin(); it != mapCoinbasePercent.end(); it++)
        {
            fCoinbaseIncreasing = (double)it->second / 100;
            int32 nSupplyCount = (it->first - nLastDecayHeight) / nSupplyCycle;
            while (nSupplyCount > 0)
            {
                nNextSupply = nSupply * (1 + fCoinbaseIncreasing);
                if (nNextSupply < nSupply + COIN)
                {
                    return nMintHeight + count * nSupplyCycle - 1;
                }
                if (nNextSupply >= nMaxSupply)
                {
                    double fCoinbase = nSupply * fCoinbaseIncreasing / nSupplyCycle;
                    return nMintHeight + count * nSupplyCycle + ceil((nMaxSupply - nSupply) / fCoinbase) - 1;
                }

                nSupply = nNextSupply;
                ++count;
                --nSupplyCount;
            }
            nLastDecayHeight = it->first;
        }
        return nMintHeight + count * nSupplyCycle - 1;
    }
    else
    {
        return INT32_MAX;
    }
}

} // namespace bigbang