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
// CDeFiRelationGraph

CDeFiRelationGraph::~CDeFiRelationGraph()
{
    for (auto it = mapDestNode.begin(); it != mapDestNode.end(); ++it)
    {
        if (it->second)
        {
            delete it->second;
            it->second = nullptr;
        }
    }
}

bool CDeFiRelationGraph::ConstructRelationGraph(const std::map<CDestination, CAddrInfo>& mapAddress)
{
    for (const auto& vd : mapAddress)
    {
        if (!UpdateAddress(vd.first, vd.second.destParent, vd.second.txid))
        {
            StdLog("CDeFiRelationGraph", "ConstructRelationGraph: UpdateAddress fail");
            return false;
        }
    }

    if (!UpdateParent())
    {
        StdLog("CDeFiRelationGraph", "ConstructRelationGraph: UpdateParent fail");
        return false;
    }

    return true;
}

bool CDeFiRelationGraph::UpdateAddress(const CDestination& dest, const CDestination& parent, const uint256& txid)
{
    if (dest.IsNull() || parent.IsNull() || txid == 0)
    {
        StdError("CDeFiRelationGraph", "UpdateAddress: param error");
        return false;
    }
    auto it = mapDestNode.find(dest);
    if (it == mapDestNode.end())
    {
        CDeFiRelationNode* pNewAddr = new CDeFiRelationNode(dest, parent, txid);
        if (pNewAddr == nullptr)
        {
            StdError("CDeFiRelationGraph", "UpdateAddress: new error, dest: %s", CAddress(dest).ToString().c_str());
            return false;
        }
        mapDestNode.insert(make_pair(dest, pNewAddr));
    }
    else
    {
        StdError("CDeFiRelationGraph", "UpdateAddress: duplicate address, dest: %s", CAddress(dest).ToString().c_str());
        return false;
    }
    return true;
}

bool CDeFiRelationGraph::UpdateParent()
{
    for (auto it = mapDestNode.begin(); it != mapDestNode.end(); ++it)
    {
        if (!it->second)
        {
            StdError("CDeFiRelationGraph", "UpdateParent: address is null, dest: %s", CAddress(it->first).ToString().c_str());
            return false;
        }
        if (it->second->parent.IsNull())
        {
            continue;
        }
        auto mt = mapDestNode.find(it->second->parent);
        if (mt != mapDestNode.end())
        {
            if (!mt->second)
            {
                StdError("CDeFiRelationGraph", "UpdateParent: parent address is null, dest: %s", CAddress(it->first).ToString().c_str());
                return false;
            }
        }
        else
        {
            CDeFiRelationNode* pNewAddr = new CDeFiRelationNode(it->second->parent, CDestination(), uint256());
            if (pNewAddr == nullptr)
            {
                StdError("CDeFiRelationGraph", "UpdateParent: new error, dest: %s", CAddress(it->second->parent).ToString().c_str());
                return false;
            }
            mt = mapDestNode.insert(make_pair(it->second->parent, pNewAddr)).first;
            setRoot.insert(it->second->parent);
        }
        it->second->pParent = mt->second;
        mt->second->setSubline.insert(it->second);
    }
    return true;
}

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
    forkReward.insert(std::make_pair(forkid, fr));
}

CProfile CDeFiForkReward::GetForkProfile(const uint256& forkid)
{
    auto it = forkReward.find(forkid);
    return (it == forkReward.end()) ? CProfile() : it->second.profile;
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
    double fReward = 0;
    CProfile profile = GetForkProfile(forkid);
    if (profile.IsNull())
    {
        return -1;
    }

    int32 nEndHeight = CBlock::GetBlockHeightByHash(hash) + 1;
    int32 nBeginHeight = PrevRewardHeight(forkid, CBlock::GetBlockHeightByHash(hash)) + 1;

    int32 nMintHeight = (profile.defi.nMintHeight < 0) ? (profile.nJointHeight + 2) : profile.defi.nMintHeight;
    if (nBeginHeight < nMintHeight)
    {
        nBeginHeight = nMintHeight;
    }

    double fCoinbase = 0;
    int32 nNextHeight = 0;
    while (nBeginHeight < nEndHeight)
    {
        if (profile.defi.nCoinbaseType == FIXED_DEFI_COINBASE_TYPE)
        {
            if (!GetFixedDecayCoinbase(profile, nBeginHeight, fCoinbase, nNextHeight))
            {
                StdError("CDeFiForkReward", "GetSectionReward GetFixedDecayCoinbase fail");
                return -1;
            }
        }
        else if (profile.defi.nCoinbaseType == SPECIFIC_DEFI_COINBASE_TYPE)
        {
            if (!GetSpecificDecayCoinbase(profile, nBeginHeight, fCoinbase, nNextHeight))
            {
                StdError("CDeFiForkReward", "GetSectionReward GetSpecificDecayCoinbase fail");
                return -1;
            }
        }

        if (nNextHeight > 0)
        {
            uint32 nHeight = min(nEndHeight, nNextHeight) - nBeginHeight;
            fReward += fCoinbase * nHeight;
            nBeginHeight += nHeight;
        }
        else
        {
            break;
        }
    }

    return (int64)fReward;
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

bool CDeFiForkReward::GetFixedDecayCoinbase(const CProfile& profile, const int32 nHeight, double& fCoinbase, int32& nNextHeight)
{
    int32 nMintHeight = (profile.defi.nMintHeight < 0) ? (profile.nJointHeight + 2) : profile.defi.nMintHeight;
    if (nHeight < nMintHeight)
    {
        return false;
    }

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
    int32 nDecayCount = (nDecayCycle <= 0) ? 0 : ((nHeight - nMintHeight) / nDecayCycle);
    int32 nDecayHeight = nDecayCount * nDecayCycle + nMintHeight;
    int32 nCurSupplyCount = (nHeight - nDecayHeight) / nSupplyCycle;

    // supply = init * (1 + nInitCoinbasePercent) ^ nSupplyCount * (1 + nInitCoinbasePercent * nCoinbaseDecayPercent) ^ nCurSupplyCount
    int64 nSupply = profile.nAmount;
    double fCoinbaseIncreasing = (double)nInitCoinbasePercent / 100;
    for (int i = 0; i <= nDecayCount; i++)
    {
        if (i < nDecayCount)
        {
            nSupply *= pow(1 + fCoinbaseIncreasing, nSupplyCount);
            fCoinbaseIncreasing = fCoinbaseIncreasing * nCoinbaseDecayPercent / 100;
        }
        else
        {
            nSupply *= pow(1 + fCoinbaseIncreasing, nCurSupplyCount);
        }
    }

    fCoinbase = nSupply * fCoinbaseIncreasing / nSupplyCycle;
    nNextHeight = (nCurSupplyCount + 1) * nSupplyCycle + nDecayHeight;
    return true;
}

bool CDeFiForkReward::GetSpecificDecayCoinbase(const CProfile& profile, const int32 nHeight, double& fCoinbase, int32& nNextHeight)
{
    int32 nMintHeight = (profile.defi.nMintHeight < 0) ? (profile.nJointHeight + 2) : profile.defi.nMintHeight;
    if (nHeight < nMintHeight)
    {
        return false;
    }

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
    int32 nRelativeHeight = (nHeight - nMintHeight + 1);
    // supply = init * (1 + nCoinbasePercent1) ^ nSupplyCount1 * (1 + nCoinbasePercent2) ^ nSupplyCount2 * ... * (1 + nCoinbasePercentN) ^ nCurSupplyCount
    int64 nSupply = profile.nAmount;
    uint32 nCurCoinbaseIncreasing = 0;
    int32 nCurSupplyCount = 0;
    int32 nLastDecayHeight = 0;
    for (auto it = mapCoinbasePercent.begin(); it != mapCoinbasePercent.end(); it++)
    {
        double fCoinbaseIncreasing = (double)it->second / 100;
        if (nRelativeHeight > it->first)
        {
            int32 nSupplyCount = (it->first - nLastDecayHeight) / nSupplyCycle;
            nSupply *= pow(1 + fCoinbaseIncreasing, nSupplyCount);
            nLastDecayHeight = it->first;
        }
        else
        {
            nCurSupplyCount = (nRelativeHeight - nLastDecayHeight) / nSupplyCycle;
            nSupply *= pow(1 + fCoinbaseIncreasing, nCurSupplyCount);
            nCurCoinbaseIncreasing = it->second;
            break;
        }
    }

    if (nCurCoinbaseIncreasing == 0)
    {
        fCoinbase = 0;
        nNextHeight = -1;
    }
    else
    {
        double fCoinbaseIncreasing = (double)nCurCoinbaseIncreasing / 100;
        fCoinbase = nSupply * fCoinbaseIncreasing / nSupplyCycle;
        nNextHeight = (nCurSupplyCount + 1) * nSupplyCycle + nLastDecayHeight + nMintHeight - 1;
    }
    return true;
}

map<CDestination, int64> CDeFiForkReward::ComputeStakeReward(const int64 nMin, const int64 nReward,
                                                             const std::map<CDestination, int64>& mapAddressAmount)
{
    map<CDestination, int64> reward;

    if (nReward == 0)
    {
        return reward;
    }

    // sort by token
    multimap<int64, pair<CDestination, uint32>> mapRank;
    for (auto& p : mapAddressAmount)
    {
        if (p.second >= nMin)
        {
            mapRank.insert(make_pair(p.second, make_pair(p.first, 0)));
        }
    }

    // tag rank
    uint32 nRank = 1;
    uint32 nPos = 0;
    uint32 nTotal = 0;
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
        reward.insert(make_pair(p.second.first, (int64)(fUnitReward * p.second.second)));
    }

    return reward;
}

map<CDestination, int64> CDeFiForkReward::ComputePromotionReward(const int64 nReward,
                                                                 const map<CDestination, int64>& mapAddressAmount,
                                                                 const std::map<int64, uint32>& mapPromotionTokenTimes,
                                                                 CDeFiRelationGraph& relation)
{
    map<CDestination, int64> reward;

    if (nReward == 0)
    {
        return reward;
    }

    // compute promotion power
    int64 nTotal = 0;
    relation.PostorderTraversal([&](CDeFiRelationNode* pNode) {
        // amount
        auto it = mapAddressAmount.find(pNode->dest);
        pNode->nAmount = (it == mapAddressAmount.end()) ? 0 : (it->second / COIN);

        // power
        pNode->nPower = 0;
        if (!pNode->setSubline.empty())
        {
            int64 nMax = -1;
            for (auto& p : pNode->setSubline)
            {
                pNode->nAmount += p->nAmount;
                int64 n = 0;
                if (p->nAmount <= nMax)
                {
                    n = p->nAmount;
                }
                else
                {
                    n = nMax;
                    nMax = p->nAmount;
                }

                if (n < 0)
                {
                    continue;
                }

                int64 nLastToken = 0;
                int64 nChildPower = 0;
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
                pNode->nPower += nChildPower;
            }
            pNode->nPower += llround(pow(nMax, 1.0 / 3));
        }

        if (pNode->nPower > 0)
        {
            nTotal += pNode->nPower;
            reward.insert(make_pair(pNode->dest, pNode->nPower));
        }

        return true;
    });

    // reward
    if (nTotal > 0)
    {
        double fUnitReward = (double)nReward / nTotal;
        for (auto& p : reward)
        {
            p.second *= fUnitReward;
        }
    }

    return reward;
}

} // namespace bigbang