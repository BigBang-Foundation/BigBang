// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BIGBANG_DEFI_H
#define BIGBANG_DEFI_H

#include <map>
#include <set>
#include <stack>
#include <type_traits>

#include "address.h"
#include "addressdb.h"
#include "profile.h"
#include "struct.h"
#include "xengine.h"

namespace bigbang
{

class CDeFiRelationRewardNode
{
public:
    CDeFiRelationRewardNode()
      : nPower(0), nAmount(0) {}
    CDeFiRelationRewardNode(const CDestination& parentIn)
      : parent(parentIn), nPower(0), nAmount(0) {}

public:
    CDestination parent;
    uint64 nPower;
    int64 nAmount;
};

typedef xengine::CForest<CDestination, CDeFiRelationRewardNode> CDeFiRelationGraph;

class CDeFiForkReward
{
public:
    enum
    {
        MAX_REWARD_CACHE = 20
    };

    typedef std::map<uint256, CDeFiRewardSet> MapSectionReward;
    struct CForkReward
    {
        MapSectionReward reward;
        CProfile profile;
        int32 nMaxRewardHeight;
    };
    typedef std::map<uint256, CForkReward> MapForkReward;

    // return exist fork or not
    bool ExistFork(const uint256& forkid) const;
    // add a fork and its profile
    void AddFork(const uint256& forkid, const CProfile& profile);
    // get a fork profile
    CProfile GetForkProfile(const uint256& forkid);
    // get the max reward height of fork
    int32 GetForkMaxRewardHeight(const uint256& forkid);
    // return the last height of previous reward cycle of nHeight
    int32 PrevRewardHeight(const uint256& forkid, const int32 nHeight);
    // return the total reward from the beginning of section to the height of hash
    int64 GetSectionReward(const uint256& forkid, const uint256& hash);
    // return exist section cache of fork or not
    bool ExistForkSection(const uint256& forkid, const uint256& section);
    // return the section reward set. Should use ExistForkSection to determine if it exists first.
    const CDeFiRewardSet& GetForkSection(const uint256& forkid, const uint256& section);
    // Add a section reward set of fork
    void AddForkSection(const uint256& forkid, const uint256& hash, CDeFiRewardSet&& reward);

    // compute stake reward
    CDeFiRewardSet ComputeStakeReward(const int64 nMin, const int64 nReward,
                                      const std::map<CDestination, int64>& mapAddressAmount);
    // compute promotion reward
    CDeFiRewardSet ComputePromotionReward(const int64 nReward,
                                          const std::map<CDestination, int64>& mapAddressAmount,
                                          const std::map<int64, uint32>& mapPromotionTokenTimes,
                                          CDeFiRelationGraph& relation);

protected:
    // for fixed decay coinbase, return the reward of between [nBeginHeight, nEndHeight)
    int64 GetFixedDecayReward(const CProfile& profile, const int32 nBeginHeight, const int32 nEndHeight);
    // for specific decay coinbase, return the reward of between [nBeginHeight, nEndHeight)
    int64 GetSpecificDecayReward(const CProfile& profile, const int32 nBeginHeight, const int32 nEndHeight);
    // return the max reward height with profile
    int32 GetMaxRewardHeight(const CProfile& profile);

protected:
    MapForkReward forkReward;
    static CDeFiRewardSet null;
};

} // namespace bigbang

#endif // BIGBANG_DEFI_H