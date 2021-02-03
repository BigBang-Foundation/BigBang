// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COMMON_PROFILE_H
#define COMMON_PROFILE_H

#include <stream/stream.h>
#include <string>
#include <vector>

#include "destination.h"

enum
{
    PROFILE_VERSION = 0,
    PROFILE_NAME = 1,
    PROFILE_SYMBOL = 2,
    PROFILE_FLAG = 3,
    PROFILE_AMOUNT = 4,
    PROFILE_MINTREWARD = 5,
    PROFILE_MINTXFEE = 6,
    PROFILE_HALVECYCLE = 7,
    PROFILE_OWNER = 8,
    PROFILE_PARENT = 9,
    PROFILE_JOINTHEIGHT = 10,
    PROFILE_FORKTYPE = 11,
    PROFILE_DEFI = 12,
    PROFILE_UEE = 13,
    PROFILE_MAX,
};

enum
{
    FORK_TYPE_COMMON = 0,
    FORK_TYPE_DEFI = 1,
    FORK_TYPE_UEE = 2,
};

enum
{
    FIXED_DEFI_COINBASE_TYPE = 0,
    SPECIFIC_DEFI_COINBASE_TYPE = 1,
    DEFI_COINBASE_TYPE_MAX
};

class CDeFiProfile
{
public:
    int32 nMintHeight;                              // beginning mint height of DeFi, -1 means the first block after origin
    int64 nMaxSupply;                               // the max DeFi supply in this fork, -1 means no upper limit
    uint8 nCoinbaseType;                            // coinbase type. 0 - fixed decay(related to 'nInitCoinbasePercent', 'nCoinbaseDecayPercent', 'nDecayCycle'). 1 - specific decay(related to 'mapCoinbasePercent')
    uint32 nInitCoinbasePercent;                    // coinbase increasing ratio(%) per supply cycle in initialization. range [1 - 10000] means inital increasing [1% - 10000%]
    uint8 nCoinbaseDecayPercent;                    // compared with previous decay cycle, coinbase increasing ratio(%), range [0 - 100] means decay to [0% - 100%]
    int32 nDecayCycle;                              // coinbase decay cycle in height, if 0 means no decay
    std::map<int32, uint32> mapCoinbasePercent;     // pairs of height - coinbase percent
    int32 nRewardCycle;                             // generate reward cycle in height, range [1, 189,216,000]
    int32 nSupplyCycle;                             // supplyment changing cycle in height, range [1, 189,216,000] && nDecayCycle is divisible by nSupplyCycle.
    uint8 nStakeRewardPercent;                      // stake reward ratio(%), range [0 - 100] means [0% - 100%]
    uint8 nPromotionRewardPercent;                  // promotion reward ratio(%), range [0 - 100] means [0% - 100%]
    uint64 nStakeMinToken;                          // the minimum token on address can participate stake reward, range [0, MAX_TOKEN]
    std::map<int64, uint32> mapPromotionTokenTimes; // In promotion computation, less than or equal to [key] amount should multiply [value].

    CDeFiProfile()
    {
        SetNull();
    }
    virtual void SetNull()
    {
        nMintHeight = 0;
        nMaxSupply = 0;
        nCoinbaseType = 0;
        nInitCoinbasePercent = 0;
        nCoinbaseDecayPercent = 0;
        nDecayCycle = 0;
        mapCoinbasePercent.clear();
        nRewardCycle = 0;
        nSupplyCycle = 0;
        nStakeRewardPercent = 0;
        nPromotionRewardPercent = 0;
        nStakeMinToken = 0;
        mapPromotionTokenTimes.clear();
    }
    bool IsNull() const
    {
        return nRewardCycle == 0;
    }

    void Save(std::vector<unsigned char>& vchProfile) const;
    void Load(const std::vector<unsigned char>& vchProfile);
};

class CUEERule
{
    friend class xengine::CStream;

public:
    int nFormula;             // Calculation formula, 1: formula1, 2: formula2
    uint64 nCoefficient;      // Initial coefficient
    int nDecayPeriodType;     // Decay period type, 0: no attenuation, 1: high attenuation, 2: circulation attenuation
    uint64 nDecayPeriodValue; // Decay period value, decay period type is 2, unit of value is token
    int nDecayAmplitudeValue; // Decay amplitude value, range: 0-100

    enum
    {
        UEER_FORMULA_1 = 1,
        UEER_FORMULA_2 = 2
    };
    enum
    {
        UEER_DPT_NO_ATTENUATION = 0,
        UEER_DPT_HIGH_ATTENUATION = 1,
        UEER_DPT_CIRULATION_ATTENUATION = 2
    };

    CUEERule()
    {
        SetNull();
    }
    CUEERule(const int nFormulaIn, const uint64 nCoefficientIn, const int nDecayPeriodTypeIn, const uint64 nDecayPeriodValueIn, const int nDecayAmplitudeValueIn)
      : nFormula(nFormulaIn), nCoefficient(nCoefficientIn), nDecayPeriodType(nDecayPeriodTypeIn), nDecayPeriodValue(nDecayPeriodValueIn), nDecayAmplitudeValue(nDecayAmplitudeValueIn)
    {
    }
    virtual ~CUEERule() = default;

    virtual void SetNull()
    {
        nFormula = 0;
        nCoefficient = 0;
        nDecayPeriodType = 0;
        nDecayPeriodValue = 0;
        nDecayAmplitudeValue = 0;
    }
    bool IsNull() const
    {
        return nFormula == 0;
    }

protected:
    template <typename O>
    void Serialize(xengine::CStream& s, O& opt)
    {
        s.Serialize(nFormula, opt);
        s.Serialize(nCoefficient, opt);
        s.Serialize(nDecayPeriodType, opt);
        s.Serialize(nDecayPeriodValue, opt);
        s.Serialize(nDecayAmplitudeValue, opt);
    }
};

class CUEEProfile
{
public:
    int64 nMaxSupply;                        // The max U element energy supply in this fork, -1 means no upper limit, unit is token
    std::map<std::string, CUEERule> mapRule; // Table of mining rules

    CUEEProfile()
    {
        SetNull();
    }
    virtual void SetNull()
    {
        nMaxSupply = 0;
        mapRule.clear();
    }
    bool IsNull() const
    {
        return (nMaxSupply == 0 || mapRule.empty());
    }

    void Save(std::vector<unsigned char>& vchProfile) const;
    void Load(const std::vector<unsigned char>& vchProfile);
};

class CProfile
{
public:
    int nVersion;
    std::string strName;
    std::string strSymbol;
    uint8 nFlag;
    int64 nAmount;
    int64 nMintReward;
    int64 nMinTxFee;
    uint32 nHalveCycle;
    CDestination destOwner;
    uint256 hashParent;
    int nJointHeight;
    int nForkType;
    CDeFiProfile defi;
    CUEEProfile uee;

public:
    enum
    {
        PROFILE_FLAG_ISOLATED = 1,
        PROFILE_FLAG_PRIVATE = 2,
        PROFILE_FLAG_ENCLOSED = 4
    };
    CProfile()
    {
        SetNull();
    }
    virtual void SetNull()
    {
        nVersion = 1;
        nFlag = 0;
        nAmount = 0;
        nMintReward = 0;
        nMinTxFee = 0;
        nHalveCycle = 0;
        hashParent = 0;
        nJointHeight = -1;
        destOwner.SetNull();
        strName.clear();
        strSymbol.clear();
        nForkType = FORK_TYPE_COMMON;
        defi.SetNull();
        uee.SetNull();
    }
    bool IsNull() const
    {
        return strName.empty();
    }
    bool IsIsolated() const
    {
        return (nFlag & PROFILE_FLAG_ISOLATED);
    }
    bool IsPrivate() const
    {
        return (nFlag & PROFILE_FLAG_PRIVATE);
    }
    bool IsEnclosed() const
    {
        return (nFlag & PROFILE_FLAG_ENCLOSED);
    }
    void SetFlag(bool fIsolated, bool fPrivate, bool fEnclosed)
    {
        nFlag = 0;
        nFlag |= (fIsolated ? PROFILE_FLAG_ISOLATED : 0);
        nFlag |= (fPrivate ? PROFILE_FLAG_PRIVATE : 0);
        nFlag |= (fEnclosed ? PROFILE_FLAG_ENCLOSED : 0);
    }
    bool Save(std::vector<unsigned char>& vchProfile);
    bool Load(const std::vector<unsigned char>& vchProfile);
};

#endif //COMMON_PROFILE_H
