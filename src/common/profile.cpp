// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "profile.h"

#include <compacttv.h>
#include <stream/datastream.h>
#include <util.h>

using namespace std;
using namespace xengine;

//////////////////////////////
// CDeFiProfile

void CDeFiProfile::Save(std::vector<unsigned char>& vchProfile) const
{
    CODataStream os(vchProfile);
    os << nMintHeight << nMaxSupply << nCoinbaseType << nInitCoinbasePercent << nCoinbaseDecayPercent << nDecayCycle << mapCoinbasePercent
       << nRewardCycle << nSupplyCycle << nStakeRewardPercent << nPromotionRewardPercent << nStakeMinToken << mapPromotionTokenTimes;
}

void CDeFiProfile::Load(const std::vector<unsigned char>& vchProfile)
{
    CIDataStream is(vchProfile);
    is >> nMintHeight >> nMaxSupply >> nCoinbaseType >> nInitCoinbasePercent >> nCoinbaseDecayPercent >> nDecayCycle >> mapCoinbasePercent
        >> nRewardCycle >> nSupplyCycle >> nStakeRewardPercent >> nPromotionRewardPercent >> nStakeMinToken >> mapPromotionTokenTimes;
}

//////////////////////////////
// CUEEProfile

void CUEEProfile::Save(vector<unsigned char>& vchProfile) const
{
    uint32 nRuleCount = mapRule.size();
    xengine::CBufStream ss;
    ss << nMaxSupply << nRuleCount;
    for (const auto& vd : mapRule)
    {
        ss << vd.first << vd.second;
    }
    vchProfile.assign(ss.GetData(), ss.GetData() + ss.GetSize());
}

void CUEEProfile::Load(const vector<unsigned char>& vchProfile)
{
    if (vchProfile.empty())
    {
        throw std::runtime_error(std::string("uee profile vchProfile is empty"));
    }
    xengine::CBufStream ss;
    try
    {
        ss.Write((char*)&(vchProfile[0]), vchProfile.size());
        uint32 nRuleCount;
        ss >> nMaxSupply >> nRuleCount;
        for (uint32 i = 0; i < nRuleCount; i++)
        {
            string strName;
            CUEERule ruleUee;
            ss >> strName >> ruleUee;
            mapRule.insert(make_pair(strName, ruleUee));
        }
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(std::string("uee profile data error, err: ") + e.what());
    }
}

//////////////////////////////
// CProfile

bool CProfile::Save(std::vector<unsigned char>& vchProfile)
{
    try
    {
        CCompactTagValue encoder;
        encoder.Push(PROFILE_VERSION, nVersion);
        encoder.Push(PROFILE_NAME, strName);
        encoder.Push(PROFILE_SYMBOL, strSymbol);
        encoder.Push(PROFILE_FLAG, nFlag);
        encoder.Push(PROFILE_AMOUNT, nAmount);
        encoder.Push(PROFILE_MINTREWARD, nMintReward);
        encoder.Push(PROFILE_MINTXFEE, nMinTxFee);
        encoder.Push(PROFILE_HALVECYCLE, nHalveCycle);

        vector<unsigned char> vchDestOwner;
        CODataStream os(vchDestOwner);
        os << destOwner.prefix << destOwner.data;
        encoder.Push(PROFILE_OWNER, vchDestOwner);

        if (hashParent != 0)
        {
            encoder.Push(PROFILE_PARENT, hashParent);
            encoder.Push(PROFILE_JOINTHEIGHT, nJointHeight);
        }

        if (nForkType != FORK_TYPE_COMMON)
        {
            encoder.Push(PROFILE_FORKTYPE, nForkType);

            if (nForkType == FORK_TYPE_DEFI)
            {
                vector<unsigned char> vchDeFi;
                defi.Save(vchDeFi);
                encoder.Push(PROFILE_DEFI, vchDeFi);
            }
            else if (nForkType == FORK_TYPE_UEE)
            {
                vector<unsigned char> vchUee;
                uee.Save(vchUee);
                encoder.Push(PROFILE_UEE, vchUee);
            }
        }

        encoder.Encode(vchProfile);
    }
    catch (exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
        return false;
    }
    return true;
}

bool CProfile::Load(const vector<unsigned char>& vchProfile)
{
    SetNull();
    CIDataStream is(vchProfile);
    try
    {
        CCompactTagValue decoder;
        decoder.Decode(vchProfile);
        if (!decoder.Get(PROFILE_VERSION, nVersion))
        {
            return false;
        }
        if (nVersion != 1)
        {
            return false;
        }
        if (!decoder.Get(PROFILE_NAME, strName))
        {
            return false;
        }
        if (!decoder.Get(PROFILE_SYMBOL, strSymbol))
        {
            return false;
        }
        if (!decoder.Get(PROFILE_FLAG, nFlag))
        {
            return false;
        }
        if (!decoder.Get(PROFILE_AMOUNT, nAmount))
        {
            return false;
        }
        if (!decoder.Get(PROFILE_MINTREWARD, nMintReward))
        {
            return false;
        }
        if (!decoder.Get(PROFILE_MINTXFEE, nMinTxFee))
        {
            return false;
        }
        if (!decoder.Get(PROFILE_HALVECYCLE, nHalveCycle))
        {
            return false;
        }

        if (!decoder.Get(PROFILE_PARENT, hashParent))
        {
            hashParent = 0;
        }

        if (!decoder.Get(PROFILE_JOINTHEIGHT, nJointHeight))
        {
            if (hashParent != 0)
            {
                return false;
            }
            nJointHeight = -1;
        }

        vector<unsigned char> vchDestOwner;
        if (decoder.Get(PROFILE_OWNER, vchDestOwner))
        {
            CIDataStream is(vchDestOwner);
            is >> destOwner.prefix >> destOwner.data;
        }

        if (decoder.Get(PROFILE_FORKTYPE, nForkType))
        {
            if (nForkType == FORK_TYPE_DEFI)
            {
                vector<unsigned char> vchDeFi;
                if (decoder.Get(PROFILE_DEFI, vchDeFi))
                {
                    defi.Load(vchDeFi);
                }
            }
            else if (nForkType == FORK_TYPE_UEE)
            {
                vector<unsigned char> vchUee;
                if (decoder.Get(PROFILE_UEE, vchUee))
                {
                    uee.Load(vchUee);
                }
            }
        }
        else
        {
            nForkType = FORK_TYPE_COMMON;
        }
    }
    catch (exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
        return false;
    }
    return true;
}
