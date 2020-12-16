// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dexbbcmap.h"

#include "destination.h"
#include "rpc/auto_protocol.h"
#include "template.h"
#include "transaction.h"
#include "util.h"

using namespace std;
using namespace xengine;

//////////////////////////////
// CTemplateDexBbcMap

CTemplateDexBbcMap::CTemplateDexBbcMap(const CDestination& destOwnerIn)
  : CTemplate(TEMPLATE_DEXBBCMAP),
    destOwner(destOwnerIn)
{
}

CTemplateDexBbcMap* CTemplateDexBbcMap::clone() const
{
    return new CTemplateDexBbcMap(*this);
}

bool CTemplateDexBbcMap::GetSignDestination(const CTransaction& tx, const uint256& hashFork, int nHeight, const vector<uint8>& vchSig,
                                            set<CDestination>& setSubDest, vector<uint8>& vchSubSig) const
{
    if (!CTemplate::GetSignDestination(tx, hashFork, nHeight, vchSig, setSubDest, vchSubSig))
    {
        return false;
    }
    setSubDest.clear();
    setSubDest.insert(destOwner);
    return true;
}

void CTemplateDexBbcMap::GetTemplateData(bigbang::rpc::CTemplateResponse& obj, CDestination&& destInstance) const
{
    obj.dexbbcmap.strOwner = (destInstance = destOwner).ToString();
}

bool CTemplateDexBbcMap::ValidateParam() const
{
    if (!IsTxSpendable(destOwner))
    {
        return false;
    }
    return true;
}

bool CTemplateDexBbcMap::SetTemplateData(const std::vector<uint8>& vchDataIn)
{
    CIDataStream is(vchDataIn);
    try
    {
        is >> destOwner;
    }
    catch (exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
        return false;
    }
    return true;
}

bool CTemplateDexBbcMap::SetTemplateData(const bigbang::rpc::CTemplateRequest& obj, CDestination&& destInstance)
{
    if (obj.strType != GetTypeName(TEMPLATE_DEXBBCMAP))
    {
        return false;
    }
    if (!destInstance.ParseString(obj.dexbbcmap.strOwner))
    {
        return false;
    }
    destOwner = destInstance;
    return true;
}

void CTemplateDexBbcMap::BuildTemplateData()
{
    vchData.clear();
    CODataStream os(vchData);
    os << destOwner;
}

bool CTemplateDexBbcMap::VerifyTxSignature(const uint256& hash, const uint16 nType, const uint256& hashAnchor, const CDestination& destTo,
                                           const vector<uint8>& vchSig, const int32 nForkHeight, bool& fCompleted) const
{
    return destOwner.VerifyTxSignature(hash, nType, hashAnchor, destTo, vchSig, nForkHeight, fCompleted);
}
