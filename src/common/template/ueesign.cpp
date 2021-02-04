// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ueesign.h"

#include "destination.h"
#include "rpc/auto_protocol.h"
#include "template.h"
#include "transaction.h"
#include "util.h"

using namespace std;
using namespace xengine;

//////////////////////////////
// CTemplateUeeSign

CTemplateUeeSign::CTemplateUeeSign(const CDestination& destOwnerIn, const CDestination& destAdminIn)
  : CTemplate(TEMPLATE_UEESIGN),
    destOwner(destOwnerIn),
    destAdmin(destAdminIn)
{
}

CTemplateUeeSign* CTemplateUeeSign::clone() const
{
    return new CTemplateUeeSign(*this);
}

bool CTemplateUeeSign::GetSignDestination(const CTransaction& tx, const uint256& hashFork, int nHeight, const vector<uint8>& vchSig,
                                          set<CDestination>& setSubDest, vector<uint8>& vchSubSig) const
{
    if (!CTemplate::GetSignDestination(tx, hashFork, nHeight, vchSig, setSubDest, vchSubSig))
    {
        StdLog("CTemplateUeeSign", "GetSignDestination: GetSignDestination fail");
        return false;
    }
    setSubDest.clear();
    setSubDest.insert(destOwner);
    return true;
}

void CTemplateUeeSign::GetTemplateData(bigbang::rpc::CTemplateResponse& obj, CDestination&& destInstance) const
{
    obj.ueesign.strOwner = (destInstance = destOwner).ToString();
    obj.ueesign.strAdmin = (destInstance = destAdmin).ToString();
}

bool CTemplateUeeSign::ValidateParam() const
{
    if (!destOwner.IsPubKey())
    {
        StdLog("CTemplateUeeSign", "ValidateParam: destOwner is not pubkey");
        return false;
    }
    if (!destAdmin.IsPubKey())
    {
        StdLog("CTemplateUeeSign", "ValidateParam: destAdmin is not pubkey");
        return false;
    }
    return true;
}

bool CTemplateUeeSign::SetTemplateData(const std::vector<uint8>& vchDataIn)
{
    CIDataStream is(vchDataIn);
    try
    {
        is >> destOwner >> destAdmin;
    }
    catch (exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
        return false;
    }
    return true;
}

bool CTemplateUeeSign::SetTemplateData(const bigbang::rpc::CTemplateRequest& obj, CDestination&& destInstance)
{
    if (obj.strType != GetTypeName(TEMPLATE_UEESIGN))
    {
        StdLog("CTemplateUeeSign", "SetTemplateData: GetTypeName fail");
        return false;
    }

    if (!destInstance.ParseString(obj.ueesign.strOwner))
    {
        StdLog("CTemplateUeeSign", "SetTemplateData: ParseString strOwner fail");
        return false;
    }
    destOwner = destInstance;

    if (!destInstance.ParseString(obj.ueesign.strAdmin))
    {
        StdLog("CTemplateUeeSign", "SetTemplateData: ParseString strAdmin fail");
        return false;
    }
    destAdmin = destInstance;
    return true;
}

void CTemplateUeeSign::BuildTemplateData()
{
    vchData.clear();
    CODataStream os(vchData);
    os << destOwner << destAdmin;
}

bool CTemplateUeeSign::VerifyTxSignature(const uint256& hash, const uint16 nType, const uint256& hashAnchor, const CDestination& destTo,
                                         const vector<uint8>& vchSig, const int32 nForkHeight, bool& fCompleted) const
{
    return destOwner.VerifyTxSignature(hash, nType, hashAnchor, destTo, vchSig, nForkHeight, fCompleted);
}
