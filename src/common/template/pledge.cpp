// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pledge.h"

#include "destination.h"
#include "rpc/auto_protocol.h"
#include "template.h"
#include "transaction.h"
#include "util.h"

using namespace std;
using namespace xengine;

//////////////////////////////
// CTemplatePledge

CTemplatePledge::CTemplatePledge(const CDestination& destOwnerIn, const vector<char>& vAidIn)
  : CTemplate(TEMPLATE_PLEDGE),
    destOwner(destOwnerIn),
    vAid(vAidIn)
{
}

CTemplatePledge* CTemplatePledge::clone() const
{
    return new CTemplatePledge(*this);
}

bool CTemplatePledge::GetSignDestination(const CTransaction& tx, const uint256& hashFork, int nHeight, const vector<uint8>& vchSig,
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

void CTemplatePledge::GetTemplateData(bigbang::rpc::CTemplateResponse& obj, CDestination&& destInstance) const
{
    obj.pledge.strOwner = (destInstance = destOwner).ToString();
    if (!vAid.empty())
    {
        std::string strTemp;
        strTemp.assign(&(vAid[0]), vAid.size());
        obj.pledge.strAid = strTemp;
    }
}

bool CTemplatePledge::ValidateParam() const
{
    if (!IsTxSpendable(destOwner))
    {
        return false;
    }
    return true;
}

bool CTemplatePledge::SetTemplateData(const vector<uint8>& vchDataIn)
{
    CIDataStream is(vchDataIn);
    try
    {
        is >> destOwner >> vAid;
    }
    catch (exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
        return false;
    }
    return true;
}

bool CTemplatePledge::SetTemplateData(const bigbang::rpc::CTemplateRequest& obj, CDestination&& destInstance)
{
    if (obj.strType != GetTypeName(TEMPLATE_PLEDGE))
    {
        return false;
    }
    if (!destInstance.ParseString(obj.pledge.strOwner))
    {
        return false;
    }
    destOwner = destInstance;

    if (obj.pledge.strAid.empty())
    {
        return false;
    }
    vAid.assign(obj.pledge.strAid.c_str(), obj.pledge.strAid.c_str() + obj.pledge.strAid.size());

    return true;
}

void CTemplatePledge::BuildTemplateData()
{
    vchData.clear();
    CODataStream os(vchData);
    os << destOwner << vAid;
}

bool CTemplatePledge::VerifyTxSignature(const uint256& hash, const uint16 nType, const uint256& hashAnchor, const CDestination& destTo,
                                        const vector<uint8>& vchSig, const int32 nForkHeight, bool& fCompleted) const
{
    return destOwner.VerifyTxSignature(hash, nType, hashAnchor, destTo, vchSig, nForkHeight, fCompleted);
}
