// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BIGBANG_RPCMOD_H
#define BIGBANG_RPCMOD_H

#include "json/json_spirit.h"
#include <boost/function.hpp>
#include <boost/thread.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <unordered_map>

#include "base.h"
#include "event.h"
#include "rpc/rpc.h"
#include "xengine.h"

namespace bigbang
{

class CRPCMod : public xengine::IIOModule, virtual public xengine::CHttpEventListener //, virtual public CRPCModEventListener
{
public:
    typedef rpc::CRPCResultPtr (CRPCMod::*RPCFunc)(rpc::CRPCParamPtr param);
    CRPCMod();
    ~CRPCMod();
    bool HandleEvent(xengine::CEventHttpReq& eventHttpReq) override;
    bool HandleEvent(xengine::CEventHttpBroken& eventHttpBroken) override;
    //bool HandleEvent(xengine::CEventHttpGetRsp& event) override;
    // bool HandleEvent(CRPCModEventUpdateNewBlock& event) override;
    // bool HandleEvent(CRPCModEventUpdateNewTx& event) override;
    std::string CallRPCFromJSON(const std::string& content, const std::function<std::string(const std::string& data)>& lmdMask);

protected:
    bool HandleInitialize() override;
    void HandleDeinitialize() override;
    bool HandleInvoke() override;
    void HandleHalt() override;
    const CBasicConfig* BasicConfig()
    {
        return dynamic_cast<const CBasicConfig*>(xengine::IBase::Config());
    }
    const CNetworkConfig* Config()
    {
        return dynamic_cast<const CNetworkConfig*>(xengine::IBase::Config());
    }
    const CRPCServerConfig* RPCServerConfig()
    {
        return dynamic_cast<const CRPCServerConfig*>(IBase::Config());
    }

    void JsonReply(uint64 nNonce, const std::string& result);

    int GetInt(const rpc::CRPCInt64& i, int valDefault)
    {
        return i.IsValid() ? int(i) : valDefault;
    }
    unsigned int GetUint(const rpc::CRPCUint64& i, unsigned int valDefault)
    {
        return i.IsValid() ? uint64(i) : valDefault;
    }
    uint64 GetUint64(const rpc::CRPCUint64& i, uint64 valDefault)
    {
        return i.IsValid() ? uint64(i) : valDefault;
    }
    bool GetForkHashOfDef(const rpc::CRPCString& hex, uint256& hashFork)
    {
        if (!hex.empty())
        {
            if (hashFork.SetHex(hex) != hex.size())
            {
                return false;
            }
        }
        else
        {
            hashFork = pCoreProtocol->GetGenesisBlockHash();
        }
        return true;
    }
    bool CheckWalletError(Errno err);
    void ListDestination(std::vector<CDestination>& vDestination);
    bool CheckVersion(std::string& strVersion);
    std::string GetWidthString(const std::string& strIn, int nWidth);
    std::string GetWidthString(uint64 nCount, int nWidth);

private:
    /* System */
    rpc::CRPCResultPtr RPCHelp(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCStop(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCVersion(rpc::CRPCParamPtr param);
    /* Network */
    rpc::CRPCResultPtr RPCGetPeerCount(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCListPeer(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCAddNode(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCRemoveNode(rpc::CRPCParamPtr param);
    /* Worldline & TxPool */
    rpc::CRPCResultPtr RPCGetForkCount(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCListFork(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetForkGenealogy(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetBlockLocation(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetBlockCount(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetBlockHash(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetBlock(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetBlockDetail(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetTxPool(rpc::CRPCParamPtr param);
    // CRPCResultPtr RPCRemovePendingTx(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetTransaction(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCSendTransaction(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetForkHeight(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetVotes(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCListDelegate(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetDeFiRelation(rpc::CRPCParamPtr param);
    /* Wallet */
    rpc::CRPCResultPtr RPCListKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetNewKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCEncryptKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCLockKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCUnlockKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCRemoveKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCImportPrivKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCImportPubKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCImportKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCExportKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCAddNewTemplate(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCImportTemplate(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCExportTemplate(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCRemoveTemplate(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCValidateAddress(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetBalance(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCListTransaction(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCSendFrom(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCCreateTransaction(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCSignTransaction(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCSignMessage(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCListAddress(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCExportWallet(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCImportWallet(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCMakeOrigin(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCSignRawTransactionWithWallet(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCSendRawTransaction(rpc::CRPCParamPtr param);
    /* Util */
    rpc::CRPCResultPtr RPCVerifyMessage(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCMakeKeyPair(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetPubKey(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetPubKeyAddress(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetTemplateAddress(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCMakeTemplate(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCDecodeTransaction(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetTxFee(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCMakeSha256(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCAesEncrypt(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCAesDecrypt(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCListUnspent(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCListUnspentOld(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCReverseHex(rpc::CRPCParamPtr param);
    /* Mint */
    rpc::CRPCResultPtr RPCGetWork(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCSubmitWork(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCQueryStat(rpc::CRPCParamPtr param);

    /*Lws RPC*/
    rpc::CRPCResultPtr RPCGetFork(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCReport(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetBlocks(rpc::CRPCParamPtr param);
    /*call LWS Server for test PushBlock*/
    rpc::CRPCResultPtr RPCPushBlock(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCPushTxEvent(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetFullTx(rpc::CRPCParamPtr param);
    rpc::CRPCResultPtr RPCGetTxEvents(rpc::CRPCParamPtr param);

protected:
    // bool CalcForkPoints(const uint256& forkHash);
    // void TrySwitchFork(const uint256& blockHash, uint256& forkHash);
    // bool GetBlocks(const uint256& forkHash, const uint256& startHash, int32 n, std::vector<CBlockEx>& blocks);
    rpc::Cblockdatadetail BlockDetailToJSON(const uint256& hashFork, const CBlockEx& block);
    void HttpServerThreadFunc();

protected:
    xengine::IIOProc* pHttpServer;
    ICoreProtocol* pCoreProtocol;
    IService* pService;
    IDataStat* pDataStat;
    IForkManager* pForkManager;
    IPusher* pPusher;
    xengine::CIOCompletion ioComplt;
    xengine::CThread thrHttpServer;

private:
    std::map<std::string, RPCFunc> mapRPCFunc;

    bool fWriteRPCLog;
};

class CPusher : public IPusher, virtual public xengine::CHttpEventListener, virtual public CRPCModEventListener
{
public:
    typedef struct _PushBlockMessage
    {
        LiveClientInfo client;
        uint64 nNonce;
        int nReqId;
        uint256 hashFork;
        CBlockEx block;
    } PushBlockMessage;

    typedef struct _PushTxEventMessage
    {
        LiveClientInfo client;
        uint64 nNonce;
        int nReqId;
        uint256 hashFork;
        CDestination destFrom;
        CTransaction tx;
        uint64 nEventId;
        uint8 nState;
    } PushTxMessage;

    CPusher();
    ~CPusher();
    void InsertNewClient(const std::string& ipport, const LiveClientInfo& client) override;
    bool HandleEvent(xengine::CEventHttpGetRsp& event) override;
    bool HandleEvent(CRPCModEventUpdateNewBlock& event) override;
    bool HandleEvent(CRPCModEventUpdateTx& event) override;
    int64 GetNonce() const override;
    int64 GetFixedNonce() const override;
    bool GetLatestEventId(const uint256& hashFork, int64& nEventId) const override;
    bool GetTxEvents(const uint256& hashFork, int64 nStartEventId, int64 num, std::vector<CRPCModEventUpdateTx>& events) override;

protected:
    const CRPCServerConfig* RPCServerConfig();

    bool HandleInitialize() override;
    void HandleDeinitialize() override;
    bool HandleInvoke() override;
    void HandleHalt() override;

    bool CallRPC(const PushBlockMessage& message);
    bool CallRPC(const PushTxMessage& message);
    bool GetResponse(bool fSSL, const std::string& strHost, int nPort, const std::string& strURL, const std::string& content, std::string& response);
    rpc::Cblockdatadetail BlockDetailToJSON(const uint256& hashFork, const CBlockEx& block);
    void RemoveClients(const std::vector<std::string>& clients);
    void RemoveClient(const std::string& client);
    void RemoveClient(uint64 nNonce);

    void PushBlock(const PushBlockMessage& message);
    void PushTransaction(const PushTxMessage& message);

protected:
    ICoreProtocol* pCoreProtocol;
    IService* pService;

private:
    mutable boost::shared_mutex mMutex;
    std::map<std::string, LiveClientInfo> mapRPCClient;                  //  IP:PORT -> LiveClientInfo
    std::map<uint256, std::list<CRPCModEventUpdateTx>> mapTxEventStream; // hashFork -> Tx Event Stream
    std::map<uint256, std::set<int64>> mapTxEventId;                     // hashFork -> Tx Event ID
    int64 nNonce;
    const int64 nFixedNonce;
};

} // namespace bigbang

#endif //BIGBANG_RPCMOD_H
