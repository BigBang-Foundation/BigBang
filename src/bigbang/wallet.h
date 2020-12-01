// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BIGBANG_WALLET_H
#define BIGBANG_WALLET_H

#include <boost/thread/thread.hpp>
#include <set>

#include "base.h"
#include "util.h"
#include "walletdb.h"
#include "wallettx.h"

namespace bigbang
{

using namespace xengine;

class CWalletCoins
{
public:
    CWalletCoins()
      : nTotalValue(0) {}
    void Push(const CWalletTxOut& out)
    {
        if (!out.IsNull())
        {
            if (setCoins.insert(out).second)
            {
                nTotalValue += out.GetAmount();
                out.AddRef();
            }
        }
    }
    void Pop(const CWalletTxOut& out)
    {
        if (!out.IsNull())
        {
            if (setCoins.erase(out))
            {
                nTotalValue -= out.GetAmount();
                out.Release();
            }
        }
    }

public:
    int64 nTotalValue;
    std::set<CWalletTxOut> setCoins;
};

class CWalletUnspent
{
public:
    void Clear()
    {
        mapWalletCoins.clear();
    }
    void Push(const uint256& hashFork, std::shared_ptr<CWalletTx>& spWalletTx, int n)
    {
        mapWalletCoins[hashFork].Push(CWalletTxOut(spWalletTx, n));
    }
    void Pop(const uint256& hashFork, std::shared_ptr<CWalletTx>& spWalletTx, int n)
    {
        mapWalletCoins[hashFork].Pop(CWalletTxOut(spWalletTx, n));
    }
    CWalletCoins& GetCoins(const uint256& hashFork)
    {
        return mapWalletCoins[hashFork];
    }
    void Dup(const uint256& hashFrom, const uint256& hashTo)
    {
        std::map<uint256, CWalletCoins>::iterator it = mapWalletCoins.find(hashFrom);
        if (it != mapWalletCoins.end())
        {
            CWalletCoins& coin = mapWalletCoins[hashTo];
            for (const CWalletTxOut& out : (*it).second.setCoins)
            {
                coin.Push(out);
            }
        }
    }

public:
    std::map<uint256, CWalletCoins> mapWalletCoins;
};

class CWalletKeyStore
{
public:
    CWalletKeyStore()
      : nTimerId(0), nAutoLockTime(-1), nAutoDelayTime(0) {}
    CWalletKeyStore(const crypto::CKey& keyIn)
      : key(keyIn), nTimerId(0), nAutoLockTime(-1), nAutoDelayTime(0) {}
    virtual ~CWalletKeyStore() {}

public:
    crypto::CKey key;
    uint32 nTimerId;
    int64 nAutoLockTime;
    int64 nAutoDelayTime;
};

class CWalletFork
{
public:
    CWalletFork(const uint256& hashParentIn = uint64(0), int nOriginHeightIn = -1, bool fIsolatedIn = true)
      : hashParent(hashParentIn), nOriginHeight(nOriginHeightIn), fIsolated(fIsolatedIn)
    {
    }
    void InsertSubline(int nHeight, const uint256& hashSubline)
    {
        mapSubline.insert(std::make_pair(nHeight, hashSubline));
    }

public:
    uint256 hashParent;
    int nOriginHeight;
    bool fIsolated;
    std::multimap<int, uint256> mapSubline;
};

class CWallet : public IWallet
{
public:
    CWallet();
    ~CWallet();
    bool IsMine(const CDestination& dest);
    /* Key store */
    boost::optional<std::string> AddKey(const crypto::CKey& key) override;
    bool LoadKey(const crypto::CKey& key);
    void GetPubKeys(std::set<crypto::CPubKey>& setPubKey) const override;
    bool Have(const crypto::CPubKey& pubkey, const int32 nVersion = -1) const override;
    bool Export(const crypto::CPubKey& pubkey, std::vector<unsigned char>& vchKey) const override;
    bool Import(const std::vector<unsigned char>& vchKey, crypto::CPubKey& pubkey) override;

    bool Encrypt(const crypto::CPubKey& pubkey, const crypto::CCryptoString& strPassphrase,
                 const crypto::CCryptoString& strCurrentPassphrase) override;
    bool GetKeyStatus(const crypto::CPubKey& pubkey, int& nVersion, bool& fLocked, int64& nAutoLockTime, bool& fPublic) const override;
    bool IsLocked(const crypto::CPubKey& pubkey) const override;
    bool Lock(const crypto::CPubKey& pubkey) override;
    bool Unlock(const crypto::CPubKey& pubkey, const crypto::CCryptoString& strPassphrase, int64 nTimeout) override;
    void AutoLock(uint32 nTimerId, const crypto::CPubKey& pubkey);
    bool Sign(const crypto::CPubKey& pubkey, const uint256& hash, std::vector<uint8>& vchSig) override;
    bool AesEncrypt(const crypto::CPubKey& pubkeyLocal, const crypto::CPubKey& pubkeyRemote, const std::vector<uint8>& vMessage, std::vector<uint8>& vCiphertext) override;
    bool AesDecrypt(const crypto::CPubKey& pubkeyLocal, const crypto::CPubKey& pubkeyRemote, const std::vector<uint8>& vCiphertext, std::vector<uint8>& vMessage) override;
    /* Template */
    bool LoadTemplate(CTemplatePtr ptr);
    void GetTemplateIds(std::set<CTemplateId>& setTemplateId) const override;
    bool Have(const CTemplateId& tid) const override;
    bool AddTemplate(CTemplatePtr& ptr) override;
    CTemplatePtr GetTemplate(const CTemplateId& tid) const override;
    /* Destination */
    void GetDestinations(std::set<CDestination>& setDest) override;
    /* Wallet Tx */
    bool SignTransaction(const CDestination& destIn, CTransaction& tx, const vector<uint8>& vchDestInData, const vector<uint8>& vchSendToData, const vector<uint8>& vchSignExtraData, const uint256& hashFork, const int32 nForkHeight, bool& fCompleted) override;
    /* Update */
    bool AddMemKey(const uint256& secret, crypto::CPubKey& pubkey) override;
    void RemoveMemKey(const crypto::CPubKey& pubkey) override;

protected:
    bool HandleInitialize() override;
    void HandleDeinitialize() override;
    bool HandleInvoke() override;
    void HandleHalt() override;
    bool LoadDB();
    void Clear();
    bool InsertKey(const crypto::CKey& key);

    bool SignPubKey(const crypto::CPubKey& pubkey, const uint256& hash, std::vector<uint8>& vchSig,
                    std::set<crypto::CPubKey>& setSignedKey);
    bool SignMultiPubKey(const std::set<crypto::CPubKey>& setPubKey, const uint256& hash, const uint256& hashAnchor,
                         std::vector<uint8>& vchSig, std::set<crypto::CPubKey>& setSignedKey);
    bool SignDestination(const CDestination& destIn, const CTransaction& tx, const vector<uint8>& vchDestInData, const uint256& hash,
                         std::vector<uint8>& vchSig, const vector<uint8>& vchSignExtraData, const uint256& hashFork, const int32 nForkHeight,
                         std::set<crypto::CPubKey>& setSignedKey, bool& fCompleted);
    void UpdateAutoLock(const std::set<crypto::CPubKey>& setSignedKey);
    bool GetSendToDestRecorded(const CTransaction& tx, const int nHeight, const std::vector<uint8>& vchSendToData, std::vector<uint8>& vchDestData);

protected:
    storage::CWalletDB dbWallet;
    IBlockChain* pBlockChain;
    mutable boost::shared_mutex rwKeyStore;
    std::map<crypto::CPubKey, CWalletKeyStore> mapKeyStore;
    std::map<CTemplateId, CTemplatePtr> mapTemplatePtr;
    std::map<crypto::CPubKey, uint256> mapMemSignKey;
};

// dummy wallet for on wallet server
class CDummyWallet : public IWallet
{
public:
    CDummyWallet() {}
    ~CDummyWallet() {}
    /* Key store */
    virtual boost::optional<std::string> AddKey(const crypto::CKey& key) override
    {
        return std::string();
    }
    virtual void GetPubKeys(std::set<crypto::CPubKey>& setPubKey) const override {}
    virtual bool Have(const crypto::CPubKey& pubkey, const int32 nVersion = -1) const override
    {
        return false;
    }
    virtual bool Export(const crypto::CPubKey& pubkey,
                        std::vector<unsigned char>& vchKey) const override
    {
        return false;
    }
    virtual bool Import(const std::vector<unsigned char>& vchKey,
                        crypto::CPubKey& pubkey) override
    {
        return false;
    }
    virtual bool Encrypt(
        const crypto::CPubKey& pubkey, const crypto::CCryptoString& strPassphrase,
        const crypto::CCryptoString& strCurrentPassphrase) override
    {
        return false;
    }
    virtual bool GetKeyStatus(const crypto::CPubKey& pubkey, int& nVersion,
                              bool& fLocked, int64& nAutoLockTime, bool& fPublic) const override
    {
        return false;
    }
    virtual bool IsLocked(const crypto::CPubKey& pubkey) const override
    {
        return false;
    }
    virtual bool Lock(const crypto::CPubKey& pubkey) override
    {
        return false;
    }
    virtual bool Unlock(const crypto::CPubKey& pubkey,
                        const crypto::CCryptoString& strPassphrase,
                        int64 nTimeout) override
    {
        return false;
    }
    virtual bool Sign(const crypto::CPubKey& pubkey, const uint256& hash,
                      std::vector<uint8>& vchSig) override
    {
        return false;
    }
    virtual bool AesEncrypt(const crypto::CPubKey& pubkeyLocal, const crypto::CPubKey& pubkeyRemote, const std::vector<uint8>& vMessage, std::vector<uint8>& vCiphertext) override
    {
        return false;
    }
    virtual bool AesDecrypt(const crypto::CPubKey& pubkeyLocal, const crypto::CPubKey& pubkeyRemote, const std::vector<uint8>& vCiphertext, std::vector<uint8>& vMessage) override
    {
        return false;
    }
    /* Template */
    virtual void GetTemplateIds(std::set<CTemplateId>& setTemplateId) const override {}
    virtual bool Have(const CTemplateId& tid) const override
    {
        return false;
    }
    virtual bool AddTemplate(CTemplatePtr& ptr) override
    {
        return false;
    }
    virtual CTemplatePtr GetTemplate(const CTemplateId& tid) const override
    {
        return nullptr;
    }
    /* Destination */
    virtual void GetDestinations(std::set<CDestination>& setDest) override
    {
    }
    /* Wallet Tx */
    virtual bool SignTransaction(const CDestination& destIn, CTransaction& tx, const vector<uint8>& vchDestInData, const vector<uint8>& vchSendToData, const vector<uint8>& vchSignExtraData,
                                 const uint256& hashFork, const int32 nForkHeight, bool& fCompleted) override
    {
        return false;
    }
    /* Update */
    virtual bool AddMemKey(const uint256& secret, crypto::CPubKey& pubkey) override
    {
        return true;
    }
    virtual void RemoveMemKey(const crypto::CPubKey& pubkey) override
    {
    }
};

} // namespace bigbang

#endif //BIGBANG_WALLET_H
