// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORAGE_BLOCKBASE_H
#define STORAGE_BLOCKBASE_H

#include <boost/range/adaptor/reversed.hpp>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <boost/thread/thread.hpp>
#include <list>
#include <map>
#include <numeric>

#include "block.h"
#include "blockdb.h"
#include "forkcontext.h"
#include "profile.h"
#include "timeseries.h"
#include "xengine.h"

namespace bigbang
{
namespace storage
{

class CBlockBase;

class CBlockFork
{
public:
    CBlockFork(const CProfile& profileIn, CBlockIndex* pIndexLastIn)
      : forkProfile(profileIn), pIndexLast(pIndexLastIn), pIndexOrigin(pIndexLast->pOrigin)
    {
    }
    void ReadLock()
    {
        rwAccess.ReadLock();
    }
    void ReadUnlock()
    {
        rwAccess.ReadUnlock();
    }
    void WriteLock()
    {
        rwAccess.WriteLock();
    }
    void WriteUnlock()
    {
        rwAccess.WriteUnlock();
    }
    void UpgradeLock()
    {
        rwAccess.UpgradeLock();
    }
    void UpgradeUnlock()
    {
        rwAccess.UpgradeUnlock();
    }
    void UpgradeToWrite()
    {
        rwAccess.UpgradeToWriteLock();
    }
    xengine::CRWAccess& GetRWAccess() const
    {
        return rwAccess;
    }
    const CProfile& GetProfile() const
    {
        return forkProfile;
    }
    CBlockIndex* GetLast() const
    {
        return pIndexLast;
    }
    CBlockIndex* GetOrigin() const
    {
        return pIndexOrigin;
    }
    void UpdateLast(CBlockIndex* pIndexLastIn)
    {
        pIndexLast = pIndexLastIn;
        UpdateNext();
    }
    void UpdateNext()
    {
        if (pIndexLast != nullptr)
        {
            CBlockIndex* pIndexNext = pIndexLast;
            if (pIndexLast->pNext)
            {
                CBlockIndex* p = pIndexLast->pNext;
                while (p != nullptr)
                {
                    p->pPrev->pNext = nullptr;
                    p = p->pNext;
                }
                pIndexLast->pNext = nullptr;
            }
            while (!pIndexNext->IsOrigin() && pIndexNext->pPrev->pNext != pIndexNext)
            {
                CBlockIndex* pIndex = pIndexNext->pPrev;
                if (pIndex->pNext != nullptr)
                {
                    CBlockIndex* p = pIndex->pNext;
                    while (p != nullptr)
                    {
                        p->pPrev->pNext = nullptr;
                        p = p->pNext;
                    }
                }
                pIndex->pNext = pIndexNext;
                pIndexNext = pIndex;
            }
        }
    }

    xengine::CForest<CDestination, CDestination>& GetRelation()
    {
        return relation;
    }

protected:
    mutable xengine::CRWAccess rwAccess;
    CProfile forkProfile;
    CBlockIndex* pIndexLast;
    CBlockIndex* pIndexOrigin;
    xengine::CForest<CDestination, CDestination> relation;
};

class CBlockView
{
public:
    class CUnspent : public CTxOut
    {
    public:
        int nOpt;
        int nTxType;
        int nHeight;

    public:
        CUnspent()
          : nOpt(0), nTxType(-1), nHeight(-1) {}
        void Enable(const CTxOut& output, int nTxTypeIn, int nHeightIn)
        {
            destTo = output.destTo;
            nAmount = output.nAmount;
            nTxTime = output.nTxTime;
            nLockUntil = output.nLockUntil;
            nTxType = nTxTypeIn;
            nHeight = nHeightIn;
            nOpt++;
        }
        void Disable()
        {
            SetNull();
            nTxType = -1;
            nHeight = -1;
            nOpt--;
        }
        bool IsModified() const
        {
            return (nOpt != 0);
        }
    };
    CBlockView();
    ~CBlockView();
    void Initialize(CBlockBase* pBlockBaseIn, boost::shared_ptr<CBlockFork> spForkIn,
                    const uint256& hashForkIn, bool fCommittableIn);
    void Deinitialize();
    bool IsCommittable() const
    {
        return fCommittable;
    }
    boost::shared_ptr<CBlockFork> GetFork() const
    {
        return spFork;
    };
    const uint256& GetForkHash() const
    {
        return hashFork;
    };
    bool ExistsTx(const uint256& txid) const;
    bool RetrieveTx(const uint256& txid, CTransaction& tx);
    bool RetrieveUnspent(const CTxOutPoint& out, CTxOut& unspent);
    bool AddTx(const uint256& txid, const CTransaction& tx, int nHeight, const CDestination& destIn = CDestination(), int64 nValueIn = 0);
    /*bool AddTx(const uint256& txid, const CAssembledTx& tx)
    {
        return AddTx(txid, tx, 0, tx.destIn, tx.nValueIn);
    }*/
    void RemoveTx(const uint256& txid, const CTransaction& tx, const CTxContxt& txContxt = CTxContxt());
    void AddBlock(const uint256& hash, const CBlockEx& block);
    void RemoveBlock(const uint256& hash, const CBlockEx& block);
    void GetUnspentChanges(std::vector<CTxUnspent>& vAddNewUnspent, std::vector<CTxUnspent>& vRemoveUnspent);
    void GetTxUpdated(std::set<uint256>& setUpdate);
    void GetTxRemoved(std::vector<uint256>& vRemove);
    void GetBlockChanges(std::vector<CBlockEx>& vAdd, std::vector<CBlockEx>& vRemove) const;

protected:
    void InsertBlockList(const uint256& hash, const CBlockEx& block, std::list<std::pair<uint256, CBlockEx>>& blockList);

protected:
    CBlockBase* pBlockBase;
    boost::shared_ptr<CBlockFork> spFork;
    uint256 hashFork;
    bool fCommittable;
    std::map<uint256, CTransaction> mapTx;
    std::map<CTxOutPoint, CUnspent> mapUnspent;
    std::vector<uint256> vTxRemove;
    std::vector<uint256> vTxAddNew;
    std::list<std::pair<uint256, CBlockEx>> vBlockAddNew;
    std::list<std::pair<uint256, CBlockEx>> vBlockRemove;

    xengine::CForest<CDestination, CDestination> relationAddNew;
    std::set<CDestination> relationRemove;
};

class CBlockHeightIndex
{
public:
    CBlockHeightIndex()
      : nTimeStamp(0) {}
    CBlockHeightIndex(uint32 nTimeStampIn, CDestination destMintIn, const uint256& hashRefBlockIn)
      : nTimeStamp(nTimeStampIn), destMint(destMintIn), hashRefBlock(hashRefBlockIn) {}

public:
    uint32 nTimeStamp;
    CDestination destMint;
    uint256 hashRefBlock;
};

class CForkHeightIndex
{
public:
    CForkHeightIndex() {}

    void AddHeightIndex(uint32 nHeight, const uint256& hashBlock, uint32 nBlockTimeStamp, const CDestination& destMint, const uint256& hashRefBlock);
    void RemoveHeightIndex(uint32 nHeight, const uint256& hashBlock);
    void UpdateBlockRef(int nHeight, const uint256& hashBlock, const uint256& hashRefBlock);
    std::map<uint256, CBlockHeightIndex>* GetBlockMintList(uint32 nHeight);

protected:
    std::map<uint32, std::map<uint256, CBlockHeightIndex>> mapHeightIndex;
};

class CBlockBase
{
    friend class CBlockView;

public:
    CBlockBase();
    ~CBlockBase();
    bool Initialize(const boost::filesystem::path& pathDataLocation, bool fDebug, bool fRenewDB = false);
    void Deinitialize();
    void Clear();
    bool IsEmpty() const;
    bool Exists(const uint256& hash) const;
    bool ExistsTx(const uint256& txid);
    bool Initiate(const uint256& hashGenesis, const CBlock& blockGenesis, const uint256& nChainTrust);
    bool AddNew(const uint256& hash, CBlockEx& block, CBlockIndex** ppIndexNew, const uint256& nChainTrust, int64 nMinEnrollAmount);
    bool AddNewForkContext(const CForkContext& ctxt);
    bool Retrieve(const uint256& hash, CBlock& block);
    bool Retrieve(const CBlockIndex* pIndex, CBlock& block);
    bool Retrieve(const uint256& hash, CBlockEx& block);
    bool Retrieve(const CBlockIndex* pIndex, CBlockEx& block);
    bool RetrieveIndex(const uint256& hash, CBlockIndex** ppIndex);
    bool RetrieveFork(const uint256& hash, CBlockIndex** ppIndex);
    bool RetrieveFork(const std::string& strName, CBlockIndex** ppIndex);
    bool RetrieveProfile(const uint256& hash, CProfile& profile);
    bool RetrieveForkContext(const uint256& hash, CForkContext& ctxt);
    bool RetrieveAncestry(const uint256& hash, std::vector<std::pair<uint256, uint256>> vAncestry);
    bool RetrieveOrigin(const uint256& hash, CBlock& block);
    bool RetrieveTx(const uint256& txid, CTransaction& tx);
    bool RetrieveTx(const uint256& txid, CTransaction& tx, uint256& hashFork, int& nHeight);
    bool RetrieveTx(const uint256& hashFork, const uint256& txid, CTransaction& tx);
    bool RetrieveTxLocation(const uint256& txid, uint256& hashFork, int& nHeight);
    bool RetrieveAvailDelegate(const uint256& hash, int height, const std::vector<uint256>& vBlockRange,
                               int64 nMinEnrollAmount,
                               std::map<CDestination, std::size_t>& mapWeight,
                               std::map<CDestination, std::vector<unsigned char>>& mapEnrollData,
                               std::vector<std::pair<CDestination, int64>>& vecAmount);
    void ListForkIndex(std::multimap<int, CBlockIndex*>& mapForkIndex);
    bool GetBlockView(CBlockView& view);
    bool GetBlockView(const uint256& hash, CBlockView& view, bool fCommitable = false, bool fGetBranchBlock = true);
    bool GetForkBlockView(const uint256& hashFork, CBlockView& view);
    bool CommitBlockView(CBlockView& view, CBlockIndex* pIndexNew);
    bool LoadIndex(CBlockOutline& diskIndex);
    bool LoadTx(CTransaction& tx, uint32 nTxFile, uint32 nTxOffset, uint256& hashFork);
    bool FilterTx(const uint256& hashFork, CTxFilter& filter);
    bool FilterTx(const uint256& hashFork, int nDepth, CTxFilter& filter);
    bool ListForkContext(std::vector<CForkContext>& vForkCtxt);
    bool GetForkBlockLocator(const uint256& hashFork, CBlockLocator& locator, uint256& hashDepth, int nIncStep);
    bool GetForkBlockInv(const uint256& hashFork, const CBlockLocator& locator, std::vector<uint256>& vBlockHash, size_t nMaxCount);
    bool CheckConsistency(int nCheckLevel, int nCheckDepth);
    bool CheckInputSingleAddressForTxWithChange(const uint256& txid);
    bool ListForkUnspent(const uint256& hashFork, const CDestination& dest, uint32 nMax, std::vector<CTxUnspent>& vUnspent);
    bool RecordRollback(const std::vector<CBlockEx>& vBlockAddNew, const std::vector<CBlockEx>& vBlockRemove);
    bool RecordRemove(const CBlockEx& block);
    bool ListForkUnspentBatch(const uint256& hashFork, uint32 nMax, std::map<CDestination, std::vector<CTxUnspent>>& mapUnspent);
    bool RetrieveAddressUnspent(const uint256& hashFork, const CDestination& dest, std::map<CTxOutPoint, CUnspentOut>& mapUnspent);

    // DeFi
    template <typename D, typename Convert>
    bool ListDeFiRelation(const uint256& hashFork, const CBlockView& view, xengine::CForest<CDestination, D>& relation, Convert convert)
    {
        boost::shared_ptr<CBlockFork> spFork;
        {
            xengine::CReadLock rlock(rwAccess);
            spFork = GetFork(hashFork);
            if (!spFork)
            {
                return false;
            }
        }

        if (spFork->GetProfile().nForkType != FORK_TYPE_DEFI)
        {
            return false;
        }
        relation = spFork->GetRelation().Copy<D>();

        std::vector<CBlockEx> vAdd;
        std::vector<CBlockEx> vRemove;
        view.GetBlockChanges(vAdd, vRemove);

        for (const CBlockEx& block : vRemove)
        {
            for (int i = block.vtx.size() - 1; i >= 0; --i)
            {
                const CTransaction& tx = block.vtx[i];
                if (tx.IsDeFiRelation())
                {
                    relation.RemoveRelation(tx.sendTo);
                }
            }
        }

        for (const CBlockEx& block : boost::adaptors::reverse(vAdd))
        {
            for (std::size_t i = 0; i < block.vtx.size(); i++)
            {
                const CTransaction& tx = block.vtx[i];
                const CTxContxt& txContxt = block.vTxContxt[i];
                if (tx.IsDeFiRelation())
                {
                    if (!relation.Insert(tx.sendTo, txContxt.destIn, convert(tx, txContxt.destIn)))
                    {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    bool ListForkAllAddressAmount(const uint256& hashFork, CBlockView& view, std::map<CDestination, int64>& mapAddressAmount);
    bool AddDeFiRelation(const uint256& hashFork, CBlockView& view, boost::shared_ptr<CBlockFork> spFork);
    bool GetDeFiRelation(const uint256& hashFork, const CDestination& destIn, CAddrInfo& addrInfo);
    bool InitDeFiRelation(const uint256& hashFork);
    bool CheckAddDeFiRelation(const uint256& hashFork, const CDestination& dest, const CDestination& parent);

    bool GetVotes(const uint256& hashGenesis, const CDestination& destDelegate, int64& nVotes);
    bool GetDelegateList(const uint256& hashGenesis, uint32 nCount, std::multimap<int64, CDestination>& mapVotes);
    bool GetDelegatePaymentList(const uint256& block_hash, std::multimap<int64, CDestination>& mapVotes);
    bool VerifyRepeatBlock(const uint256& hashFork, uint32 height, const CDestination& destMint, uint16 nBlockType,
                           uint32 nBlockTimeStamp, uint32 nRefBlockTimeStamp, uint32 nExtendedBlockSpacing);
    bool GetBlockDelegateVote(const uint256& hashBlock, std::map<CDestination, int64>& mapVote);
    bool GetDelegateEnrollTx(int height, const std::vector<uint256>& vBlockRange, std::map<CDestination, CDiskPos>& mapEnrollTxPos);
    bool GetBlockDelegatedEnrollTx(const uint256& hashBlock, std::map<int, std::set<CDestination>>& mapEnrollDest);
    bool VerifyRefBlock(const uint256& hashGenesis, const uint256& hashRefBlock);
    CBlockIndex* GetForkValidLast(const uint256& hashGenesis, const uint256& hashFork, int nRefVacantHeight);
    bool VerifySameChain(const uint256& hashPrevBlock, const uint256& hashAfterBlock);
    bool GetLastRefBlockHash(const uint256& hashFork, const uint256& hashBlock, uint256& hashRefBlock, bool& fOrigin);
    bool GetPrimaryHeightBlockTime(const uint256& hashLastBlock, int nHeight, uint256& hashBlock, int64& nTime);

protected:
    CBlockIndex* GetIndex(const uint256& hash) const;
    CBlockIndex* GetOrCreateIndex(const uint256& hash);
    CBlockIndex* GetBranch(CBlockIndex* pIndexRef, CBlockIndex* pIndex, std::vector<CBlockIndex*>& vPath);
    CBlockIndex* GetOriginIndex(const uint256& txidMint) const;
    void UpdateBlockHeightIndex(const uint256& hashFork, const uint256& hashBlock, uint32 nBlockTimeStamp, const CDestination& destMint, const uint256& hashRefBlock);
    void RemoveBlockIndex(const uint256& hashFork, const uint256& hashBlock);
    void UpdateBlockRef(const uint256& hashFork, const uint256& hashBlock, const uint256& hashRefBlock);
    CBlockIndex* AddNewIndex(const uint256& hash, const CBlock& block, uint32 nFile, uint32 nOffset, uint256 nChainTrust);
    boost::shared_ptr<CBlockFork> GetFork(const uint256& hash);
    boost::shared_ptr<CBlockFork> GetFork(const std::string& strName);
    boost::shared_ptr<CBlockFork> AddNewFork(const CProfile& profileIn, CBlockIndex* pIndexLast);
    bool LoadForkProfile(const CBlockIndex* pIndexOrigin, CProfile& profile);
    bool VerifyDelegateVote(const uint256& hash, CBlockEx& block, int64 nMinEnrollAmount, CDelegateContext& ctxtDelegate);
    bool UpdateDelegate(const uint256& hash, CBlockEx& block, const CDiskPos& posBlock, CDelegateContext& ctxtDelegate);
    bool GetTxUnspent(const uint256 fork, const CTxOutPoint& out, CTxOut& unspent);
    bool GetTxNewIndex(CBlockView& view, CBlockIndex* pIndexNew, std::vector<std::pair<uint256, CTxIndex>>& vTxNew);
    bool IsValidBlock(CBlockIndex* pForkLast, const uint256& hashBlock);
    bool VerifyValidBlock(CBlockIndex* pIndexGenesisLast, const CBlockIndex* pIndex);
    CBlockIndex* GetLongChainLastBlock(const uint256& hashFork, int nStartHeight, CBlockIndex* pIndexGenesisLast, const std::set<uint256>& setInvalidHash);
    void ClearCache();
    bool LoadDB();
    bool InitDeFiRelation(boost::shared_ptr<CBlockFork> spFork);
    bool SetupLog(const boost::filesystem::path& pathDataLocation, bool fDebug);
    void Log(const char* pszIdent, const char* pszFormat, ...)
    {
        va_list ap;
        va_start(ap, pszFormat);
        log(pszIdent, "[INFO]", pszFormat, ap);
        va_end(ap);
    }
    void Debug(const char* pszIdent, const char* pszFormat, ...)
    {
        if (fDebugLog)
        {
            va_list ap;
            va_start(ap, pszFormat);
            log(pszIdent, "[DEBUG]", pszFormat, ap);
            va_end(ap);
        }
    }
    void Warn(const char* pszIdent, const char* pszFormat, ...)
    {
        va_list ap;
        va_start(ap, pszFormat);
        log(pszIdent, "[WARN]", pszFormat, ap);
        va_end(ap);
    }
    void Error(const char* pszIdent, const char* pszFormat, ...)
    {
        va_list ap;
        va_start(ap, pszFormat);
        log(pszIdent, "[ERROR]", pszFormat, ap);
        va_end(ap);
    }

protected:
    mutable xengine::CRWAccess rwAccess;
    xengine::CLog log;
    bool fDebugLog;
    CBlockDB dbBlock;
    CTimeSeriesCached tsBlock;
    std::map<uint256, CBlockIndex*> mapIndex;
    std::map<uint256, CForkHeightIndex> mapForkHeightIndex;
    std::map<uint256, boost::shared_ptr<CBlockFork>> mapFork;
};

} // namespace storage
} // namespace bigbang

#endif //STORAGE_BLOCKBASE_H
