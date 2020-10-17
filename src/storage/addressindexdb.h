// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORAGE_ADDRESSINDEXDB_H
#define STORAGE_ADDRESSINDEXDB_H

#include <boost/thread/thread.hpp>

#include "transaction.h"
#include "xengine.h"

namespace bigbang
{
namespace storage
{

//////////////////////////////
// CAddrIndex

class CAddrIndex
{
    friend class xengine::CStream;

public:
    std::map<CTxOutPoint, CUnspentOut> mapUnspent;
    bool fLoad;

public:
    CAddrIndex()
    {
        SetNull();
    }
    void SetNull()
    {
        mapUnspent.clear();
        fLoad = false;
    }
    bool IsNull() const
    {
        return mapUnspent.empty();
    }
    void AddUnspent(const CTxOutPoint& out, const CUnspentOut& unspent);
    void RemoveUnspent(const CTxOutPoint& out);
    void SetData(CAddrIndex& addrIndex);
    void ClearNull();
    friend bool operator==(const CAddrIndex& a, const CAddrIndex& b)
    {
        if (a.mapUnspent.size() != b.mapUnspent.size())
        {
            return false;
        }
        for (const auto& vd : a.mapUnspent)
        {
            auto mt = b.mapUnspent.find(vd.first);
            if (mt == b.mapUnspent.end())
            {
                return false;
            }
            if (vd.second != mt->second)
            {
                return false;
            }
        }
        return true;
    }
    friend bool operator!=(const CAddrIndex& a, const CAddrIndex& b)
    {
        return !(a == b);
    }

protected:
    template <typename O>
    void Serialize(xengine::CStream& s, O& opt)
    {
        s.Serialize(mapUnspent, opt);
    }
};

//////////////////////////////
// CForkAddressIndexDBWalker

class CForkAddressIndexDBWalker
{
public:
    virtual bool Walk(const CDestination& dest, const CAddrIndex& addrIndex) = 0;
};

//////////////////////////////
// CListAddressIndexWalker

class CListAddressIndexWalker : public CForkAddressIndexDBWalker
{
public:
    CListAddressIndexWalker() {}
    bool Walk(const CDestination& dest, const CAddrIndex& addrIndex) override
    {
        mapAddressIndex[dest] = addrIndex;
        return true;
    }

public:
    std::map<CDestination, CAddrIndex> mapAddressIndex;
};

//////////////////////////////
// CForkAddressIndexDB

class CForkAddressIndexDB : public xengine::CKVDB
{
    typedef std::map<CDestination, CAddrIndex> MapType;
    class CDblMap
    {
    public:
        CDblMap()
          : nIdxUpper(0) {}
        MapType& GetUpperMap()
        {
            return mapCache[nIdxUpper];
        }
        MapType& GetLowerMap()
        {
            return mapCache[nIdxUpper ^ 1];
        }
        void Flip()
        {
            MapType& mapLower = mapCache[nIdxUpper ^ 1];
            mapLower.clear();
            nIdxUpper = nIdxUpper ^ 1;
        }
        void Clear()
        {
            mapCache[0].clear();
            mapCache[1].clear();
            nIdxUpper = 0;
        }

    protected:
        MapType mapCache[2];
        int nIdxUpper;
    };

public:
    CForkAddressIndexDB(const boost::filesystem::path& pathDB);
    ~CForkAddressIndexDB();
    bool RemoveAll();
    bool UpdateAddress(const std::vector<CTxUnspent>& vAddNew, const std::vector<CTxUnspent>& vRemove);
    bool RepairAddress(const std::vector<std::pair<CDestination, CAddrIndex>>& vAddUpdate, const std::vector<CDestination>& vRemove);
    bool WriteAddress(const CDestination& dest, const CAddrIndex& addrIndex);
    bool ReadAddress(const CDestination& dest, CAddrIndex& addrIndex);
    bool RetrieveAddressUnspent(const CDestination& dest, std::map<CTxOutPoint, CUnspentOut>& mapUnspent);
    bool Copy(CForkAddressIndexDB& dbAddressIndex);
    void SetCache(const CDblMap& dblCacheIn)
    {
        dblCache = dblCacheIn;
    }
    bool WalkThroughAddress(CForkAddressIndexDBWalker& walker);
    bool Flush();

protected:
    bool CopyWalker(xengine::CBufStream& ssKey, xengine::CBufStream& ssValue,
                    CForkAddressIndexDB& dbAddressIndex);
    bool LoadWalker(xengine::CBufStream& ssKey, xengine::CBufStream& ssValue,
                    CForkAddressIndexDBWalker& walker, const MapType& mapUpper, const MapType& mapLower);

protected:
    xengine::CRWAccess rwUpper;
    xengine::CRWAccess rwLower;
    CDblMap dblCache;
};

class CAddressIndexDB
{
public:
    CAddressIndexDB();
    bool Initialize(const boost::filesystem::path& pathData);
    void Deinitialize();
    bool Exists(const uint256& hashFork)
    {
        return (!!mapAddressDB.count(hashFork));
    }
    bool AddNewFork(const uint256& hashFork);
    bool RemoveFork(const uint256& hashFork);
    void Clear();
    bool Update(const uint256& hashFork, const std::vector<CTxUnspent>& vAddNew, const std::vector<CTxUnspent>& vRemove);
    bool RepairAddress(const uint256& hashFork, const std::vector<std::pair<CDestination, CAddrIndex>>& vAddUpdate, const std::vector<CDestination>& vRemove);
    bool Retrieve(const uint256& hashFork, const CDestination& dest, CAddrIndex& addrIndex);
    bool RetrieveAddressUnspent(const uint256& hashFork, const CDestination& dest, std::map<CTxOutPoint, CUnspentOut>& mapUnspent);
    bool Copy(const uint256& srcFork, const uint256& destFork);
    bool WalkThrough(const uint256& hashFork, CForkAddressIndexDBWalker& walker);
    void Flush(const uint256& hashFork);

protected:
    void FlushProc();

protected:
    boost::filesystem::path pathAddress;
    xengine::CRWAccess rwAccess;
    std::map<uint256, std::shared_ptr<CForkAddressIndexDB>> mapAddressDB;

    boost::mutex mtxFlush;
    boost::condition_variable condFlush;
    boost::thread* pThreadFlush;
    bool fStopFlush;
};

} // namespace storage
} // namespace bigbang

#endif //STORAGE_ADDRESSINDEXDB_H
