// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addresstxindexdb.h"

#include <boost/bind.hpp>

#include "leveldbeng.h"

using namespace std;
using namespace xengine;

namespace bigbang
{
namespace storage
{

#define ADDRESS_TXINDEX_FLUSH_INTERVAL (600)

//////////////////////////////
// CForkAddressTxIndexDB

CForkAddressTxIndexDB::CForkAddressTxIndexDB(const boost::filesystem::path& pathDB)
{
    CLevelDBArguments args;
    args.path = pathDB.string();
    args.syncwrite = false;
    CLevelDBEngine* engine = new CLevelDBEngine(args);

    if (!CKVDB::Open(engine))
    {
        delete engine;
    }
}

CForkAddressTxIndexDB::~CForkAddressTxIndexDB()
{
    Close();
    dblCache.Clear();
}

bool CForkAddressTxIndexDB::RemoveAll()
{
    if (!CKVDB::RemoveAll())
    {
        return false;
    }
    dblCache.Clear();
    return true;
}

bool CForkAddressTxIndexDB::UpdateAddressTxIndex(const vector<pair<CAddrTxIndex, CAddrTxInfo>>& vAddNew, const vector<CAddrTxIndex>& vRemove)
{
    xengine::CWriteLock wlock(rwUpper);

    MapType& mapUpper = dblCache.GetUpperMap();

    for (const auto& vd : vAddNew)
    {
        mapUpper[vd.first] = vd.second;
    }

    for (const auto& vd : vRemove)
    {
        mapUpper[vd].SetNull();
    }

    return true;
}

bool CForkAddressTxIndexDB::RepairAddressTxIndex(const vector<pair<CAddrTxIndex, CAddrTxInfo>>& vAddUpdate, const vector<CAddrTxIndex>& vRemove)
{
    if (!TxnBegin())
    {
        return false;
    }

    for (const auto& vd : vAddUpdate)
    {
        Write(vd.first, vd.second);
    }

    for (const auto& vd : vRemove)
    {
        Erase(vd);
    }

    if (!TxnCommit())
    {
        return false;
    }
    return true;
}

bool CForkAddressTxIndexDB::WriteAddressTxIndex(const CAddrTxIndex& key, const CAddrTxInfo& value)
{
    return Write(key, value);
}

bool CForkAddressTxIndexDB::ReadAddressTxIndex(const CAddrTxIndex& key, CAddrTxInfo& value)
{
    {
        xengine::CReadLock rlock(rwUpper);

        MapType& mapUpper = dblCache.GetUpperMap();
        typename MapType::iterator it = mapUpper.find(key);
        if (it != mapUpper.end())
        {
            if (!it->second.IsNull())
            {
                value = it->second;
                return true;
            }
            return false;
        }
    }

    {
        xengine::CReadLock rlock(rwLower);

        MapType& mapLower = dblCache.GetLowerMap();
        typename MapType::iterator it = mapLower.find(key);
        if (it != mapLower.end())
        {
            if (!it->second.IsNull())
            {
                value = it->second;
                return true;
            }
            return false;
        }
    }

    return Read(key, value);
}

bool CForkAddressTxIndexDB::RetrieveAddressTxIndex(const CDestination& dest, const int64 nOffset, const int64 nCount, map<CAddrTxIndex, CAddrTxInfo>& mapAddrTxIndex)
{
    CGetAddressTxIndexWalker walker(nOffset, nCount, mapAddrTxIndex);
    WalkThroughAddressTxIndex(walker, dest);
    return true;
}

bool CForkAddressTxIndexDB::RetrieveTxIndex(const CAddrTxIndex& addrTxIndex, CAddrTxInfo& addrTxInfo)
{
    return Read(addrTxIndex, addrTxInfo);
}

bool CForkAddressTxIndexDB::Copy(CForkAddressTxIndexDB& dbAddressTxIndex)
{
    if (!dbAddressTxIndex.RemoveAll())
    {
        return false;
    }

    try
    {
        xengine::CReadLock rulock(rwUpper);
        xengine::CReadLock rdlock(rwLower);

        if (!WalkThrough(boost::bind(&CForkAddressTxIndexDB::CopyWalker, this, _1, _2, boost::ref(dbAddressTxIndex))))
        {
            return false;
        }

        dbAddressTxIndex.SetCache(dblCache);
    }
    catch (exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
        return false;
    }
    return true;
}

bool CForkAddressTxIndexDB::WalkThroughAddressTxIndex(CForkAddressTxIndexDBWalker& walker, const CDestination& dest)
{
    try
    {
        xengine::CReadLock rulock(rwUpper);
        xengine::CReadLock rdlock(rwLower);

        MapType& mapUpper = dblCache.GetUpperMap();
        MapType& mapLower = dblCache.GetLowerMap();

        if (dest.IsNull())
        {
            if (!WalkThrough(boost::bind(&CForkAddressTxIndexDB::LoadWalker, this, _1, _2, boost::ref(walker),
                                         boost::ref(mapUpper), boost::ref(mapLower))))
            {
                return false;
            }
        }
        else
        {
            if (!WalkThrough(boost::bind(&CForkAddressTxIndexDB::LoadWalker, this, _1, _2, boost::ref(walker),
                                         boost::ref(mapUpper), boost::ref(mapLower)),
                             dest, true))
            {
                return false;
            }
        }

        for (MapType::iterator it = mapLower.begin(); it != mapLower.end(); ++it)
        {
            const CAddrTxIndex& key = (*it).first;
            const CAddrTxInfo& value = (*it).second;
            if ((dest.IsNull() || key.dest == dest) && !mapUpper.count(key) && !value.IsNull())
            {
                if (!walker.Walk(key, value))
                {
                    return false;
                }
            }
        }
        for (MapType::iterator it = mapUpper.begin(); it != mapUpper.end(); ++it)
        {
            const CAddrTxIndex& key = (*it).first;
            const CAddrTxInfo& value = (*it).second;
            if ((dest.IsNull() || key.dest == dest) && !value.IsNull())
            {
                if (!walker.Walk(key, value))
                {
                    return false;
                }
            }
        }
    }
    catch (exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
        return false;
    }
    return true;
}

bool CForkAddressTxIndexDB::CopyWalker(CBufStream& ssKey, CBufStream& ssValue,
                                       CForkAddressTxIndexDB& dbAddressUnspent)
{
    CAddrTxIndex key;
    CAddrTxInfo value;
    ssKey >> key;
    ssValue >> value;

    return dbAddressUnspent.WriteAddressTxIndex(key, value);
}

bool CForkAddressTxIndexDB::LoadWalker(CBufStream& ssKey, CBufStream& ssValue,
                                       CForkAddressTxIndexDBWalker& walker, const MapType& mapUpper, const MapType& mapLower)
{
    CAddrTxIndex key;
    CAddrTxInfo value;
    ssKey >> key;

    if (mapUpper.count(key) || mapLower.count(key))
    {
        return true;
    }

    ssValue >> value;

    return walker.Walk(key, value);
}

bool CForkAddressTxIndexDB::Flush()
{
    xengine::CUpgradeLock ulock(rwLower);

    vector<pair<CAddrTxIndex, CAddrTxInfo>> vAddNew;
    vector<CAddrTxIndex> vRemove;

    MapType& mapLower = dblCache.GetLowerMap();
    for (typename MapType::iterator it = mapLower.begin(); it != mapLower.end(); ++it)
    {
        if (it->second.IsNull())
        {
            vRemove.push_back(it->first);
        }
        else
        {
            vAddNew.push_back(*it);
        }
    }

    if (!TxnBegin())
    {
        return false;
    }

    for (const auto& addr : vAddNew)
    {
        Write(addr.first, addr.second);
    }

    for (int i = 0; i < vRemove.size(); i++)
    {
        Erase(vRemove[i]);
    }

    if (!TxnCommit())
    {
        return false;
    }

    ulock.Upgrade();

    {
        xengine::CWriteLock wlock(rwUpper);
        dblCache.Flip();
    }

    return true;
}

//////////////////////////////
// CAddressTxIndexDB

CAddressTxIndexDB::CAddressTxIndexDB()
{
    pThreadFlush = nullptr;
    fStopFlush = true;
}

bool CAddressTxIndexDB::Initialize(const boost::filesystem::path& pathData, const bool fFlush)
{
    pathAddress = pathData / "addresstxindex";

    if (!boost::filesystem::exists(pathAddress))
    {
        boost::filesystem::create_directories(pathAddress);
    }

    if (!boost::filesystem::is_directory(pathAddress))
    {
        return false;
    }

    if (fFlush)
    {
        fStopFlush = false;
        pThreadFlush = new boost::thread(boost::bind(&CAddressTxIndexDB::FlushProc, this));
        if (pThreadFlush == nullptr)
        {
            fStopFlush = true;
            return false;
        }
    }
    return true;
}

void CAddressTxIndexDB::Deinitialize()
{
    if (pThreadFlush)
    {
        {
            boost::unique_lock<boost::mutex> lock(mtxFlush);
            fStopFlush = true;
        }
        condFlush.notify_all();
        pThreadFlush->join();
        delete pThreadFlush;
        pThreadFlush = nullptr;

        {
            CWriteLock wlock(rwAccess);

            for (map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.begin();
                 it != mapAddressDB.end(); ++it)
            {
                std::shared_ptr<CForkAddressTxIndexDB> spAddress = (*it).second;

                spAddress->Flush();
                spAddress->Flush();
            }
            mapAddressDB.clear();
        }
    }
    else
    {
        CWriteLock wlock(rwAccess);
        mapAddressDB.clear();
    }
}

bool CAddressTxIndexDB::AddNewFork(const uint256& hashFork)
{
    CWriteLock wlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        return true;
    }

    std::shared_ptr<CForkAddressTxIndexDB> spAddress(new CForkAddressTxIndexDB(pathAddress / hashFork.GetHex()));
    if (spAddress == nullptr || !spAddress->IsValid())
    {
        return false;
    }
    mapAddressDB.insert(make_pair(hashFork, spAddress));
    return true;
}

bool CAddressTxIndexDB::RemoveFork(const uint256& hashFork)
{
    CWriteLock wlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        (*it).second->RemoveAll();
        mapAddressDB.erase(it);
        return true;
    }
    return false;
}

void CAddressTxIndexDB::Clear()
{
    CWriteLock wlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.begin();
    while (it != mapAddressDB.end())
    {
        (*it).second->RemoveAll();
        mapAddressDB.erase(it++);
    }
}

bool CAddressTxIndexDB::UpdateAddressTxIndex(const uint256& hashFork, const vector<pair<CAddrTxIndex, CAddrTxInfo>>& vAddNew, const vector<CAddrTxIndex>& vRemove)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it == mapAddressDB.end())
    {
        StdLog("CAddressTxIndexDB", "UpdateAddressTxIndex: find fork fail, fork: %s", hashFork.GetHex().c_str());
        return false;
    }
    return it->second->UpdateAddressTxIndex(vAddNew, vRemove);
}

bool CAddressTxIndexDB::RepairAddressTxIndex(const uint256& hashFork, const vector<pair<CAddrTxIndex, CAddrTxInfo>>& vAddUpdate, const vector<CAddrTxIndex>& vRemove)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it == mapAddressDB.end())
    {
        StdLog("CAddressTxIndexDB", "RepairAddressTxIndex: find fork fail, fork: %s", hashFork.GetHex().c_str());
        return false;
    }
    return it->second->RepairAddressTxIndex(vAddUpdate, vRemove);
}

bool CAddressTxIndexDB::RetrieveAddressTxIndex(const uint256& hashFork, const CDestination& dest, const int64 nOffset, const int64 nCount, map<CAddrTxIndex, CAddrTxInfo>& mapAddrTxIndex)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it == mapAddressDB.end())
    {
        StdLog("CAddressTxIndexDB", "RetrieveAddressTxIndex: find fork fail, fork: %s", hashFork.GetHex().c_str());
        return false;
    }
    return it->second->RetrieveAddressTxIndex(dest, nOffset, nCount, mapAddrTxIndex);
}

bool CAddressTxIndexDB::RetrieveTxIndex(const uint256& hashFork, const CAddrTxIndex& addrTxIndex, CAddrTxInfo& addrTxInfo)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it == mapAddressDB.end())
    {
        StdLog("CAddressTxIndexDB", "RetrieveTxIndex: find fork fail, fork: %s", hashFork.GetHex().c_str());
        return false;
    }
    return it->second->RetrieveTxIndex(addrTxIndex, addrTxInfo);
}

bool CAddressTxIndexDB::Copy(const uint256& srcFork, const uint256& destFork)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator itSrc = mapAddressDB.find(srcFork);
    if (itSrc == mapAddressDB.end())
    {
        return false;
    }

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator itDest = mapAddressDB.find(destFork);
    if (itDest == mapAddressDB.end())
    {
        return false;
    }

    return ((*itSrc).second->Copy(*(*itDest).second));
}

bool CAddressTxIndexDB::WalkThrough(const uint256& hashFork, CForkAddressTxIndexDBWalker& walker)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        return (*it).second->WalkThroughAddressTxIndex(walker);
    }
    return false;
}

void CAddressTxIndexDB::Flush(const uint256& hashFork)
{
    boost::unique_lock<boost::mutex> lock(mtxFlush);
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        (*it).second->Flush();
    }
}

void CAddressTxIndexDB::FlushProc()
{
    SetThreadName("AddressTxIndexDB");
    boost::system_time timeout = boost::get_system_time();
    boost::unique_lock<boost::mutex> lock(mtxFlush);
    while (!fStopFlush)
    {
        timeout += boost::posix_time::seconds(ADDRESS_TXINDEX_FLUSH_INTERVAL);

        while (!fStopFlush)
        {
            if (!condFlush.timed_wait(lock, timeout))
            {
                break;
            }
        }

        if (!fStopFlush)
        {
            vector<std::shared_ptr<CForkAddressTxIndexDB>> vAddressDB;
            vAddressDB.reserve(mapAddressDB.size());
            {
                CReadLock rlock(rwAccess);

                for (map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.begin();
                     it != mapAddressDB.end(); ++it)
                {
                    vAddressDB.push_back((*it).second);
                }
            }
            for (int i = 0; i < vAddressDB.size(); i++)
            {
                vAddressDB[i]->Flush();
            }
        }
    }
}

} // namespace storage
} // namespace bigbang
