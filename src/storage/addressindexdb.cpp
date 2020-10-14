// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addressindexdb.h"

#include <boost/bind.hpp>

#include "leveldbeng.h"

using namespace std;
using namespace xengine;

namespace bigbang
{
namespace storage
{

#define ADDRESS_INDEX_FLUSH_INTERVAL (60)

//////////////////////////////
// CAddrIndex

bool CAddrIndex::AddUnspent(const CTxOutPoint& out, const CUnspentOut& unspent)
{
    auto it = mapUnspent.find(out);
    if (it != mapUnspent.end())
    {
        if (it->second.IsNull())
        {
            it->second = unspent;
            nTotalValue += unspent.nAmount;
        }
    }
    else
    {
        mapUnspent[out] = unspent;
        nTotalValue += unspent.nAmount;
    }
    return true;
}

void CAddrIndex::RemoveUnspent(const CTxOutPoint& out)
{
    auto it = mapUnspent.find(out);
    if (it != mapUnspent.end() && !it->second.IsNull())
    {
        nTotalValue -= it->second.nAmount;
        it->second.SetNull();
    }
}

void CAddrIndex::SetData(CAddrIndex& addrIndex)
{
    for (const auto& vd : mapUnspent)
    {
        if (vd.second.IsNull())
        {
            addrIndex.RemoveUnspent(vd.first);
        }
        else
        {
            addrIndex.AddUnspent(vd.first, vd.second);
        }
    }
    *this = addrIndex;
}

void CAddrIndex::AddData(const CAddrIndex& addrIndex)
{
    for (const auto& vd : addrIndex.mapUnspent)
    {
        if (vd.second.IsNull())
        {
            RemoveUnspent(vd.first);
        }
        else
        {
            AddUnspent(vd.first, vd.second);
        }
    }
}

void CAddrIndex::ClearNull()
{
    auto it = mapUnspent.begin();
    while (it != mapUnspent.end())
    {
        if (it->second.IsNull())
        {
            mapUnspent.erase(it++);
        }
        else
        {
            ++it;
        }
    }
}

//////////////////////////////
// CForkAddressIndexDB

CForkAddressIndexDB::CForkAddressIndexDB(const boost::filesystem::path& pathDB)
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

CForkAddressIndexDB::~CForkAddressIndexDB()
{
    Close();
    dblCache.Clear();
}

bool CForkAddressIndexDB::RemoveAll()
{
    if (!CKVDB::RemoveAll())
    {
        return false;
    }
    dblCache.Clear();
    return true;
}

bool CForkAddressIndexDB::UpdateAddress(const vector<CTxUnspent>& vAddNew, const vector<CTxUnspent>& vRemove)
{
    xengine::CWriteLock wlock(rwUpper);

    MapType& mapUpper = dblCache.GetUpperMap();

    for (const auto& vd : vRemove)
    {
        mapUpper[vd.output.destTo].RemoveUnspent(static_cast<const CTxOutPoint&>(vd));
    }

    for (const auto& vd : vAddNew)
    {
        mapUpper[vd.output.destTo].AddUnspent(static_cast<const CTxOutPoint&>(vd), CUnspentOut(vd.output, vd.nTxType, vd.nHeight));
    }

    return true;
}

bool CForkAddressIndexDB::RepairAddress(const vector<pair<CDestination, CAddrIndex>>& vAddUpdate, const vector<CDestination>& vRemove)
{
    if (!TxnBegin())
    {
        return false;
    }

    for (const auto& addr : vAddUpdate)
    {
        Write(addr.first, addr.second);
    }

    for (const auto& dest : vRemove)
    {
        Erase(dest);
    }

    if (!TxnCommit())
    {
        return false;
    }
    return true;
}

bool CForkAddressIndexDB::WriteAddress(const CDestination& dest, const CAddrIndex& addrIndex)
{
    return Write(dest, addrIndex);
}

bool CForkAddressIndexDB::ReadAddress(const CDestination& dest, CAddrIndex& addrIndex)
{
    {
        xengine::CReadLock rlock(rwUpper);

        MapType& mapUpper = dblCache.GetUpperMap();
        typename MapType::iterator it = mapUpper.find(dest);
        if (it != mapUpper.end())
        {
            if (it->second.fLoad)
            {
                addrIndex = it->second;
                return true;
            }
        }
    }

    CAddrIndex addrIndexLower;
    bool fGetLower = false;
    bool fLoadLower = false;
    {
        xengine::CReadLock rlock(rwLower);

        MapType& mapLower = dblCache.GetLowerMap();
        typename MapType::iterator it = mapLower.find(dest);
        if (it != mapLower.end())
        {
            if (it->second.fLoad)
            {
                addrIndex = it->second;
                fLoadLower = true;
            }
            else
            {
                addrIndexLower = it->second;
                fGetLower = true;
            }
        }
    }

    if (!fLoadLower)
    {
        if (!Read(dest, addrIndex))
        {
            addrIndex.SetNull();
        }
        addrIndex.fLoad = true;
    }

    if (fGetLower)
    {
        for (const auto& vd : addrIndexLower.mapUnspent)
        {
            if (vd.second.IsNull())
            {
                addrIndex.RemoveUnspent(vd.first);
            }
            else
            {
                addrIndex.AddUnspent(vd.first, vd.second);
            }
        }
    }

    {
        xengine::CWriteLock wlock(rwUpper);

        MapType& mapUpper = dblCache.GetUpperMap();
        mapUpper[dest].SetData(addrIndex);
    }

    return true;
}

bool CForkAddressIndexDB::RetrieveAddressUnspent(const CDestination& dest, map<CTxOutPoint, CUnspentOut>& mapUnspent)
{
    CAddrIndex addrIndex;
    if (!ReadAddress(dest, addrIndex))
    {
        return false;
    }
    mapUnspent = addrIndex.mapUnspent;
    return true;
}

bool CForkAddressIndexDB::Copy(CForkAddressIndexDB& dbAddressIndex)
{
    if (!dbAddressIndex.RemoveAll())
    {
        return false;
    }

    try
    {
        xengine::CReadLock rulock(rwUpper);
        xengine::CReadLock rdlock(rwLower);

        if (!WalkThrough(boost::bind(&CForkAddressIndexDB::CopyWalker, this, _1, _2, boost::ref(dbAddressIndex))))
        {
            return false;
        }

        dbAddressIndex.SetCache(dblCache);
    }
    catch (exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
        return false;
    }
    return true;
}

bool CForkAddressIndexDB::WalkThroughAddress(CForkAddressIndexDBWalker& walker)
{
    try
    {
        xengine::CReadLock rulock(rwUpper);
        xengine::CReadLock rdlock(rwLower);

        MapType& mapUpper = dblCache.GetUpperMap();
        MapType& mapLower = dblCache.GetLowerMap();

        if (!WalkThrough(boost::bind(&CForkAddressIndexDB::LoadWalker, this, _1, _2, boost::ref(walker),
                                     boost::ref(mapUpper), boost::ref(mapLower))))
        {
            return false;
        }

        for (MapType::iterator it = mapLower.begin(); it != mapLower.end(); ++it)
        {
            const CDestination& dest = (*it).first;
            const CAddrIndex& addrIndex = (*it).second;
            if (!mapUpper.count(dest) && !addrIndex.IsNull())
            {
                if (!walker.Walk(dest, addrIndex))
                {
                    return false;
                }
            }
        }
        for (MapType::iterator it = mapUpper.begin(); it != mapUpper.end(); ++it)
        {
            const CDestination& dest = (*it).first;
            const CAddrIndex& addrIndex = (*it).second;
            if (!addrIndex.IsNull())
            {
                if (!walker.Walk(dest, addrIndex))
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

bool CForkAddressIndexDB::CopyWalker(CBufStream& ssKey, CBufStream& ssValue,
                                     CForkAddressIndexDB& dbAddressIndex)
{
    CDestination dest;
    CAddrIndex addrIndex;
    ssKey >> dest;
    ssValue >> addrIndex;

    return dbAddressIndex.WriteAddress(dest, addrIndex);
}

bool CForkAddressIndexDB::LoadWalker(CBufStream& ssKey, CBufStream& ssValue,
                                     CForkAddressIndexDBWalker& walker, const MapType& mapUpper, const MapType& mapLower)
{
    CDestination dest;
    CAddrIndex addrIndex;
    ssKey >> dest;

    if (mapUpper.count(dest) || mapLower.count(dest))
    {
        return true;
    }

    ssValue >> addrIndex;

    return walker.Walk(dest, addrIndex);
}

bool CForkAddressIndexDB::Flush()
{
    xengine::CUpgradeLock ulock(rwLower);

    vector<pair<CDestination, CAddrIndex>> vAddNew;
    vector<CDestination> vRemove;

    MapType& mapLower = dblCache.GetLowerMap();
    for (typename MapType::iterator it = mapLower.begin(); it != mapLower.end(); ++it)
    {
        if (it->second.IsNull())
        {
            vRemove.push_back(it->first);
        }
        else
        {
            if (it->second.fLoad)
            {
                vAddNew.push_back(*it);
            }
            else
            {
                CAddrIndex addrIndex;
                Read(it->first, addrIndex);
                for (const auto& vd : it->second.mapUnspent)
                {
                    if (vd.second.IsNull())
                    {
                        addrIndex.RemoveUnspent(vd.first);
                    }
                    else
                    {
                        addrIndex.AddUnspent(vd.first, vd.second);
                    }
                }
                vAddNew.push_back(make_pair(it->first, addrIndex));
            }
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
// CAddressIndexDB

CAddressIndexDB::CAddressIndexDB()
{
    pThreadFlush = nullptr;
    fStopFlush = true;
}

bool CAddressIndexDB::Initialize(const boost::filesystem::path& pathData)
{
    pathAddress = pathData / "addressindex";

    if (!boost::filesystem::exists(pathAddress))
    {
        boost::filesystem::create_directories(pathAddress);
    }

    if (!boost::filesystem::is_directory(pathAddress))
    {
        return false;
    }

    fStopFlush = false;
    pThreadFlush = new boost::thread(boost::bind(&CAddressIndexDB::FlushProc, this));
    if (pThreadFlush == nullptr)
    {
        fStopFlush = true;
        return false;
    }

    return true;
}

void CAddressIndexDB::Deinitialize()
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
    }

    {
        CWriteLock wlock(rwAccess);

        for (map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.begin();
             it != mapAddressDB.end(); ++it)
        {
            std::shared_ptr<CForkAddressIndexDB> spAddress = (*it).second;

            spAddress->Flush();
            spAddress->Flush();
        }
        mapAddressDB.clear();
    }
}

bool CAddressIndexDB::AddNewFork(const uint256& hashFork)
{
    CWriteLock wlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        return true;
    }

    std::shared_ptr<CForkAddressIndexDB> spAddress(new CForkAddressIndexDB(pathAddress / hashFork.GetHex()));
    if (spAddress == nullptr || !spAddress->IsValid())
    {
        return false;
    }
    mapAddressDB.insert(make_pair(hashFork, spAddress));
    return true;
}

bool CAddressIndexDB::RemoveFork(const uint256& hashFork)
{
    CWriteLock wlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        (*it).second->RemoveAll();
        mapAddressDB.erase(it);
        return true;
    }
    return false;
}

void CAddressIndexDB::Clear()
{
    CWriteLock wlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.begin();
    while (it != mapAddressDB.end())
    {
        (*it).second->RemoveAll();
        mapAddressDB.erase(it++);
    }
}

bool CAddressIndexDB::Update(const uint256& hashFork, const vector<CTxUnspent>& vAddNew, const vector<CTxUnspent>& vRemove)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        return (*it).second->UpdateAddress(vAddNew, vRemove);
    }
    return false;
}

bool CAddressIndexDB::RepairAddress(const uint256& hashFork, const vector<pair<CDestination, CAddrIndex>>& vAddUpdate, const vector<CDestination>& vRemove)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        return (*it).second->RepairAddress(vAddUpdate, vRemove);
    }
    return false;
}

bool CAddressIndexDB::Retrieve(const uint256& hashFork, const CDestination& dest, CAddrIndex& addrIndex)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        return (*it).second->ReadAddress(dest, addrIndex);
    }
    return false;
}

bool CAddressIndexDB::RetrieveAddressUnspent(const uint256& hashFork, const CDestination& dest, map<CTxOutPoint, CUnspentOut>& mapUnspent)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        return (*it).second->RetrieveAddressUnspent(dest, mapUnspent);
    }
    StdLog("CAddressIndexDB", "Retrieve: find fork fail");
    return false;
}

bool CAddressIndexDB::Copy(const uint256& srcFork, const uint256& destFork)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator itSrc = mapAddressDB.find(srcFork);
    if (itSrc == mapAddressDB.end())
    {
        return false;
    }

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator itDest = mapAddressDB.find(destFork);
    if (itDest == mapAddressDB.end())
    {
        return false;
    }

    return ((*itSrc).second->Copy(*(*itDest).second));
}

bool CAddressIndexDB::WalkThrough(const uint256& hashFork, CForkAddressIndexDBWalker& walker)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        return (*it).second->WalkThroughAddress(walker);
    }
    return false;
}

void CAddressIndexDB::Flush(const uint256& hashFork)
{
    boost::unique_lock<boost::mutex> lock(mtxFlush);
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it != mapAddressDB.end())
    {
        (*it).second->Flush();
    }
}

void CAddressIndexDB::FlushProc()
{
    SetThreadName("AddressIndexDB");
    boost::system_time timeout = boost::get_system_time();
    boost::unique_lock<boost::mutex> lock(mtxFlush);
    while (!fStopFlush)
    {
        timeout += boost::posix_time::seconds(ADDRESS_INDEX_FLUSH_INTERVAL);

        while (!fStopFlush)
        {
            if (!condFlush.timed_wait(lock, timeout))
            {
                break;
            }
        }

        if (!fStopFlush)
        {
            vector<std::shared_ptr<CForkAddressIndexDB>> vAddressDB;
            vAddressDB.reserve(mapAddressDB.size());
            {
                CReadLock rlock(rwAccess);

                for (map<uint256, std::shared_ptr<CForkAddressIndexDB>>::iterator it = mapAddressDB.begin();
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
