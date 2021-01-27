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
#define ADDRESS_TXINDEX_HISTORY_TRANS_HEIGHT 100000

//////////////////////////////
// CForkHistoryAddressTxIndexDB

CForkHistoryAddressTxIndexDB::CForkHistoryAddressTxIndexDB()
  : nPrevTransferHeight(0), fModifyAddressBf(false)
{
}

CForkHistoryAddressTxIndexDB::~CForkHistoryAddressTxIndexDB()
{
    Deinitialize();
}

bool CForkHistoryAddressTxIndexDB::Initialize(const boost::filesystem::path& pathDB)
{
    CLevelDBArguments args;
    args.path = (pathDB / "index").string();
    args.syncwrite = false;
    CLevelDBEngine* engine = new CLevelDBEngine(args);

    if (!Open(engine))
    {
        delete engine;
        return false;
    }

    if (!tsAddrTxIndexChunk.Initialize(pathDB, "hisaddrtxindex"))
    {
        Close();
        return false;
    }

    pathAddressBf = boost::filesystem::path(pathDB / "hisaddrtxindex/addressbf.dat");
    if (is_regular_file(pathAddressBf))
    {
        try
        {
            vector<unsigned char> vBfData;
            CFileStream fs(pathAddressBf.string().c_str());
            fs >> vBfData;
            bfAddress.SetData(vBfData);
        }
        catch (std::exception& e)
        {
            StdError(__PRETTY_FUNCTION__, e.what());
            Deinitialize();
            return false;
        }
    }

    return true;
}

void CForkHistoryAddressTxIndexDB::Deinitialize()
{
    PushHisAddressBfData();
    tsAddrTxIndexChunk.Deinitialize();
    Close();
    bfAddress.Reset();
}

int CForkHistoryAddressTxIndexDB::GetPrevTransferHeight()
{
    return nPrevTransferHeight;
}

void CForkHistoryAddressTxIndexDB::SetPrevTransferHeight(int nHeightIn)
{
    nPrevTransferHeight = nHeightIn;
}

bool CForkHistoryAddressTxIndexDB::RemoveAll()
{
    if (!CKVDB::RemoveAll())
    {
        return false;
    }
    return true;
}

bool CForkHistoryAddressTxIndexDB::AddAddressTxIndex(const uint32 nBeginHeight, const uint32 nEndHeight, const map<CDestination, vector<CHisAddrTxIndex>>& mapAddNew)
{
    vector<CDestination> vAddress;
    vector<vector<CHisAddrTxIndex>> vBatchWrite;

    vAddress.reserve(mapAddNew.size());
    vBatchWrite.reserve(mapAddNew.size());

    for (const auto& vd : mapAddNew)
    {
        vAddress.push_back(vd.first);
        vBatchWrite.push_back(vd.second);
    }

    vector<CDiskPos> vPos;
    if (!tsAddrTxIndexChunk.WriteBatch(vBatchWrite, vPos))
    {
        return false;
    }

    if (!TxnBegin())
    {
        return false;
    }

    uint64 nHeightSect = ((uint64)nBeginHeight << 32 | nEndHeight);
    for (size_t i = 0; i < vAddress.size(); i++)
    {
        Write(make_pair(vAddress[i], BSwap64(nHeightSect)), vPos[i]);
    }

    if (!TxnCommit())
    {
        return false;
    }

    for (size_t i = 0; i < vAddress.size(); i++)
    {
        try
        {
            xengine::CBufStream ss;
            ss << vAddress[i];
            bfAddress.Add((const unsigned char*)ss.GetData(), ss.GetSize());
            fModifyAddressBf = true;
        }
        catch (std::exception& e)
        {
            StdError(__PRETTY_FUNCTION__, e.what());
        }
    }
    return true;
}

void CForkHistoryAddressTxIndexDB::PushHisAddressBfData()
{
    if (fModifyAddressBf)
    {
        fModifyAddressBf = false;
        FILE* fp = fopen(pathAddressBf.string().c_str(), "w");
        if (fp == nullptr)
        {
            return;
        }
        fclose(fp);
        fp = nullptr;

        if (is_regular_file(pathAddressBf))
        {
            vector<unsigned char> vBfData;
            bfAddress.GetData(vBfData);
            try
            {
                CFileStream fs(pathAddressBf.string().c_str());
                fs << vBfData;
            }
            catch (std::exception& e)
            {
                StdError(__PRETTY_FUNCTION__, e.what());
            }
        }
    }
}

bool CForkHistoryAddressTxIndexDB::IsHisAddressBfExist(const CDestination& dest)
{
    try
    {
        xengine::CBufStream ss;
        ss << dest;
        if (bfAddress.Test((const unsigned char*)ss.GetData(), ss.GetSize()))
        {
            return true;
        }
    }
    catch (std::exception& e)
    {
        StdError(__PRETTY_FUNCTION__, e.what());
    }
    return false;
}

bool CForkHistoryAddressTxIndexDB::LoadWalker(xengine::CBufStream& ssKey, xengine::CBufStream& ssValue, vector<pair<uint64, CDiskPos>>& vTxIndexPos)
{
    pair<CDestination, uint64> key;
    CDiskPos value;
    ssKey >> key;
    ssValue >> value;
    vTxIndexPos.push_back(make_pair(BSwap64(key.second), value));
    return true;
}

bool CForkHistoryAddressTxIndexDB::GetHistoryAddressTxIndex(const CDestination& dest, const int nPrevHeightIn, const uint64 nPrevTxSeqIn, const int64 nOffsetIn, const int64 nCountIn, vector<CHisAddrTxIndex>& vAddrTxIndex)
{
    vector<pair<uint64, CDiskPos>> vTxIndexPos;
    if (!WalkThrough(boost::bind(&CForkHistoryAddressTxIndexDB::LoadWalker, this, _1, _2, boost::ref(vTxIndexPos)), dest, true))
    {
        return false;
    }
    uint64 nCurPos = 0;
    for (const auto& vd : vTxIndexPos)
    {
        if (nPrevHeightIn < -1 || nPrevTxSeqIn == -1)
        {
            vector<CHisAddrTxIndex> vTxIndex;
            if (!tsAddrTxIndexChunk.Read(vTxIndex, vd.second))
            {
                return false;
            }
            if (nOffsetIn < 0)
            {
                vAddrTxIndex.insert(vAddrTxIndex.end(), vTxIndex.begin(), vTxIndex.end());
            }
            else
            {
                for (const CHisAddrTxIndex& index : vTxIndex)
                {
                    if (nCurPos++ >= nOffsetIn)
                    {
                        vAddrTxIndex.push_back(index);
                        if (nCountIn > 0 && vAddrTxIndex.size() >= nCountIn)
                        {
                            return true;
                        }
                    }
                }
            }
        }
        else
        {
            uint32 nBeginHeight = vd.first >> 32;
            //uint32 nEndHeight = vd.first & 0xFFFFFFFF;
            if (nBeginHeight >= nPrevHeightIn)
            {
                vector<CHisAddrTxIndex> vTxIndex;
                if (!tsAddrTxIndexChunk.Read(vTxIndex, vd.second))
                {
                    return false;
                }
                int64 nPrevHeightSeq = (((int64)nPrevHeightIn << 32) | (nPrevTxSeqIn & 0xFFFFFFFFL));
                for (const CHisAddrTxIndex& index : vTxIndex)
                {
                    if (index.nHeightSeq >= nPrevHeightSeq)
                    {
                        vAddrTxIndex.push_back(index);
                        if (nCountIn > 0 && vAddrTxIndex.size() >= nCountIn)
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return true;
}

//////////////////////////////
// CGetAddressTxIndexWalker

bool CGetAddressTxIndexWalker::Walk(const CAddrTxIndex& key, const CAddrTxInfo& value)
{
    if (nPrevHeight < -1 || nPrevTxSeq == -1)
    {
        if (nOffset < 0)
        {
            vCacheAddrTxInfo.push_back(make_pair(key, value));
        }
        else
        {
            if (nCurPos++ >= nOffset)
            {
                if (nCount > 0 && mapAddressTxIndex.size() >= nCount)
                {
                    return false;
                }
                mapAddressTxIndex[key] = value;
                if (nCount > 0 && mapAddressTxIndex.size() >= nCount)
                {
                    return false;
                }
            }
        }
    }
    else
    {
        int64 nPrevHeightSeq = (((int64)nPrevHeight << 32) | (nPrevTxSeq & 0xFFFFFFFFL));
        if (key.nHeightSeq > nPrevHeightSeq)
        {
            if (nCount > 0 && mapAddressTxIndex.size() >= nCount)
            {
                return false;
            }
            nCurPos++;
            mapAddressTxIndex[key] = value;
            if (nCount > 0 && mapAddressTxIndex.size() >= nCount)
            {
                return false;
            }
        }
    }
    return true;
}

//////////////////////////////
// CForkAddressTxIndexDB

CForkAddressTxIndexDB::CForkAddressTxIndexDB()
{
}

CForkAddressTxIndexDB::~CForkAddressTxIndexDB()
{
    Deinitialize();
}

bool CForkAddressTxIndexDB::Initialize(const boost::filesystem::path& pathDB)
{
    CLevelDBArguments args;
    args.path = pathDB.string();
    args.syncwrite = false;
    CLevelDBEngine* engine = new CLevelDBEngine(args);

    if (!Open(engine))
    {
        delete engine;
        return false;
    }

    if (!dbHistory.Initialize(pathDB))
    {
        Close();
        return false;
    }
    return true;
}

void CForkAddressTxIndexDB::Deinitialize()
{
    dbHistory.Deinitialize();
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
        Write(CAddrTxIndex(vd.first.dest, BSwap64(vd.first.nHeightSeq), vd.first.txid), vd.second);
    }

    for (const auto& vd : vRemove)
    {
        Erase(CAddrTxIndex(vd.dest, BSwap64(vd.nHeightSeq), vd.txid));
    }

    if (!TxnCommit())
    {
        return false;
    }
    return true;
}

bool CForkAddressTxIndexDB::WriteAddressTxIndex(const CAddrTxIndex& key, const CAddrTxInfo& value)
{
    return Write(CAddrTxIndex(key.dest, BSwap64(key.nHeightSeq), key.txid), value);
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

    return Read(CAddrTxIndex(key.dest, BSwap64(key.nHeightSeq), key.txid), value);
}

int64 CForkAddressTxIndexDB::RetrieveAddressTxIndex(const CDestination& dest, const int nPrevHeight, const uint64 nPrevTxSeq, const int64 nOffset, const int64 nCount, map<CAddrTxIndex, CAddrTxInfo>& mapAddrTxIndex)
{
    vector<CHisAddrTxIndex> vAddrTxIndex;
    if (dbHistory.IsHisAddressBfExist(dest))
    {
        if (!dbHistory.GetHistoryAddressTxIndex(dest, nPrevHeight, nPrevTxSeq, nOffset, nCount, vAddrTxIndex))
        {
            return -1;
        }
        for (const CHisAddrTxIndex& hat : vAddrTxIndex)
        {
            CAddrTxIndex index(dest, hat.nHeightSeq, hat.txid);
            CAddrTxInfo info(hat.nDirection, hat.destPeer, hat.nTxType, hat.nTimeStamp, hat.nLockUntil, hat.nAmount, hat.nTxFee);
            mapAddrTxIndex.insert(make_pair(index, info));
        }
        return vAddrTxIndex.size();
    }

    if ((nPrevHeight < -1 || nPrevTxSeq == -1) && nOffset == -1)
    {
        // last count tx
        if (dest.IsNull())
        {
            return -1;
        }
        CGetAddressTxIndexWalker walker(-2, -1, -1, nCount, mapAddrTxIndex);
        WalkThroughAddressTxIndex(walker, dest, -2, -1);
        if (!walker.vCacheAddrTxInfo.empty())
        {
            int64 nSetOffset;
            if (nCount >= 0)
            {
                nSetOffset = walker.vCacheAddrTxInfo.size() - nCount;
                if (nSetOffset < 0)
                {
                    nSetOffset = 0;
                }
            }
            else
            {
                nSetOffset = 0;
            }
            auto it = walker.vCacheAddrTxInfo.begin() + nSetOffset;
            for (; it != walker.vCacheAddrTxInfo.end(); ++it)
            {
                mapAddrTxIndex.insert(make_pair(it->first, it->second));
            }
        }
        return walker.vCacheAddrTxInfo.size();
    }
    CGetAddressTxIndexWalker walker(nPrevHeight, nPrevTxSeq, nOffset, nCount, mapAddrTxIndex);
    WalkThroughAddressTxIndex(walker, dest, nPrevHeight, nPrevTxSeq);
    return walker.nCurPos;
}

bool CForkAddressTxIndexDB::RetrieveTxIndex(const CAddrTxIndex& addrTxIndex, CAddrTxInfo& addrTxInfo)
{
    return Read(CAddrTxIndex(addrTxIndex.dest, BSwap64(addrTxIndex.nHeightSeq), addrTxIndex.txid), addrTxInfo);
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

bool CForkAddressTxIndexDB::WalkThroughAddressTxIndex(CForkAddressTxIndexDBWalker& walker, const CDestination& dest, const int nPrevHeight, const uint64 nPrevTxSeq)
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
            if (nPrevHeight < -1 || nPrevTxSeq == -1)
            {
                if (!WalkThrough(boost::bind(&CForkAddressTxIndexDB::LoadWalker, this, _1, _2, boost::ref(walker),
                                             boost::ref(mapUpper), boost::ref(mapLower)),
                                 dest, true))
                {
                    return false;
                }
            }
            else
            {
                int64 nHeightSeq = (((int64)nPrevHeight << 32) | (nPrevTxSeq & 0xFFFFFFFFL));
                if (!WalkThroughOfPrefix(boost::bind(&CForkAddressTxIndexDB::LoadWalker, this, _1, _2, boost::ref(walker),
                                                     boost::ref(mapUpper), boost::ref(mapLower)),
                                         make_pair(dest, BSwap64(nHeightSeq)), dest))
                {
                    return false;
                }
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
    key.nHeightSeq = BSwap64(key.nHeightSeq);

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
    key.nHeightSeq = BSwap64(key.nHeightSeq);

    return walker.Walk(key, value);
}

bool CForkAddressTxIndexDB::TransferWalker(xengine::CBufStream& ssKey, xengine::CBufStream& ssValue, CForkAddressTxIndexDBWalker& walker)
{
    CAddrTxIndex key;
    CAddrTxInfo value;
    ssKey >> key;

    ssValue >> value;
    key.nHeightSeq = BSwap64(key.nHeightSeq);

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
            vRemove.push_back(CAddrTxIndex(it->first.dest, BSwap64(it->first.nHeightSeq), it->first.txid));
        }
        else
        {
            vAddNew.push_back(make_pair(CAddrTxIndex(it->first.dest, BSwap64(it->first.nHeightSeq), it->first.txid), it->second));
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

bool CForkAddressTxIndexDB::TransferHistoryData(const int nEndHeight, const int nTransferAddrCountIn, CAddrTxIndex& lastTransferKey, map<CDestination, vector<CHisAddrTxIndex>>& mapAddrHisTxIndexOut)
{
    class CTransferWalker : public CForkAddressTxIndexDBWalker
    {
    public:
        CTransferWalker(const int nEndHeightIn, const int nGetAddressCountIn, map<CDestination, vector<CHisAddrTxIndex>>& mapAddrHisTxIndexIn)
          : nEndHeight(nEndHeightIn), nGetAddressCount(nGetAddressCountIn), mapAddrHisTxIndex(mapAddrHisTxIndexIn) {}

        bool Walk(const CAddrTxIndex& key, const CAddrTxInfo& value)
        {
            if (!destLast.IsNull())
            {
                if (key.dest != destLast || key.GetHeight() >= nEndHeight)
                {
                    if (mapAddrHisTxIndex.size() >= nGetAddressCount)
                    {
                        lastKey = key;
                        return false;
                    }
                }
            }
            if (key.GetHeight() < nEndHeight)
            {
                mapAddrHisTxIndex[key.dest].push_back(CHisAddrTxIndex(key.nHeightSeq, key.txid, value.nDirection, value.destPeer,
                                                                      value.nTxType, value.nTimeStamp, value.nLockUntil, value.nAmount, value.nTxFee));
                destLast = key.dest;
            }
            return true;
        }

    protected:
        const int nEndHeight;
        const int nGetAddressCount;

    public:
        CAddrTxIndex lastKey;
        CDestination destLast;
        map<CDestination, vector<CHisAddrTxIndex>>& mapAddrHisTxIndex;
    };

    CTransferWalker walker(nEndHeight, nTransferAddrCountIn, mapAddrHisTxIndexOut);
    if (lastTransferKey.IsNull())
    {
        if (!WalkThrough(boost::bind(&CForkAddressTxIndexDB::TransferWalker, this, _1, _2, boost::ref(walker))))
        {
            return false;
        }
    }
    else
    {
        if (!WalkThrough(boost::bind(&CForkAddressTxIndexDB::TransferWalker, this, _1, _2, boost::ref(walker)), lastTransferKey, false))
        {
            return false;
        }
    }
    lastTransferKey = walker.lastKey;
    return true;
}

bool CForkAddressTxIndexDB::TransferHistoryTxIndex(const int nCurChainHeightIn, const int nTransferAddrCount)
{
    int nPrevTransferHeight = dbHistory.GetPrevTransferHeight();
    if (nCurChainHeightIn < ADDRESS_TXINDEX_HISTORY_TRANS_HEIGHT * 2
        || nCurChainHeightIn - nPrevTransferHeight < ADDRESS_TXINDEX_HISTORY_TRANS_HEIGHT * 2)
    {
        return true;
    }
    int nEndHeight = (nCurChainHeightIn / ADDRESS_TXINDEX_HISTORY_TRANS_HEIGHT - 1) * ADDRESS_TXINDEX_HISTORY_TRANS_HEIGHT;

    map<CDestination, vector<CHisAddrTxIndex>> mapAddrHisTxIndex;
    if (!TransferHistoryData(nEndHeight, nTransferAddrCount, cacheLastTransferKey, mapAddrHisTxIndex))
    {
        return true;
    }

    if (mapAddrHisTxIndex.empty() || cacheLastTransferKey.IsNull())
    {
        dbHistory.SetPrevTransferHeight(nEndHeight);
        cacheLastTransferKey.SetNull();
        return true;
    }

    dbHistory.AddAddressTxIndex(nEndHeight - ADDRESS_TXINDEX_HISTORY_TRANS_HEIGHT, nEndHeight, mapAddrHisTxIndex);

    return false;
}

void CForkAddressTxIndexDB::PushHisAddressBfData()
{
    dbHistory.PushHisAddressBfData();
}

//////////////////////////////
// CAddressTxIndexDB

CAddressTxIndexDB::CAddressTxIndexDB()
{
    pThreadFlush = nullptr;
    fStopFlush = true;
    nCurChainHeight = 0;
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

    std::shared_ptr<CForkAddressTxIndexDB> spAddress(new CForkAddressTxIndexDB());
    if (spAddress == nullptr || !spAddress->Initialize(pathAddress / hashFork.GetHex()))
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
    if (!vAddNew.empty())
    {
        int nNewHeight = vAddNew[0].first.GetHeight();
        if (nNewHeight > nCurChainHeight)
        {
            nCurChainHeight = nNewHeight;
        }
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

int64 CAddressTxIndexDB::RetrieveAddressTxIndex(const uint256& hashFork, const CDestination& dest, const int nPrevHeight, const uint64 nPrevTxSeq, const int64 nOffset, const int64 nCount, map<CAddrTxIndex, CAddrTxInfo>& mapAddrTxIndex)
{
    CReadLock rlock(rwAccess);

    map<uint256, std::shared_ptr<CForkAddressTxIndexDB>>::iterator it = mapAddressDB.find(hashFork);
    if (it == mapAddressDB.end())
    {
        StdLog("CAddressTxIndexDB", "RetrieveAddressTxIndex: find fork fail, fork: %s", hashFork.GetHex().c_str());
        return -1;
    }
    return it->second->RetrieveAddressTxIndex(dest, nPrevHeight, nPrevTxSeq, nOffset, nCount, mapAddrTxIndex);
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
            for (size_t i = 0; i < vAddressDB.size(); i++)
            {
                vAddressDB[i]->Flush();
            }

            while (!fStopFlush)
            {
                bool fSynAll = true;
                for (size_t i = 0; i < vAddressDB.size(); i++)
                {
                    if (!vAddressDB[i]->TransferHistoryTxIndex(nCurChainHeight, 100))
                    {
                        fSynAll = false;
                    }
                }
                if (fSynAll)
                {
                    break;
                }
                timeout = boost::get_system_time();
                condFlush.timed_wait(lock, timeout);
            }

            for (size_t i = 0; i < vAddressDB.size(); i++)
            {
                vAddressDB[i]->PushHisAddressBfData();
            }
        }
    }
}

} // namespace storage
} // namespace bigbang
