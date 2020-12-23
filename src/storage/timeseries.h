// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORAGE_TIMESERIES_H
#define STORAGE_TIMESERIES_H

#include <boost/filesystem.hpp>
#include <boost/thread/thread.hpp>
#include <xengine.h>

#include "crc24q.h"
#include "uint256.h"

namespace bigbang
{
namespace storage
{

class CDiskPos
{
    friend class xengine::CStream;

public:
    uint32 nFile;
    uint32 nOffset;

public:
    CDiskPos(uint32 nFileIn = 0, uint32 nOffsetIn = 0)
      : nFile(nFileIn), nOffset(nOffsetIn) {}
    bool IsNull() const
    {
        return (nFile == 0);
    }
    bool operator==(const CDiskPos& b) const
    {
        return (nFile == b.nFile && nOffset == b.nOffset);
    }
    bool operator!=(const CDiskPos& b) const
    {
        return (nFile != b.nFile || nOffset != b.nOffset);
    }
    bool operator<(const CDiskPos& b) const
    {
        return (nFile < b.nFile || (nFile == b.nFile && nOffset < b.nOffset));
    }

protected:
    template <typename O>
    void Serialize(xengine::CStream& s, O& opt)
    {
        s.Serialize(nFile, opt);
        s.Serialize(nOffset, opt);
    }
};

template <typename T>
class CTSWalker
{
public:
    virtual bool Walk(const T& t, uint32 nFile, uint32 nOffset) = 0;
};

class CTSBufWalker
{
public:
    virtual bool Walk(const uint8* pBuf, const uint32 nSize, uint32 nFile, uint32 nOffset) = 0;
};

class CTimeSeriesBase
{
public:
    CTimeSeriesBase();
    ~CTimeSeriesBase();
    virtual bool Initialize(const boost::filesystem::path& pathLocationIn, const std::string& strPrefixIn);
    virtual void Deinitialize();

protected:
    bool CheckDiskSpace();
    const std::string FileName(uint32 nFile);
    bool GetFilePath(uint32 nFile, std::string& strPath);
    bool GetLastFilePath(uint32& nFile, std::string& strPath);
    bool RemoveFollowUpFile(uint32 nBeginFile);
    bool TruncateFile(const std::string& pathFile, uint32 nOffset);
    bool RepairFile(uint32 nFile, uint32 nOffset);

protected:
    enum
    {
        MAX_FILE_SIZE = 0x7F000000,
        MAX_CHUNK_SIZE = 0x200000
    };
    boost::filesystem::path pathLocation;
    std::string strPrefix;
    uint32 nLastFile;
};

class CTimeSeriesCached : public CTimeSeriesBase
{
public:
    CTimeSeriesCached();
    ~CTimeSeriesCached();
    bool Initialize(const boost::filesystem::path& pathLocationIn, const std::string& strPrefixIn);
    void Deinitialize();
    template <typename T>
    bool Write(const T& t, uint32& nFile, uint32& nOffset, bool fWriteCache = true)
    {
        boost::unique_lock<boost::mutex> lock(mtxCache);

        std::string pathFile;
        if (!GetLastFilePath(nFile, pathFile))
        {
            return false;
        }
        try
        {
            xengine::CFileStream fs(pathFile.c_str());
            fs.SeekToEnd();
            uint32 nSize = fs.GetSerializeSize(t);
            fs << nMagicNum << nSize;
            nOffset = fs.GetCurPos();
            fs << t;
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
            return false;
        }
        if (fWriteCache)
        {
            if (!WriteToCache(t, CDiskPos(nFile, nOffset)))
            {
                ResetCache();
            }
        }
        return true;
    }
    template <typename T>
    bool Write(const T& t, CDiskPos& pos, bool fWriteCache = true)
    {
        boost::unique_lock<boost::mutex> lock(mtxCache);

        std::string pathFile;
        if (!GetLastFilePath(pos.nFile, pathFile))
        {
            return false;
        }
        try
        {
            xengine::CFileStream fs(pathFile.c_str());
            fs.SeekToEnd();
            uint32 nSize = fs.GetSerializeSize(t);
            fs << nMagicNum << nSize;
            pos.nOffset = fs.GetCurPos();
            fs << t;
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
            return false;
        }
        if (fWriteCache)
        {
            if (!WriteToCache(t, pos))
            {
                ResetCache();
            }
        }
        return true;
    }
    bool Write(const uint8* pData, const uint32 nSize, CDiskPos& pos)
    {
        std::string pathFile;
        if (!GetLastFilePath(pos.nFile, pathFile))
        {
            return false;
        }
        try
        {
            xengine::CFileStream fs(pathFile.c_str());
            fs.SeekToEnd();
            pos.nOffset = fs.GetCurPos();
            fs.Write((const char*)pData, nSize);
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
            return false;
        }
        return true;
    }
    template <typename T>
    bool Read(T& t, uint32 nFile, uint32 nOffset, bool fWriteCache = true)
    {
        boost::unique_lock<boost::mutex> lock(mtxCache);

        if (ReadFromCache(t, CDiskPos(nFile, nOffset)))
        {
            return true;
        }

        std::string pathFile;
        if (!GetFilePath(nFile, pathFile))
        {
            return false;
        }
        try
        {
            // Open history file to read
            xengine::CFileStream fs(pathFile.c_str());
            fs.Seek(nOffset);
            fs >> t;
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
            return false;
        }

        if (fWriteCache)
        {
            if (!WriteToCache(t, CDiskPos(nFile, nOffset)))
            {
                ResetCache();
            }
        }
        return true;
    }
    template <typename T>
    bool Read(T& t, const CDiskPos& pos, bool fWriteCache = true)
    {
        boost::unique_lock<boost::mutex> lock(mtxCache);

        if (ReadFromCache(t, pos))
        {
            return true;
        }

        std::string pathFile;
        if (!GetFilePath(pos.nFile, pathFile))
        {
            return false;
        }
        try
        {
            // Open history file to read
            xengine::CFileStream fs(pathFile.c_str());
            fs.Seek(pos.nOffset);
            fs >> t;
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
            return false;
        }

        if (fWriteCache)
        {
            if (!WriteToCache(t, pos))
            {
                ResetCache();
            }
        }
        return true;
    }
    template <typename T>
    bool WalkThrough(CTSWalker<T>& walker, uint32& nLastFileRet, uint32& nLastPosRet, bool fRepairFile)
    {
        bool fRet = true;
        uint32 nFile = 1;
        uint32 nOffset = 0;
        nLastFileRet = 0;
        nLastPosRet = 0;
        std::string pathFile;

        while (GetFilePath(nFile, pathFile) && fRet)
        {
            nLastFileRet = nFile;
            bool fFileDataError = false;
            try
            {
                xengine::CFileStream fs(pathFile.c_str());
                fs.Seek(0);
                nOffset = 0;
                std::size_t nFileSize = fs.GetSize();
                if (nFileSize > MAX_FILE_SIZE)
                {
                    xengine::StdError("TimeSeriesCached", "WalkThrough: File size error, nFile: %d, size: %lu", nFile, nFileSize);
                    fFileDataError = true;
                    break;
                }
                while (!fs.IsEOF() && fRet && nOffset < (uint32)nFileSize)
                {
                    uint32 nMagic, nSize;
                    T t;
                    try
                    {
                        fs >> nMagic >> nSize >> t;
                    }
                    catch (std::exception& e)
                    {
                        xengine::StdError("TimeSeriesCached", "WalkThrough: Read error, nFile: %d, msg: %s", nFile, e.what());
                        fFileDataError = true;
                        break;
                    }
                    if (nMagic != nMagicNum || (fs.GetCurPos() - nOffset - 8 != nSize))
                    {
                        if (nMagic != nMagicNum)
                        {
                            xengine::StdError("TimeSeriesCached", "WalkThrough: nMagic error, nFile: %d, nMagic=%x, right magic: %x",
                                              nFile, nMagic, nMagicNum);
                        }
                        if (fs.GetCurPos() - nOffset - 8 != nSize)
                        {
                            xengine::StdError("TimeSeriesCached", "WalkThrough: read size error, nFile: %d, GetCurPos: %lu, nOffset: %d, nSize: %d",
                                              nFile, fs.GetCurPos(), nOffset, nSize);
                        }
                        fFileDataError = true;
                        break;
                    }
                    if (!walker.Walk(t, nFile, nOffset + 8))
                    {
                        xengine::StdLog("TimeSeriesCached", "WalkThrough: Walk fail");
                        fRet = false;
                        break;
                    }
                    nOffset = fs.GetCurPos();
                }
                if (fRet && !fFileDataError)
                {
                    if (nOffset != (uint32)nFileSize)
                    {
                        xengine::StdLog("TimeSeriesCached", "WalkThrough: nOffset error, nOffset: %d, nFileSize: %lu", nOffset, nFileSize);
                    }
                }
            }
            catch (std::exception& e)
            {
                xengine::StdError("TimeSeriesCached", "WalkThrough: catch error, nFile: %d, msg: %s", nFile, e.what());
                fRet = false;
                break;
            }
            if (fFileDataError)
            {
                if (fRepairFile)
                {
                    if (!RepairFile(nFile, nOffset))
                    {
                        xengine::StdError("TimeSeriesCached", "WalkThrough: RepairFile fail");
                        fRet = false;
                    }
                    xengine::StdLog("TimeSeriesCached", "WalkThrough: RepairFile success");
                }
                break;
            }
            nFile++;
        }
        nLastPosRet = nOffset;
        return fRet;
    }
    template <typename T>
    bool ReadDirect(T& t, uint32 nFile, uint32 nOffset)
    {
        std::string pathFile;
        if (!GetFilePath(nFile, pathFile))
        {
            return false;
        }
        try
        {
            xengine::CFileStream fs(pathFile.c_str());
            fs.Seek(nOffset);
            fs >> t;
        }
        catch (...)
        {
            return false;
        }
        return true;
    }
    int ReadDirect(uint8* pDataBuf, const int nReadSize, uint32 nFile, uint32 nOffset)
    {
        if (pDataBuf == nullptr || nReadSize <= 0)
        {
            return -1;
        }
        std::string pathFile;
        if (!GetFilePath(nFile, pathFile))
        {
            return -2;
        }
        FILE* f = fopen(pathFile.c_str(), "rb");
        if (f == nullptr)
        {
            return -3;
        }
        if (nOffset > 0)
        {
            fseek(f, nOffset, SEEK_SET);
        }
        size_t nLen = fread(pDataBuf, 1, nReadSize, f);
        fclose(f);
        return nLen;
    }
    int ReadLast(uint8* pDataBuf, const int nReadSize)
    {
        if (pDataBuf == nullptr || nReadSize <= 0)
        {
            xengine::StdError("TimeSeriesCached", "ReadLast: param error");
            return -1;
        }
        uint32 nFile;
        std::string pathFile;
        if (!GetLastFilePath(nFile, pathFile))
        {
            xengine::StdError("TimeSeriesCached", "ReadLast: GetLastFilePath fail");
            return -2;
        }
        FILE* f = fopen(pathFile.c_str(), "rb");
        if (f == nullptr)
        {
            return -3;
        }
        fseek(f, 0, SEEK_END);
        if (ftell(f) <= nReadSize)
        {
            fseek(f, 0, SEEK_SET);
        }
        else
        {
            fseek(f, nReadSize, SEEK_END);
        }
        size_t nLen = fread(pDataBuf, 1, nReadSize, f);
        fclose(f);
        return nLen;
    }
    bool WalkThrough(CTSBufWalker& walker, const uint32 nReadSliceSize)
    {
        uint32 nFile = 1;
        uint32 nOffset = 0;
        std::string pathFile;

        if (nReadSliceSize == 0)
        {
            return false;
        }
        uint8* pReadBuf = (uint8*)malloc(nReadSliceSize);
        if (pReadBuf == nullptr)
        {
            return false;
        }

        while (GetFilePath(nFile, pathFile))
        {
            FILE* f = fopen(pathFile.c_str(), "rb");
            if (f == nullptr)
            {
                free(pReadBuf);
                return false;
            }

            nOffset = 0;
            while (!feof(f))
            {
                size_t nLen = fread(pReadBuf, 1, nReadSliceSize, f);
                if (nLen == 0)
                {
                    break;
                }
                if (!walker.Walk(pReadBuf, nLen, nFile, nOffset))
                {
                    free(pReadBuf);
                    return false;
                }
                nOffset += nLen;
            }

            fclose(f);
            nFile++;
        }
        free(pReadBuf);
        return true;
    }
    bool WalkThrough(CTSBufWalker& walker)
    {
        bool fRet = true;
        uint32 nFile = 1;
        uint32 nOffset = 0;
        uint32 nSurplusSize = 0;
        std::string pathFile;

        const uint32 nReadBufSize = 0x2000000;
        uint8* pReadBuf = (uint8*)malloc(nReadBufSize);
        if (pReadBuf == nullptr)
        {
            return false;
        }

        while (GetFilePath(nFile, pathFile) && fRet)
        {
            FILE* f = fopen(pathFile.c_str(), "rb");
            if (f == nullptr)
            {
                fRet = false;
                break;
            }

            nOffset = 0;
            nSurplusSize = 0;
            while (!feof(f) && fRet)
            {
                if (nSurplusSize >= nReadBufSize)
                {
                    fRet = false;
                    break;
                }
                size_t nLen = fread(pReadBuf + nSurplusSize, 1, nReadBufSize - nSurplusSize, f);
                if (nLen == 0)
                {
                    break;
                }
                nSurplusSize += nLen;

                uint8* pCurPos = pReadBuf;
                while (nSurplusSize > sizeof(uint32) * 2)
                {
                    if (*(uint32*)pCurPos != nMagicNum)
                    {
                        fRet = false;
                        break;
                    }
                    uint32 nBlockSize = *(uint32*)(pCurPos + sizeof(uint32));
                    if (nBlockSize == 0 || nBlockSize > nReadBufSize / 2)
                    {
                        fRet = false;
                        break;
                    }
                    uint32 nSectSize = sizeof(uint32) * 2 + nBlockSize;
                    if (nSurplusSize < nSectSize)
                    {
                        break;
                    }
                    nOffset += (sizeof(uint32) * 2);
                    if (!walker.Walk(pCurPos + (sizeof(uint32) * 2), nBlockSize, nFile, nOffset))
                    {
                        fRet = false;
                        break;
                    }
                    nOffset += nBlockSize;
                    pCurPos += nSectSize;
                    nSurplusSize -= nSectSize;
                }

                if (fRet && pCurPos != pReadBuf && nSurplusSize > 0)
                {
                    if (pReadBuf + nSurplusSize > pCurPos)
                    {
                        size_t nFirstLen = pCurPos - pReadBuf;
                        memcpy(pReadBuf, pCurPos, nFirstLen);
                        memcpy(pReadBuf + nFirstLen, pCurPos + nFirstLen, nSurplusSize - nFirstLen);
                    }
                    else
                    {
                        memcpy(pReadBuf, pCurPos, nSurplusSize);
                    }
                }
            }

            if (fRet && nSurplusSize != 0)
            {
                fRet = false;
            }

            fclose(f);
            nFile++;
        }

        free(pReadBuf);
        return fRet;
    }
    size_t GetSize(const uint32 nFile = -1)
    {
        uint32 nFileNo = (nFile == -1) ? 1 : nFile;
        size_t nOffset = 0;
        std::string pathFile;
        while (GetFilePath(nFileNo, pathFile))
        {
            try
            {
                xengine::CFileStream fs(pathFile.c_str());
                nOffset += fs.GetSize();
            }
            catch (std::exception& e)
            {
                xengine::StdError("TimeSeriesCached", "GetSize: catch error, nFile: %d, msg: %s", nFile, e.what());
                break;
            }

            if (nFile == -1)
            {
                nFileNo++;
            }
            else
            {
                break;
            }
        }
        return nOffset;
    }
    template <typename T>
    static uint32 GetChecksum(T& t)
    {
        try
        {
            xengine::CBufStream ss;
            ss << t;
            return crypto::crc24q((uint8*)ss.GetData(), ss.GetSize());
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
        }
        return 0;
    }
    static uint32 GetChecksum(const uint8* pData, const uint32 nSize)
    {
        return crypto::crc24q(pData, nSize);
    }

protected:
    void ResetCache();
    bool VacateCache(uint32 nNeeded);
    template <typename T>
    bool WriteToCache(const T& t, const CDiskPos& diskpos)
    {
        if (mapCachePos.count(diskpos))
        {
            return true;
        }
        uint32 nSize = cacheStream.GetSerializeSize(t);
        if (!VacateCache(nSize))
        {
            return false;
        }
        try
        {
            std::size_t nPos;
            cacheStream << diskpos << nSize;
            nPos = cacheStream.GetWritePos();
            cacheStream << t;
            mapCachePos.insert(std::make_pair(diskpos, nPos));
            return true;
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
        }
        return false;
    }
    template <typename T>
    bool ReadFromCache(T& t, const CDiskPos& diskpos)
    {
        std::map<CDiskPos, size_t>::iterator it = mapCachePos.find(diskpos);
        if (it != mapCachePos.end())
        {
            if (cacheStream.Seek((*it).second))
            {
                try
                {
                    cacheStream >> t;
                    return true;
                }
                catch (std::exception& e)
                {
                    xengine::StdError(__PRETTY_FUNCTION__, e.what());
                }
            }
            ResetCache();
        }
        return false;
    }

protected:
    enum
    {
        FILE_CACHE_SIZE = 0x2000000
    };
    boost::mutex mtxCache;
    xengine::CCircularStream cacheStream;
    std::map<CDiskPos, std::size_t> mapCachePos;
    static const uint32 nMagicNum;
};

class CTimeSeriesChunk : public CTimeSeriesBase
{
public:
    CTimeSeriesChunk();
    ~CTimeSeriesChunk();
    template <typename T>
    bool Write(const T& t, CDiskPos& pos)
    {
        boost::unique_lock<boost::mutex> lock(mtxWriter);

        std::string pathFile;
        if (!GetLastFilePath(pos.nFile, pathFile))
        {
            return false;
        }
        try
        {
            xengine::CFileStream fs(pathFile.c_str());
            fs.SeekToEnd();
            uint32 nSize = fs.GetSerializeSize(t);
            fs << nMagicNum << nSize;
            pos.nOffset = fs.GetCurPos();
            fs << t;
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
            return false;
        }
        return true;
    }
    template <typename T>
    bool WriteBatch(const typename std::vector<T>& vBatch, std::vector<CDiskPos>& vPos)
    {
        boost::unique_lock<boost::mutex> lock(mtxWriter);

        size_t n = 0;

        while (n < vBatch.size())
        {
            uint32 nFile, nOffset;
            std::string pathFile;
            if (!GetLastFilePath(nFile, pathFile))
            {
                return false;
            }
            try
            {
                xengine::CFileStream fs(pathFile.c_str());
                fs.SeekToEnd();
                do
                {
                    uint32 nSize = fs.GetSerializeSize(vBatch[n]);
                    fs << nMagicNum << nSize;
                    nOffset = fs.GetCurPos();
                    fs << vBatch[n++];
                    vPos.push_back(CDiskPos(nFile, nOffset));
                } while (n < vBatch.size() && nOffset < MAX_FILE_SIZE - MAX_CHUNK_SIZE - 8);
            }
            catch (std::exception& e)
            {
                xengine::StdError(__PRETTY_FUNCTION__, e.what());
                return false;
            }
        }

        return true;
    }
    template <typename T>
    bool Read(T& t, const CDiskPos& pos)
    {
        std::string pathFile;
        if (!GetFilePath(pos.nFile, pathFile))
        {
            return false;
        }
        try
        {
            // Open history file to read
            xengine::CFileStream fs(pathFile.c_str());
            fs.Seek(pos.nOffset);
            fs >> t;
        }
        catch (std::exception& e)
        {
            xengine::StdError(__PRETTY_FUNCTION__, e.what());
            return false;
        }
        return true;
    }

protected:
    boost::mutex mtxWriter;
    static const uint32 nMagicNum;
};

} // namespace storage
} // namespace bigbang

#endif //STORAGE_TIMESERIES_H
