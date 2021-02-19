// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STORAGE_FORKDB_H
#define STORAGE_FORKDB_H

#include <map>

#include "forkcontext.h"
#include "uint256.h"
#include "xengine.h"

namespace bigbang
{
namespace storage
{

class CUeeSignKey
{
    friend class xengine::CStream;

public:
    uint256 hashFork;
    CDestination destUeeSign;
    uint256 hashBlock;
    int nTxIndex;

public:
    CUeeSignKey() {}
    CUeeSignKey(const uint256& hashForkIn, const CDestination& destUeeSignIn, const uint256& hashBlockIn, const int nTxIndexIn)
      : hashFork(hashForkIn), destUeeSign(destUeeSignIn), hashBlock(hashBlockIn), nTxIndex(nTxIndexIn) {}

protected:
    template <typename O>
    void Serialize(xengine::CStream& s, O& opt)
    {
        s.Serialize(hashFork, opt);
        s.Serialize(destUeeSign, opt);
        s.Serialize(hashBlock, opt);
        s.Serialize(nTxIndex, opt);
    }
};

class CQueryUeeSignKey
{
    friend class xengine::CStream;

public:
    uint256 hashFork;
    CDestination destUeeSign;

public:
    CQueryUeeSignKey() {}
    CQueryUeeSignKey(const uint256& hashForkIn, const CDestination& destUeeSignIn)
      : hashFork(hashForkIn), destUeeSign(destUeeSignIn) {}

protected:
    template <typename O>
    void Serialize(xengine::CStream& s, O& opt)
    {
        s.Serialize(hashFork, opt);
        s.Serialize(destUeeSign, opt);
    }
};

class CForkDB : public xengine::CKVDB
{
public:
    CForkDB() {}
    bool Initialize(const boost::filesystem::path& pathData, const uint256& hashGenesisBlockIn);
    void Deinitialize();
    bool AddNewForkContext(const CForkContext& ctxt);
    bool RemoveForkContext(const uint256& hashFork);
    bool RetrieveForkContext(const uint256& hashFork, CForkContext& ctxt);
    bool ListForkContext(std::vector<CForkContext>& vForkCtxt, std::map<uint256, CValidForkId>& mapValidForkId);
    bool UpdateFork(const uint256& hashFork, const uint256& hashLastBlock = uint256());
    bool RemoveFork(const uint256& hashFork);
    bool RetrieveFork(const uint256& hashFork, uint256& hashLastBlock);
    bool ListFork(std::vector<std::pair<uint256, uint256>>& vFork);
    bool AddValidForkHash(const uint256& hashBlock, const uint256& hashRefFdBlock, const std::map<uint256, int>& mapValidFork);
    bool RetrieveValidForkHash(const uint256& hashBlock, uint256& hashRefFdBlock, std::map<uint256, int>& mapValidFork);
    bool ListActiveFork(std::map<uint256, uint256>& mapActiveFork);
    bool AddUeeSignTx(const uint256& hashFork, const CDestination& destUeeSign, const uint256& hashBlock, const int nTxIndex, const uint256& txid, const int64 nBalance);
    bool ListUeeSignTx(const uint256& hashFork, const CDestination& destUeeSign, std::vector<std::tuple<uint256, int, uint256, int64>>& vUeeSignTx);
    void Clear();

protected:
    bool LoadCtxtWalker(xengine::CBufStream& ssKey, xengine::CBufStream& ssValue, std::vector<CForkContext>& vForkCtxt);
    bool LoadActiveForkWalker(xengine::CBufStream& ssKey, xengine::CBufStream& ssValue, std::map<uint256, uint256>& mapFork);
    bool LoadValidForkWalker(xengine::CBufStream& ssKey, xengine::CBufStream& ssValue, std::map<uint256, CValidForkId>& mapBlockForkId);
    bool LoadUeeSignTxWalker(xengine::CBufStream& ssKey, xengine::CBufStream& ssValue, std::vector<std::tuple<uint256, int, uint256, int64>>& vUeeSignTx);

protected:
    uint256 hashGenesisBlock;
};

} // namespace storage
} // namespace bigbang

#endif //STORAGE_FORKDB_H
