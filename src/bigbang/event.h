// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BIGBANG_EVENT_H
#define BIGBANG_EVENT_H

#include <map>
#include <set>
#include <vector>

#include "block.h"
#include "peerevent.h"
#include "struct.h"
#include "transaction.h"
#include "xengine.h"

namespace bigbang
{

enum
{
    EVENT_BASE = network::EVENT_PEER_MAX,
    EVENT_BLOCKMAKER_UPDATE,
    EVENT_BLOCKMAKER_ENROLL,
    EVENT_BLOCKMAKER_DISTRIBUTE,
    EVENT_BLOCKMAKER_PUBLISH,
    EVENT_BLOCKMAKER_AGREE,

    ///////// RPCMod ////////////////
    EVENT_RPCMOD_UPDATE_NEW_BLOCK,
    EVENT_RPCMOD_UPDATE_TRANSACTION
};

class CBlockMakerEventListener;
#define TYPE_BLOCKMAKEREVENT(type, body) \
    xengine::CEventCategory<type, CBlockMakerEventListener, body, CNil>

typedef TYPE_BLOCKMAKEREVENT(EVENT_BLOCKMAKER_UPDATE, CBlockMakerUpdate) CEventBlockMakerUpdate;
typedef TYPE_BLOCKMAKEREVENT(EVENT_BLOCKMAKER_AGREE, CDelegateAgreement) CEventBlockMakerAgree;

class CBlockMakerEventListener : virtual public xengine::CEventListener
{
public:
    virtual ~CBlockMakerEventListener() {}
    DECLARE_EVENTHANDLER(CEventBlockMakerUpdate);
    DECLARE_EVENTHANDLER(CEventBlockMakerAgree);
};

enum class CHANGE_STATE : uint8
{
    STATE_ADDED = 0,
    STATE_REMOVED = 1
};

template <int type, typename L, typename D>
class CRPCModEventData : public CEvent
{
    friend class CStream;

public:
    CRPCModEventData(uint64 nNonceIn, const uint256& hashForkIn, const CDestination& destFromIn, int64 nChangeIn, uint8 nStateIn)
      : CEvent(nNonceIn, type),
        hashFork(hashForkIn), destFrom(destFromIn), nChange(nChangeIn), nState(nStateIn)
    {
    }
    virtual ~CRPCModEventData() {}
    virtual bool Handle(CEventListener& listener)
    {
        try
        {
            return (dynamic_cast<L&>(listener)).HandleEvent(*this);
        }
        catch (std::bad_cast&)
        {
            return listener.HandleEvent(*this);
        }
        catch (std::exception& e)
        {
            StdError(__PRETTY_FUNCTION__, e.what());
        }
        return false;
    }

protected:
    template <typename O>
    void Serialize(CStream& s, O& opt)
    {
        s.Serialize(hashFork, opt);
        s.Serialize(data, opt);
    }

public:
    uint256 hashFork;
    CDestination destFrom;
    int64 nChange;
    uint8 nState;
    D data;
};

class CRPCModEventListener;
#define TYPE_RPCMOD_EVENT(type, body) \
    CRPCModEventData<type, CRPCModEventListener, body>

typedef TYPE_RPCMOD_EVENT(EVENT_RPCMOD_UPDATE_NEW_BLOCK, CBlockEx) CRPCModEventUpdateNewBlock;
typedef TYPE_RPCMOD_EVENT(EVENT_RPCMOD_UPDATE_TRANSACTION, CTransaction) CRPCModEventUpdateTx;

class CRPCModEventListener : virtual public CEventListener
{
public:
    virtual ~CRPCModEventListener() {}
    DECLARE_EVENTHANDLER(CRPCModEventUpdateNewBlock);
    DECLARE_EVENTHANDLER(CRPCModEventUpdateTx);
};

} // namespace bigbang

#endif //BIGBANG_EVENT_H
