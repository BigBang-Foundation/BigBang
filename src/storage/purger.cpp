// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "purger.h"

#include "blockdb.h"
#include "delegatevotesave.h"
#include "txpooldata.h"
#include "walletdb.h"

using namespace std;
using namespace boost::filesystem;
using namespace xengine;

namespace bigbang
{
namespace storage
{

//////////////////////////////
// CPurger

bool CPurger::ResetDB(const boost::filesystem::path& pathDataLocation, const uint256& hashGenesisBlockIn) const
{
    {
        CBlockDB dbBlock;
        if (dbBlock.Initialize(pathDataLocation, hashGenesisBlockIn, true))
        {
            if (!dbBlock.RemoveAll())
            {
                return false;
            }
            dbBlock.Deinitialize();
        }
    }

    {
        CTxPoolData datTxPool;
        if (datTxPool.Initialize(pathDataLocation))
        {
            if (!datTxPool.Remove())
            {
                return false;
            }
        }
    }

    {
        CDelegateVoteSave datVoteSave;
        if (datVoteSave.Initialize(pathDataLocation))
        {
            if (!datVoteSave.Remove())
            {
                return false;
            }
        }
    }

    return true;
}

bool CPurger::RemoveBlockFile(const path& pathDataLocation) const
{
    try
    {
        path pathBlock = pathDataLocation / "block";
        if (exists(pathBlock))
        {
            // delete all files except the block directory
            directory_iterator end;
            directory_iterator it(pathBlock);
            for (; it != end; it++)
            {
                remove_all(it->path());
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

} // namespace storage
} // namespace bigbang
