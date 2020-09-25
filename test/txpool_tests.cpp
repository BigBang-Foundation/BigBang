// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txpool.h"

#include <boost/test/unit_test.hpp>

#include "test_big.h"
#include "transaction.h"
#include "uint256.h"

using namespace std;
using namespace xengine;
using namespace bigbang;

BOOST_FIXTURE_TEST_SUITE(txpool_tests, BasicUtfSetup)

BOOST_AUTO_TEST_CASE(txcache_test)
{
    CTxCache cache(5);

    std::vector<CTransaction> vecTx;
    cache.AddNew(uint256(1, uint224()), vecTx);
    BOOST_CHECK(cache.Retrieve(uint256(1, uint224()), vecTx) == true);

    cache.AddNew(uint256(3, uint224()), vecTx);
    BOOST_CHECK(cache.Retrieve(uint256(1, uint224()), vecTx) == true);
    BOOST_CHECK(cache.Retrieve(uint256(3, uint224()), vecTx) == true);

    cache.AddNew(uint256(6, uint224()), vecTx);
    BOOST_CHECK(cache.Retrieve(uint256(1, uint224()), vecTx) == false);
    BOOST_CHECK(cache.Retrieve(uint256(3, uint224()), vecTx) == true);
    BOOST_CHECK(cache.Retrieve(uint256(6, uint224()), vecTx) == true);

    cache.AddNew(uint256(4, uint224()), vecTx);
    cache.AddNew(uint256(2, uint224()), vecTx);
    cache.AddNew(uint256(5, uint224()), vecTx);
    cache.AddNew(uint256(1, uint224()), vecTx);

    BOOST_CHECK(cache.Retrieve(uint256(1, uint224()), vecTx) == false);
    BOOST_CHECK(cache.Retrieve(uint256(2, uint224()), vecTx) == true);
    BOOST_CHECK(cache.Retrieve(uint256(6, uint224()), vecTx) == true);
    BOOST_CHECK(cache.Retrieve(uint256(4, uint224()), vecTx) == true);

    cache.Clear();
    vecTx.clear();

    cache.AddNew(uint256(125, uint224("1asfasf")), vecTx);
    cache.AddNew(uint256(125, uint224("awdaweawrawfasdadawd")), vecTx);
    cache.AddNew(uint256(126, uint224("126")), vecTx);
    BOOST_CHECK(cache.Retrieve(uint256(125, uint224("1asfasf")), vecTx) == true);
    BOOST_CHECK(cache.Retrieve(uint256(125, uint224("awdaweawrawfasdadawd")), vecTx) == true);

    cache.AddNew(uint256(130, uint224()), vecTx);
    cache.AddNew(uint256(120, uint224()), vecTx);
    cache.AddNew(uint256(110, uint224()), vecTx);
    cache.AddNew(uint256(110, uint224()), vecTx);
    cache.AddNew(uint256(115, uint224()), vecTx);

    BOOST_CHECK(cache.Retrieve(uint256(120, uint224()), vecTx) == false);
    BOOST_CHECK(cache.Retrieve(uint256(210, uint224()), vecTx) == false);
    BOOST_CHECK(cache.Retrieve(uint256(130, uint224()), vecTx) == true);
    BOOST_CHECK(cache.Retrieve(uint256(125, uint224()), vecTx) == false);
    BOOST_CHECK(cache.Retrieve(uint256(125, uint224("1asfasf")), vecTx) == false);
    BOOST_CHECK(cache.Retrieve(uint256(125, uint224("awdaweawrawfasdadawd")), vecTx) == false);
}


static uint64 GetSequenceNumber()
{
    static uint64 nLastSequenceNumber = 0;
    return ((++nLastSequenceNumber) << 24);
}

// BOOST_AUTO_TEST_CASE(seq_test)
// {
//     CTxPoolView view;

//     CPooledTx tx1;
//     tx1.nTimeStamp = 1;

//     CPooledTx tx2;
//     tx2.nTimeStamp = 2;
//     tx2.vInput.push_back(CTxIn(CTxOutPoint(tx1.GetHash(), 0)));

//     CPooledTx tx3;
//     tx3.nTimeStamp = 3;
//     tx3.vInput.push_back(CTxIn(CTxOutPoint(tx2.GetHash(), 0)));

//     tx3.nSequenceNumber = GetSequenceNumber();
//     tx1.nSequenceNumber = GetSequenceNumber();
//     tx2.nSequenceNumber = GetSequenceNumber();

//     BOOST_CHECK(view.AddNew(tx3.GetHash(), tx3));
//     BOOST_CHECK(view.AddNew(tx1.GetHash(), tx1));
//     BOOST_CHECK(view.AddNew(tx2.GetHash(), tx2));
// }


// tx1         tx6
//  |           |
// tx2    tx4  tx5   tx7
//  |      |    |     |
// tx3     --- tx8-----    tx9
//  |           |          |
//  |---------tx10---------|
BOOST_AUTO_TEST_CASE(txpoolview_test)
{
    CTxPoolView view;

    CPooledTx tx1;
    tx1.nTimeStamp = 1001;

    CPooledTx tx2;
    tx2.nTimeStamp = 1002;
    tx2.vInput.push_back(CTxIn(CTxOutPoint(tx1.GetHash(), 0)));

    CPooledTx tx3;
    tx3.nTimeStamp = 1003;
    tx3.vInput.push_back(CTxIn(CTxOutPoint(tx2.GetHash(), 0)));

    tx1.nSequenceNumber = GetSequenceNumber();
    tx2.nSequenceNumber = GetSequenceNumber();
    tx3.nSequenceNumber = GetSequenceNumber();

    BOOST_CHECK(view.AddNew(tx1.GetHash(), tx1));
    BOOST_CHECK(view.AddNew(tx2.GetHash(), tx2));
    BOOST_CHECK(view.AddNew(tx3.GetHash(), tx3));

    BOOST_CHECK(view.IsSpent(CTxOutPoint(tx1.GetHash(), 0)));
    BOOST_CHECK(view.IsSpent(CTxOutPoint(tx2.GetHash(), 0)));
    BOOST_CHECK(!view.IsSpent(CTxOutPoint(tx3.GetHash(), 0)));

    CTxPoolView involvedTxPoolView;
    view.InvalidateSpent(CTxOutPoint(tx1.GetHash(), 0), involvedTxPoolView);

    BOOST_CHECK(!view.IsSpent(CTxOutPoint(tx1.GetHash(), 0)));
    BOOST_CHECK(!view.IsSpent(CTxOutPoint(tx2.GetHash(), 0)));
    BOOST_CHECK(!view.IsSpent(CTxOutPoint(tx3.GetHash(), 0)));

    BOOST_CHECK(view.Exists(tx1.GetHash()));
    BOOST_CHECK(!view.Exists(tx2.GetHash()));
    BOOST_CHECK(!view.Exists(tx3.GetHash()));

    BOOST_CHECK(!involvedTxPoolView.Exists(tx1.GetHash()));
    BOOST_CHECK(involvedTxPoolView.Exists(tx2.GetHash()));
    BOOST_CHECK(involvedTxPoolView.Exists(tx3.GetHash()));
    BOOST_CHECK(involvedTxPoolView.IsSpent(CTxOutPoint(tx2.GetHash(), 0)));
    BOOST_CHECK(!involvedTxPoolView.IsSpent(CTxOutPoint(tx3.GetHash(), 0)));
}
BOOST_AUTO_TEST_SUITE_END()