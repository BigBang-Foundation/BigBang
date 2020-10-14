// Copyright (c) 2019-2020 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/filesystem/path.hpp>
#include <boost/test/unit_test.hpp>
#include <map>

#include "defi.h"
#include "forkcontext.h"
#include "param.h"
#include "profile.h"
#include "test_big.h"

using namespace std;
using namespace xengine;
using namespace bigbang;
using namespace storage;

BOOST_FIXTURE_TEST_SUITE(defi_tests, BasicUtfSetup)

BOOST_AUTO_TEST_CASE(common_profile)
{
    CProfile profile;
    profile.strName = "BBC Test";
    profile.strSymbol = "BBCA";
    profile.nVersion = 1;
    profile.nMinTxFee = 100;
    profile.nMintReward = 1000;
    profile.nAmount = 100000;

    std::vector<uint8> vchProfile;
    BOOST_CHECK(profile.Save(vchProfile));

    CProfile profileLoad;
    try
    {
        BOOST_CHECK(profileLoad.Load(vchProfile));
    }
    catch (const std::exception& e)
    {
        BOOST_FAIL(e.what());
    }

    BOOST_CHECK(profileLoad.strName == profile.strName);
    BOOST_CHECK(profileLoad.strSymbol == profile.strSymbol);
    BOOST_CHECK(profileLoad.nVersion == profile.nVersion);
    BOOST_CHECK(profileLoad.nMinTxFee == profile.nMinTxFee);
    BOOST_CHECK(profileLoad.nMintReward == profile.nMintReward);
    BOOST_CHECK(profileLoad.nAmount == profile.nAmount);

    CForkContext forkContextWrite(uint256(), uint256(), uint256(), profile);
    CBufStream ss;
    ss << forkContextWrite;
    CForkContext forkContextRead;
    ss >> forkContextRead;

    BOOST_CHECK(forkContextRead.GetProfile().strName == profile.strName);
    BOOST_CHECK(forkContextRead.GetProfile().strSymbol == profile.strSymbol);
    BOOST_CHECK(forkContextRead.GetProfile().nVersion == profile.nVersion);
    BOOST_CHECK(forkContextRead.GetProfile().nMinTxFee == profile.nMinTxFee);
    BOOST_CHECK(forkContextRead.GetProfile().nMintReward == profile.nMintReward);
    BOOST_CHECK(forkContextRead.GetProfile().nAmount == profile.nAmount);
}

BOOST_AUTO_TEST_CASE(defi_profile)
{
    CProfile profile;
    profile.strName = "BBC Test";
    profile.strSymbol = "BBCA";
    profile.nVersion = 1;
    profile.nMinTxFee = 100;
    profile.nMintReward = 1000;
    profile.nAmount = 100000;
    profile.nForkType = FORK_TYPE_DEFI;
    profile.defi.nMintHeight = -1;
    profile.defi.nMaxSupply = 5;
    profile.defi.nCoinbaseType = SPECIFIC_DEFI_COINBASE_TYPE;
    profile.defi.nDecayCycle = 10;
    profile.defi.nCoinbaseDecayPercent = 50;
    profile.defi.nInitCoinbasePercent = 15;
    profile.defi.nPromotionRewardPercent = 20;
    profile.defi.nRewardCycle = 25;
    profile.defi.nSupplyCycle = 55;
    profile.defi.nStakeMinToken = 100;
    profile.defi.nStakeRewardPercent = 30;
    profile.defi.mapPromotionTokenTimes.insert(std::make_pair(10, 11));
    profile.defi.mapPromotionTokenTimes.insert(std::make_pair(11, 12));
    profile.defi.mapCoinbasePercent.insert(std::make_pair(5, 10));
    profile.defi.mapCoinbasePercent.insert(std::make_pair(15, 11));

    std::vector<uint8> vchProfile;
    BOOST_CHECK(profile.Save(vchProfile));

    CProfile profileLoad;
    try
    {
        BOOST_CHECK(profileLoad.Load(vchProfile));
    }
    catch (const std::exception& e)
    {
        BOOST_FAIL(e.what());
    }

    BOOST_CHECK(profileLoad.strName == profile.strName);
    BOOST_CHECK(profileLoad.strSymbol == profile.strSymbol);
    BOOST_CHECK(profileLoad.nVersion == profile.nVersion);
    BOOST_CHECK(profileLoad.nMinTxFee == profile.nMinTxFee);
    BOOST_CHECK(profileLoad.nMintReward == profile.nMintReward);
    BOOST_CHECK(profileLoad.nAmount == profile.nAmount);

    BOOST_CHECK(profileLoad.nForkType == profile.nForkType);
    BOOST_CHECK(profileLoad.defi.nMintHeight == profile.defi.nMintHeight);
    BOOST_CHECK(profileLoad.defi.nMaxSupply == profile.defi.nMaxSupply);
    BOOST_CHECK(profileLoad.defi.nCoinbaseType == profile.defi.nCoinbaseType);
    BOOST_CHECK(profileLoad.defi.nDecayCycle == profile.defi.nDecayCycle);
    BOOST_CHECK(profileLoad.defi.nInitCoinbasePercent == profile.defi.nInitCoinbasePercent);
    BOOST_CHECK(profileLoad.defi.nPromotionRewardPercent == profile.defi.nPromotionRewardPercent);
    BOOST_CHECK(profileLoad.defi.nRewardCycle == profile.defi.nRewardCycle);
    BOOST_CHECK(profileLoad.defi.nSupplyCycle == profile.defi.nSupplyCycle);
    BOOST_CHECK(profileLoad.defi.nStakeMinToken == profile.defi.nStakeMinToken);
    BOOST_CHECK(profileLoad.defi.nStakeRewardPercent == profile.defi.nStakeRewardPercent);
    BOOST_CHECK(profileLoad.defi.mapPromotionTokenTimes.size() == profile.defi.mapPromotionTokenTimes.size());
    BOOST_CHECK(profileLoad.defi.mapCoinbasePercent.size() == profile.defi.mapCoinbasePercent.size());

    CForkContext forkContextWrite(uint256(), uint256(), uint256(), profile);
    CBufStream ss;
    ss << forkContextWrite;
    CForkContext forkContextRead;
    ss >> forkContextRead;

    BOOST_CHECK(forkContextRead.GetProfile().strName == profile.strName);
    BOOST_CHECK(forkContextRead.GetProfile().strSymbol == profile.strSymbol);
    BOOST_CHECK(forkContextRead.GetProfile().nVersion == profile.nVersion);
    BOOST_CHECK(forkContextRead.GetProfile().nMinTxFee == profile.nMinTxFee);
    BOOST_CHECK(forkContextRead.GetProfile().nMintReward == profile.nMintReward);
    BOOST_CHECK(forkContextRead.GetProfile().nAmount == profile.nAmount);

    BOOST_CHECK(forkContextRead.GetProfile().nForkType == profile.nForkType);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nMintHeight == profile.defi.nMintHeight);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nCoinbaseType == profile.defi.nCoinbaseType);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nDecayCycle == profile.defi.nDecayCycle);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nMaxSupply == profile.defi.nMaxSupply);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nInitCoinbasePercent == profile.defi.nInitCoinbasePercent);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nPromotionRewardPercent == profile.defi.nPromotionRewardPercent);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nRewardCycle == profile.defi.nRewardCycle);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nSupplyCycle == profile.defi.nSupplyCycle);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nStakeMinToken == profile.defi.nStakeMinToken);
    BOOST_CHECK(forkContextRead.GetProfile().defi.nStakeRewardPercent == profile.defi.nStakeRewardPercent);
    BOOST_CHECK(forkContextRead.GetProfile().defi.mapPromotionTokenTimes.size() == profile.defi.mapPromotionTokenTimes.size());
    BOOST_CHECK(forkContextRead.GetProfile().defi.mapCoinbasePercent.size() == profile.defi.mapCoinbasePercent.size());

    COldForkContext oldForkContextWrite(uint256(), uint256(), uint256(), profile);
    CBufStream ssFork;
    ssFork << oldForkContextWrite;
    CForkContext newForkContextRead;
    ssFork >> newForkContextRead;
    BOOST_CHECK(newForkContextRead.GetProfile().strName == profile.strName);
    BOOST_CHECK(newForkContextRead.GetProfile().strSymbol == profile.strSymbol);
    BOOST_CHECK(newForkContextRead.GetProfile().nVersion == profile.nVersion);
    BOOST_CHECK(newForkContextRead.GetProfile().nMinTxFee == profile.nMinTxFee);
    BOOST_CHECK(newForkContextRead.GetProfile().nMintReward == profile.nMintReward);
    BOOST_CHECK(newForkContextRead.GetProfile().nAmount == profile.nAmount);

    BOOST_CHECK(newForkContextRead.GetProfile().nForkType == FORK_TYPE_COMMON);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nMintHeight != profile.defi.nMintHeight);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nCoinbaseType != SPECIFIC_DEFI_COINBASE_TYPE);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nDecayCycle != profile.defi.nDecayCycle);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nMaxSupply != profile.defi.nMaxSupply);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nInitCoinbasePercent != profile.defi.nInitCoinbasePercent);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nPromotionRewardPercent != profile.defi.nPromotionRewardPercent);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nRewardCycle != profile.defi.nRewardCycle);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nSupplyCycle != profile.defi.nSupplyCycle);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nStakeMinToken != profile.defi.nStakeMinToken);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.nStakeRewardPercent != profile.defi.nStakeRewardPercent);
    BOOST_CHECK(newForkContextRead.GetProfile().defi.mapPromotionTokenTimes.size() != profile.defi.mapPromotionTokenTimes.size());
    BOOST_CHECK(newForkContextRead.GetProfile().defi.mapCoinbasePercent.size() != profile.defi.mapCoinbasePercent.size());
}

static void RandGeneretor256(uint8_t* p)
{
    for (int i = 0; i < 32; i++)
    {
        *p++ = rand();
    }
}

BOOST_AUTO_TEST_CASE(defi_relation_graph)
{
    {
        CAddress A("1w8ehkb2jc0qcn7wze3tv8enzzwmytn9b7n7gghwfa219rv1vhhd82n6h");
        CAddress A1("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm");

        std::map<CDestination, CAddrInfo> mapAddressTree{
            { A1, CAddrInfo(CDestination(), A) }
        };

        CDeFiRelationGraph defiGraph;
        for (auto& x : mapAddressTree)
        {
            BOOST_CHECK(defiGraph.Insert(x.first, x.second.destParent, x.second.destParent));
        }
    }

    {
        CAddress A("1w8ehkb2jc0qcn7wze3tv8enzzwmytn9b7n7gghwfa219rv1vhhd82n6h");
        CAddress A1("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm");
        CAddress A2("1q71vfagprv5hqwckzbvhep0d0ct72j5j2heak2sgp4vptrtc2btdje3q");
        CAddress A3("1gbma6s21t4bcwymqz6h1dn1t7qy45019b1t00ywfyqymbvp90mqc1wmq");

        std::map<CDestination, CAddrInfo> mapAddressTree;
        mapAddressTree.insert(std::make_pair(A1, CAddrInfo(CDestination(), A)));
        mapAddressTree.insert(std::make_pair(A2, CAddrInfo(CDestination(), A)));
        mapAddressTree.insert(std::make_pair(A3, CAddrInfo(CDestination(), A)));

        CDeFiRelationGraph defiGraph;
        for (auto& x : mapAddressTree)
        {
            BOOST_CHECK(defiGraph.Insert(x.first, x.second.destParent, x.second.destParent));
        }
        BOOST_CHECK(defiGraph.mapRoot.size() == 1);
    }

    {
        CAddress A("1w8ehkb2jc0qcn7wze3tv8enzzwmytn9b7n7gghwfa219rv1vhhd82n6h");
        CAddress A1("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm");
        CAddress A2("1q71vfagprv5hqwckzbvhep0d0ct72j5j2heak2sgp4vptrtc2btdje3q");
        CAddress A3("1gbma6s21t4bcwymqz6h1dn1t7qy45019b1t00ywfyqymbvp90mqc1wmq");
        CAddress AA11("1dq62d8y4fz20sfg63zzy4h4ayksswv1fgqjzvegde306bxxg5zygc27q");
        CAddress AA21("1awxt9zsbtjjxx4bk3q2j18s25kj00cajx3rj1bwg8beep7awmx1pkb8p");
        CAddress AA22("1t877w7b61wsx1rabkd69dbn2kgybpj4ayw2eycezg8qkyfekn97hrmgy");
        CAddress AAA111("18f2dv1vc6nv2xj7ak0e0yye4tx77205f5j73ep2a7a5w6szhjexkd5mj");
        CAddress AAA221("1yy76yav5mnah0jzew049a6gp5bs2ns67xzfvcengjkpqyymfb4n6vrda");
        CAddress AAA222("1g03a0775sbarkrazjrs7qymdepbkn3brn7375p7ysf0tnrcx408pj03n");

        std::map<CDestination, CAddrInfo> mapAddressTree;
        mapAddressTree.insert(std::make_pair(A1, CAddrInfo(CDestination(), A)));
        mapAddressTree.insert(std::make_pair(A2, CAddrInfo(CDestination(), A)));
        mapAddressTree.insert(std::make_pair(A3, CAddrInfo(CDestination(), A)));
        mapAddressTree.insert(std::make_pair(AA11, CAddrInfo(CDestination(), A1)));
        mapAddressTree.insert(std::make_pair(AAA111, CAddrInfo(CDestination(), AA11)));
        mapAddressTree.insert(std::make_pair(AA21, CAddrInfo(CDestination(), A2)));
        mapAddressTree.insert(std::make_pair(AA22, CAddrInfo(CDestination(), A2)));
        mapAddressTree.insert(std::make_pair(AAA221, CAddrInfo(CDestination(), AA22)));
        mapAddressTree.insert(std::make_pair(AAA222, CAddrInfo(CDestination(), AA22)));

        CDeFiRelationGraph defiGraph;
        for (auto& x : mapAddressTree)
        {
            BOOST_CHECK(defiGraph.Insert(x.first, x.second.destParent, x.second.destParent));
        }
        BOOST_CHECK(defiGraph.mapRoot.size() == 1);
        BOOST_CHECK(defiGraph.mapRoot.find(A) != defiGraph.mapRoot.end());
    }

    {
        CAddress A("1w8ehkb2jc0qcn7wze3tv8enzzwmytn9b7n7gghwfa219rv1vhhd82n6h");
        CAddress A1("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm");
        CAddress A2("1q71vfagprv5hqwckzbvhep0d0ct72j5j2heak2sgp4vptrtc2btdje3q");
        CAddress A3("1gbma6s21t4bcwymqz6h1dn1t7qy45019b1t00ywfyqymbvp90mqc1wmq");
        CAddress AA11("1dq62d8y4fz20sfg63zzy4h4ayksswv1fgqjzvegde306bxxg5zygc27q");
        CAddress AA21("1awxt9zsbtjjxx4bk3q2j18s25kj00cajx3rj1bwg8beep7awmx1pkb8p");
        CAddress AA22("1t877w7b61wsx1rabkd69dbn2kgybpj4ayw2eycezg8qkyfekn97hrmgy");
        CAddress AAA111("18f2dv1vc6nv2xj7ak0e0yye4tx77205f5j73ep2a7a5w6szhjexkd5mj");
        CAddress AAA221("1yy76yav5mnah0jzew049a6gp5bs2ns67xzfvcengjkpqyymfb4n6vrda");
        CAddress AAA222("1g03a0775sbarkrazjrs7qymdepbkn3brn7375p7ysf0tnrcx408pj03n");

        CAddress B("1dt714q0p5143qhekgg0dx9qwnk6ww13f5v27xh6tpfmps25387ga2w5b");
        CAddress B1("1n1c0g6krvcvxhtgebptvz34rdq7qz2dcs6ngrphpnav465fdcpsmmbxj");
        CAddress B2("1m73jrn8np6ny50g3xr461yys6x3rme4yf1t7t9xa464v6n6p84ppzxa2");
        CAddress B3("1q284qfnpasxmkytpv5snda5ptqbpjxa9ryp2re0j1527qncmg38z7ar1");
        CAddress B4("134btp09511w3bnr1qq4de6btdkxkbp2y5x3zmr09g0m9hfn9frsa1k2f");

        std::map<CDestination, CAddrInfo> mapAddressTree;
        mapAddressTree.insert(std::make_pair(A1, CAddrInfo(CDestination(), A)));
        mapAddressTree.insert(std::make_pair(A2, CAddrInfo(CDestination(), A)));
        mapAddressTree.insert(std::make_pair(A3, CAddrInfo(CDestination(), A)));
        mapAddressTree.insert(std::make_pair(AA11, CAddrInfo(CDestination(), A1)));
        mapAddressTree.insert(std::make_pair(AAA111, CAddrInfo(CDestination(), AA11)));
        mapAddressTree.insert(std::make_pair(AA21, CAddrInfo(CDestination(), A2)));
        mapAddressTree.insert(std::make_pair(AA22, CAddrInfo(CDestination(), A2)));
        mapAddressTree.insert(std::make_pair(AAA221, CAddrInfo(CDestination(), AA22)));
        mapAddressTree.insert(std::make_pair(AAA222, CAddrInfo(CDestination(), AA22)));
        mapAddressTree.insert(std::make_pair(B1, CAddrInfo(CDestination(), B)));
        mapAddressTree.insert(std::make_pair(B2, CAddrInfo(CDestination(), B)));
        mapAddressTree.insert(std::make_pair(B3, CAddrInfo(CDestination(), B)));
        mapAddressTree.insert(std::make_pair(B4, CAddrInfo(CDestination(), B)));

        CDeFiRelationGraph defiGraph;
        for (auto& x : mapAddressTree)
        {
            BOOST_CHECK(defiGraph.Insert(x.first, x.second.destParent, x.second.destParent));
        }
        BOOST_CHECK(defiGraph.mapRoot.size() == 2);
        BOOST_CHECK(defiGraph.mapNode.size() == 15);
        BOOST_CHECK(defiGraph.mapRoot.find(A) != defiGraph.mapRoot.end());
        BOOST_CHECK(defiGraph.mapRoot.find(B) != defiGraph.mapRoot.end());
        BOOST_CHECK(defiGraph.mapNode.find(A) != defiGraph.mapNode.end());
        BOOST_CHECK(defiGraph.mapNode.find(B) != defiGraph.mapNode.end());
        BOOST_CHECK(defiGraph.mapRoot.find(B3) == defiGraph.mapRoot.end());
        BOOST_CHECK(defiGraph.mapRoot.find(AA22) == defiGraph.mapRoot.end());
    }
}

BOOST_AUTO_TEST_CASE(reward)
{
    // STD_DEBUG = true;
    // boost::filesystem::path logPath = boost::filesystem::absolute(boost::unit_test::framework::master_test_suite().argv[0]).parent_path();
    // InitLog(logPath, true, true, 1024, 1024);

    CDeFiForkReward r;
    uint256 forkid1;
    RandGeneretor256(forkid1.begin());
    uint256 forkid2;
    RandGeneretor256(forkid2.begin());

    // test ExistFork and AddFork
    BOOST_CHECK(!r.ExistFork(forkid1));

    CProfile profile1;
    profile1.strName = "BBC Test1";
    profile1.strSymbol = "BBCA";
    profile1.nVersion = 1;
    profile1.nMinTxFee = NEW_MIN_TX_FEE;
    profile1.nMintReward = 0;
    profile1.nAmount = 21000000 * COIN;
    profile1.nJointHeight = 150;
    profile1.nForkType = FORK_TYPE_DEFI;
    profile1.defi.nMintHeight = -1;
    profile1.defi.nMaxSupply = 2100000000 * COIN;
    profile1.defi.nCoinbaseType = FIXED_DEFI_COINBASE_TYPE;
    profile1.defi.nDecayCycle = 1036800;
    profile1.defi.nCoinbaseDecayPercent = 50;
    profile1.defi.nInitCoinbasePercent = 10;
    profile1.defi.nPromotionRewardPercent = 50;
    profile1.defi.nRewardCycle = 1440;
    profile1.defi.nSupplyCycle = 43200;
    profile1.defi.nStakeMinToken = 100 * COIN;
    profile1.defi.nStakeRewardPercent = 50;
    profile1.defi.mapPromotionTokenTimes.insert(std::make_pair(10000, 10));
    r.AddFork(forkid1, profile1);

    CProfile profile2 = profile1;
    profile2.strName = "BBC Test2";
    profile2.strSymbol = "BBCB";
    profile2.nVersion = 1;
    profile2.nMinTxFee = NEW_MIN_TX_FEE;
    profile2.nMintReward = 0;
    profile2.nAmount = 10000000 * COIN;
    profile2.nJointHeight = 150;
    profile2.nForkType = FORK_TYPE_DEFI;
    profile2.defi.nMintHeight = 1500;
    profile2.defi.nMaxSupply = 1000000000 * COIN;
    profile2.defi.nCoinbaseType = SPECIFIC_DEFI_COINBASE_TYPE;
    profile2.defi.mapCoinbasePercent = { { 259200, 10 }, { 777600, 8 }, { 1814400, 5 }, { 3369600, 3 }, { 5184000, 2 } };
    profile2.defi.nRewardCycle = 1440;
    profile2.defi.nSupplyCycle = 43200;
    profile2.defi.nStakeMinToken = 100 * COIN;
    profile2.defi.nStakeRewardPercent = 50;
    profile2.defi.mapPromotionTokenTimes.insert(std::make_pair(10000, 10));
    r.AddFork(forkid2, profile2);

    BOOST_CHECK(r.ExistFork(forkid1));
    BOOST_CHECK(r.GetForkProfile(forkid1).strSymbol == "BBCA");

    // supply = 21000000000000
    // for (i = 0; i < (1036000 / 43200); i++ ) supply *= 1.1
    // for (i = 0; i < (1036000 / 43200); i++ ) supply *= 1.05
    // for (i = 0; i < (1036000 / 43200); i++ ) supply *= 1.025
    // for (i = 0; i < (1036000 / 43200); i++ ) supply *= 1.0125
    // for (i = 0; i < (1036000 / 43200); i++ ) supply *= 1.00625
    // for (i = 0; i < (1036000 / 43200); i++ ) supply *= 1.003125
    // for (i = 0; i < 20; i++ ) supply *= 1.0015625
    // supply = 2099250670895780, height = 164 * 43200 = 7084800
    // coinbase = 2099250670895780 * 1.0015625 / 43200 = 75927758.64061704
    // supply = max = 2100000000000000, height = 7084800 + ceil((max - supply) / coinbase) + 151(mint_height - 1) = 7094820
    BOOST_CHECK(r.GetForkMaxRewardHeight(forkid1) == 7094820);
    // supply = 10000000000000
    // for (i = 0; i < (259200 / 43200); i++ ) supply *= 1.1
    // for (i = 0; i < ((777600 - 259200) / 43200); i++ ) supply *= 1.08
    // for (i = 0; i < ((1814400 - 777600) / 43200); i++ ) supply *= 1.05
    // for (i = 0; i < ((3369600 - 3369600) / 43200); i++ ) supply *= 1.03
    // for (i = 0; i < ((5184000 - 3369600) / 43200); i++ ) supply *= 1.02
    // max = 1000000000000000, supply = 957925331297192, supply < max, height = 518400 + 1499(mint_height - 1) = 5185499
    BOOST_CHECK(r.GetForkMaxRewardHeight(forkid2) == 5185499);

    // test common reward
    BOOST_CHECK(r.GetFixedDecayReward(profile1, 152, 1592) == 70000000000);
    BOOST_CHECK(r.GetFixedDecayReward(profile1, 152, 1036952) == 185844386191952);
    BOOST_CHECK(r.GetFixedDecayReward(profile1, 1036952, 1036953) == 239403225);
    BOOST_CHECK(r.GetFixedDecayReward(profile1, 152, 1036953) == 185844625595177);
    BOOST_CHECK(r.GetFixedDecayReward(profile1, 7094819, 7094820) == 75927759);
    BOOST_CHECK(r.GetFixedDecayReward(profile1, 7094820, 7094821) == 73981955);

    BOOST_CHECK(r.GetSpecificDecayReward(profile2, 1500, 2940) == 33333333333);
    BOOST_CHECK(r.GetSpecificDecayReward(profile2, 1500, 260700) == 7715610000000);
    BOOST_CHECK(r.GetSpecificDecayReward(profile2, 260700, 260701) == 32806685);
    BOOST_CHECK(r.GetSpecificDecayReward(profile2, 1500, 260701) == 7715642806685);
    BOOST_CHECK(r.GetSpecificDecayReward(profile2, 1500, 5185500) == 947925331297192);
    BOOST_CHECK(r.GetSpecificDecayReward(profile2, 5185500, 5185501) == 0);

    // test PrevRewardHeight
    BOOST_CHECK(r.PrevRewardHeight(forkid1, -10) == -1);
    BOOST_CHECK(r.PrevRewardHeight(forkid1, 0) == -1);
    BOOST_CHECK(r.PrevRewardHeight(forkid1, 151) == -1);
    BOOST_CHECK(r.PrevRewardHeight(forkid1, 152) == 151);
    BOOST_CHECK(r.PrevRewardHeight(forkid1, 1591) == 151);
    BOOST_CHECK(r.PrevRewardHeight(forkid1, 1592) == 1591);
    BOOST_CHECK(r.PrevRewardHeight(forkid1, 100000) == 99511);
    BOOST_CHECK(r.PrevRewardHeight(forkid1, 10000000) == 9999511);

    // test coinbase
    // fixed coinbase
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(0, uint224(0))) == 0);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(151, uint224(0))) == 0);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(152, uint224(0))) == 48611111);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(1591, uint224(0))) == 70000000000);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(43352, uint224(0))) == 53472222);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(100000, uint224(0))) == 28762708333);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(7086391, uint224(0))) == 109335972442);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(7095031, uint224(0))) == 93313269565);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(7095032, uint224(0))) == 0);
    BOOST_CHECK(r.GetSectionReward(forkid1, uint256(10000000, uint224(0))) == 0);
    int64 nReward = r.GetSectionReward(forkid1, uint256(100000, uint224(0)));

    // specific coinbase
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(0, uint224(0))) == 0);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(1499, uint224(0))) == 0);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(1500, uint224(0))) == 23148148);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(2939, uint224(0))) == 33333333333);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(44700, uint224(0))) == 25462963);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(260700, uint224(0))) == 32806685);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(1001348, uint224(0))) == 32224247818);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(2001348, uint224(0))) == 126959353756);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(4001348, uint224(0))) == 246829392556);
    BOOST_CHECK(r.GetSectionReward(forkid2, uint256(10001348, uint224(0))) == 0);

    CAddress A("1632srrskscs1d809y3x5ttf50f0gabf86xjz2s6aetc9h9ewwhm58dj3");
    CAddress a1("1f1nj5gjgrcz45g317s1y4tk18bbm89jdtzd41m9s0t14tp2ngkz4cg0x");
    CAddress a11("1pmj5p47zhqepwa9vfezkecxkerckhrks31pan5fh24vs78s6cbkrqnxp");
    CAddress a111("1bvaag2t23ybjmasvjyxnzetja0awe5d1pyw361ea3jmkfdqt5greqvfq");
    CAddress a2("1ab1sjh07cz7xpb0xdkpwykfm2v91cvf2j1fza0gj07d2jktdnrwtyd57");
    CAddress a21("1782a5jv06egd6pb2gjgp2p664tgej6n4gmj79e1hbvgfgy3t006wvwzt");
    CAddress a22("1c7s095dcvzdsedrkpj6y5kjysv5sz3083xkahvyk7ry3tag4ddyydbv4");
    CAddress a221("1ytysehvcj13ka9r1qhh9gken1evjdp9cn00cz0bhqjqgzwc6sdmse548");
    CAddress a222("16aaahq32cncamxbmvedjy5jqccc2hcpk7rc0h2zqcmmrnm1g2213t2k3");
    CAddress a3("1vz7k0748t840bg3wgem4mhf9pyvptf1z2zqht6bc2g9yn6cmke8h4dwe");
    CAddress B("1fpt2z9nyh0a5999zrmabg6ppsbx78wypqapm29fsasx993z11crp6zm7");
    CAddress b1("1rampdvtmzmxfzr3crbzyz265hbr9a8y4660zgpbw6r7qt9hdy535zed7");
    CAddress b2("1w0k188jwq5aenm6sfj6fdx9f3d96k20k71612ddz81qrx6syr4bnp5m9");
    CAddress b3("196wx05mee1zavws828vfcap72tebtskw094tp5sztymcy30y7n9varfa");
    CAddress b4("19k8zjwdntjp8avk41c8aek0jxrs1fgyad5q9f1gd1q2fdd0hafmm549d");
    CAddress C("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm");

    // test stake reward
    // B = 1/1
    map<CDestination, int64> balance;
    balance = map<CDestination, int64>{
        { A, 0 },
        { B, 100 * COIN },
    };
    {
        CDeFiRewardSet reward = r.ComputeStakeReward(profile1.defi.nStakeMinToken, nReward, balance);
        BOOST_CHECK(reward.size() == 1);
        auto it = reward.begin();
        BOOST_CHECK(it->dest == B && it->nReward == nReward);
    }

    // a1 = 1/5, a11 = 3/5, a111 = 1/5
    balance = map<CDestination, int64>{
        { A, 0 },
        { a1, 100 * COIN },
        { a11, 1000 * COIN },
        { a111, 100 * COIN },
    };
    {
        CDeFiRewardSet reward = r.ComputeStakeReward(profile1.defi.nStakeMinToken, nReward, balance);
        BOOST_CHECK(reward.size() == 3);
        auto& destIdx = reward.get<0>();
        auto it = destIdx.find(a1);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 5752541666);
        it = destIdx.find(a11);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 17257624999);
        it = destIdx.find(a111);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 5752541666);
    }

    // test promotion reward
    balance = map<CDestination, int64>{
        { A, 10000 * COIN },
        { a1, 100000 * COIN },
        { a11, 100000 * COIN },
        { a111, 100000 * COIN },
        { a2, 1 * COIN },
        { a21, 1 * COIN },
        { a22, 12000 * COIN },
        { a221, 18000 * COIN },
        { a222, 5000 * COIN },
        { a3, 1000000 * COIN },
        { B, 10000 * COIN },
        { b1, 10000 * COIN },
        { b2, 11000 * COIN },
        { b3, 5000 * COIN },
        { b4, 50000 * COIN },
        { C, 19568998 * COIN },
    };

    map<CDestination, CAddrInfo> mapAddress;
    mapAddress = map<CDestination, CAddrInfo>{
        { a1, CAddrInfo(A, A) },
        { a11, CAddrInfo(A, a1) },
        { a111, CAddrInfo(A, a11) },
        { a2, CAddrInfo(A, A) },
        { a21, CAddrInfo(A, a2) },
        { a22, CAddrInfo(A, a2) },
        { a221, CAddrInfo(A, a22) },
        { a222, CAddrInfo(A, a22) },
        { a3, CAddrInfo(A, A) },
        { b1, CAddrInfo(B, B) },
        { b2, CAddrInfo(B, B) },
        { b3, CAddrInfo(B, B) },
        { b4, CAddrInfo(B, B) },
    };

    CDeFiRelationGraph relation;
    for (auto& x : mapAddress)
    {
        BOOST_CHECK(relation.Insert(x.first, x.second.destParent, x.second.destParent));
    }
    {
        CDeFiRewardSet reward = r.ComputePromotionReward(nReward, balance, profile1.defi.mapPromotionTokenTimes, relation);
        BOOST_CHECK(reward.size() == 6);

        auto& destIdx = reward.get<0>();
        auto it = destIdx.find(A);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 18149590582);
        it = destIdx.find(a1);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 2043626);
        it = destIdx.find(a11);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 1620807);
        it = destIdx.find(a2);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 1515102);
        it = destIdx.find(a22);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 1762663353);
        it = destIdx.find(B);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 8845274860);
    }

    // boost::filesystem::remove_all(logPath);
}

BOOST_AUTO_TEST_CASE(reward2)
{
    CDeFiForkReward r;
    uint256 forkid;
    RandGeneretor256(forkid.begin());

    // test ExistFork and AddFork
    BOOST_CHECK(!r.ExistFork(forkid));

    CProfile profile;
    profile.strName = "BBC Test2";
    profile.strSymbol = "BBCB";
    profile.nVersion = 1;
    profile.nMinTxFee = NEW_MIN_TX_FEE;
    profile.nMintReward = 0;
    profile.nAmount = 10000000 * COIN; // 首期发行一千万母币
    profile.nJointHeight = 15;
    profile.nForkType = FORK_TYPE_DEFI;
    profile.defi.nMintHeight = 20;
    profile.defi.nMaxSupply = 1000000000 * COIN; // BTCA 总共发行十亿枚
    profile.defi.nCoinbaseType = SPECIFIC_DEFI_COINBASE_TYPE;
    profile.defi.mapCoinbasePercent = { { 259200, 10 }, { 777600, 8 }, { 1814400, 5 }, { 3369600, 3 }, { 5184000, 2 } }; // 发行阶段，半年，1年（用高度表示），参考BTCA白皮书，月增长原有基数的10%，8%
    profile.defi.nRewardCycle = 5;                                                                                       // every 5 height once reward
    profile.defi.nSupplyCycle = 150;                                                                                     // every 150  once supply
    profile.defi.nStakeMinToken = 100 * COIN;                                                                            // min token required, >= 100, can be required to join this defi game
    profile.defi.nStakeRewardPercent = 50;                                                                               // 50% of supply amount per day
    profile.defi.mapPromotionTokenTimes.insert(std::make_pair(10000, 10));                                               // 用于推广收益，小于等于10000的部分，要放大10倍
    r.AddFork(forkid, profile);

    BOOST_CHECK(r.ExistFork(forkid));
    BOOST_CHECK(r.GetForkProfile(forkid).strSymbol == "BBCB");

    int64 nReward = r.GetSectionReward(forkid, uint256(24, uint224(0)));

    CAddress A("1632srrskscs1d809y3x5ttf50f0gabf86xjz2s6aetc9h9ewwhm58dj3");
    CAddress a1("1f1nj5gjgrcz45g317s1y4tk18bbm89jdtzd41m9s0t14tp2ngkz4cg0x");
    CAddress a11("1pmj5p47zhqepwa9vfezkecxkerckhrks31pan5fh24vs78s6cbkrqnxp");
    CAddress a111("1bvaag2t23ybjmasvjyxnzetja0awe5d1pyw361ea3jmkfdqt5greqvfq");
    CAddress a2("1ab1sjh07cz7xpb0xdkpwykfm2v91cvf2j1fza0gj07d2jktdnrwtyd57");
    CAddress a21("1782a5jv06egd6pb2gjgp2p664tgej6n4gmj79e1hbvgfgy3t006wvwzt");
    CAddress a22("1c7s095dcvzdsedrkpj6y5kjysv5sz3083xkahvyk7ry3tag4ddyydbv4");
    CAddress a221("1ytysehvcj13ka9r1qhh9gken1evjdp9cn00cz0bhqjqgzwc6sdmse548");
    CAddress a222("16aaahq32cncamxbmvedjy5jqccc2hcpk7rc0h2zqcmmrnm1g2213t2k3");
    CAddress a3("1vz7k0748t840bg3wgem4mhf9pyvptf1z2zqht6bc2g9yn6cmke8h4dwe");
    CAddress B("1fpt2z9nyh0a5999zrmabg6ppsbx78wypqapm29fsasx993z11crp6zm7");
    CAddress b1("1rampdvtmzmxfzr3crbzyz265hbr9a8y4660zgpbw6r7qt9hdy535zed7");
    CAddress b2("1w0k188jwq5aenm6sfj6fdx9f3d96k20k71612ddz81qrx6syr4bnp5m9");
    CAddress b3("196wx05mee1zavws828vfcap72tebtskw094tp5sztymcy30y7n9varfa");
    CAddress b4("19k8zjwdntjp8avk41c8aek0jxrs1fgyad5q9f1gd1q2fdd0hafmm549d");
    CAddress C("1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm");

    // test stake reward
    // B = 1/1
    map<CDestination, int64> balance;
    balance = map<CDestination, int64>{
        { A, 0 },
        { B, 100 * COIN },
    };
    std::cout << "nReward " << nReward << std::endl;
    {
        CDeFiRewardSet reward = r.ComputeStakeReward(profile.defi.nStakeMinToken, (nReward), balance);
        BOOST_CHECK(reward.size() == 1);
        auto it = reward.begin();

        // B的持币量排名 1
        // 各个地址的排名相加 1
        // nReward = 925925925
        // 1 / 1 * nReward * 50%
        BOOST_CHECK(it->dest == B && it->nReward == (nReward));
    }

    balance = map<CDestination, int64>{
        { A, 0 },
        { a1, 100 * COIN },   //  rank 1
        { a11, 1000 * COIN }, // rank 5
        { a111, 100 * COIN }, // rank 1
        { a221, 105 * COIN }, // rank 4
        { a222, 100 * COIN }, // rank 1
    };
    {
        CDeFiRewardSet reward = r.ComputeStakeReward(profile.defi.nStakeMinToken, nReward, balance);
        BOOST_CHECK(reward.size() == 5);
        auto& destIdx = reward.get<0>();
        auto it = destIdx.find(a1);
        // 1 / 12 * nReward
        BOOST_CHECK(it != destIdx.end() && it->nReward == (2777777777));
        std::cout << "a1 " << it->nReward << std::endl;
        it = destIdx.find(a11);
        // 5 / 12 * nReward
        BOOST_CHECK(it != destIdx.end() && it->nReward == (13888888888));
        it = destIdx.find(a111);
        // 1 / 12 * nReward
        BOOST_CHECK(it != destIdx.end() && it->nReward == (2777777777));
        it = destIdx.find(a221);
        // 4 / 12 * nReward
        BOOST_CHECK(it != destIdx.end() && it->nReward == (11111111111));

        it = destIdx.find(a222);
        // 1 / 12 * nReward
        BOOST_CHECK(it != destIdx.end() && it->nReward == (2777777777));
    }

    // test promotion reward
    balance = map<CDestination, int64>{
        { A, 10000 * COIN },
        { a1, 100000 * COIN },
        { a11, 100000 * COIN },
        { a111, 100000 * COIN },
        { a2, 1 * COIN },
        { a21, 1 * COIN },
        { a22, 12000 * COIN },
        { a221, 18000 * COIN },
        { a222, 5000 * COIN },
        { a3, 1000000 * COIN },
        { B, 10000 * COIN },
        { b1, 10000 * COIN },
        { b2, 11000 * COIN },
        { b3, 5000 * COIN },
        { b4, 50000 * COIN },
        { C, 19568998 * COIN },
    };

    {
        CDeFiRewardSet reward = r.ComputeStakeReward(profile.defi.nStakeMinToken, (nReward), balance);
        BOOST_CHECK(reward.size() == 14);
        auto& destIdx = reward.get<0>();

        // 3 / 98 * nReward
        auto it = destIdx.find(A);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (1020408163));

        // 10 / 98 * nReward
        it = destIdx.find(a1);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (3401360544));

        // 10 / 98 * nReward
        it = destIdx.find(a11);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (3401360544));

        // 10 / 98 * nReward
        it = destIdx.find(a111);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (3401360544));

        // 7 / 98 * nReward
        it = destIdx.find(a22);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (2380952380));

        // 8 / 98 * nReward
        it = destIdx.find(a221);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (2721088435));

        // 1 / 98 * nReward
        it = destIdx.find(a222);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (340136054));

        // 13 / 98 * nReward
        it = destIdx.find(a3);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (4421768707));

        // 3 / 98 * nReward
        it = destIdx.find(B);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (1020408163));

        // 3 / 98 * nReward
        it = destIdx.find(b1);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (1020408163));

        // 6 / 98 * nReward
        it = destIdx.find(b2);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (2040816326));

        // 1 / 98 * nReward
        it = destIdx.find(b3);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (340136054));

        // 9 / 98 * nReward
        it = destIdx.find(b4);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (3061224489));

        // 14 / 98 * nReward
        it = destIdx.find(C);
        BOOST_CHECK(it != destIdx.end() && it->nReward == (4761904761));
    }

    map<CDestination, CAddrInfo> mapAddress;
    mapAddress = map<CDestination, CAddrInfo>{
        { a1, CAddrInfo(A, A) },
        { a11, CAddrInfo(A, a1) },
        { a111, CAddrInfo(A, a11) },
        { a2, CAddrInfo(A, A) },
        { a21, CAddrInfo(A, a2) },
        { a22, CAddrInfo(A, a2) },
        { a221, CAddrInfo(A, a22) },
        { a222, CAddrInfo(A, a22) },
        { a3, CAddrInfo(A, A) },
        { b1, CAddrInfo(B, B) },
        { b2, CAddrInfo(B, B) },
        { b3, CAddrInfo(B, B) },
        { b4, CAddrInfo(B, B) },
    };

    CDeFiRelationGraph relation;
    for (auto& x : mapAddress)
    {
        BOOST_CHECK(relation.Insert(x.first, x.second.destParent, x.second.destParent));
    }
    {
        CDeFiRewardSet reward = r.ComputePromotionReward(nReward, balance, profile.defi.mapPromotionTokenTimes, relation);
        BOOST_CHECK(reward.size() == 6);
        auto& destIdx = reward.get<0>();

        // 515102 / 816312 * nReward
        auto it = destIdx.find(A);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 21033706066);

        // 58 / 816312 * nReward
        it = destIdx.find(a1);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 2368375);

        // 46 / 816312 * nReward
        it = destIdx.find(a11);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 1878366);

        // 43 / 816312 * nReward
        it = destIdx.find(a2);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 1755864);

        // 50026 / 816312 * nReward
        it = destIdx.find(a22);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 2042764694);

        // 251037 / 816312 * nReward
        it = destIdx.find(B);
        BOOST_CHECK(it != destIdx.end() && it->nReward == 10250859965);
    }
}

// test second defi reward supply. because reward1, reward2 just change param of fork and test first defi reward
BOOST_AUTO_TEST_CASE(reward3)
{
    CDeFiForkReward r;
    uint256 forkid;
    RandGeneretor256(forkid.begin());

    // test ExistFork and AddFork
    BOOST_CHECK(!r.ExistFork(forkid));

    CProfile profile;
    profile.strName = "BBC Test3";
    profile.strSymbol = "BBCC";
    profile.nVersion = 1;
    profile.nMinTxFee = NEW_MIN_TX_FEE;
    profile.nMintReward = 0;
    profile.nAmount = 20000000 * COIN; // 首期发行二千万母币
    profile.nJointHeight = 15;
    profile.nForkType = FORK_TYPE_DEFI;
    profile.defi.nMintHeight = 20;
    profile.defi.nMaxSupply = 1000000000 * COIN; // BTCA 总共发行十亿枚
    profile.defi.nCoinbaseType = FIXED_DEFI_COINBASE_TYPE;
    profile.defi.nRewardCycle = 5;        // 1440 = 60 * 24  every N height once reward
    profile.defi.nSupplyCycle = 150;      // 43200 = 60 * 24 * 30 every N height once supply
    profile.defi.nStakeMinToken = 100 * COIN;                                                                            // min token required, >= 100, can be required to join this defi game
    profile.defi.nStakeRewardPercent = 50;                                                                               // 50% of supply amount per day
    profile.defi.mapPromotionTokenTimes.insert(std::make_pair(10000, 10));                                               // 用于推广收益，小于等于10000的部分，要放大10倍
    r.AddFork(forkid, profile);

    BOOST_CHECK(r.ExistFork(forkid));
    BOOST_CHECK(r.GetForkProfile(forkid).strSymbol == "BBCC");



}

BOOST_AUTO_TEST_SUITE_END()
