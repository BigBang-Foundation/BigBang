// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "defs.h"
#include "uint256.h"
#include "util.h"
#include "crypto.h"

#include "test_big.h"

#include <boost/test/unit_test.hpp>

#include <map>
#include <string>

using namespace xengine;
using namespace bigbang::crypto;

BOOST_FIXTURE_TEST_SUITE(slowhash_tests, BasicUtfSetup)

BOOST_AUTO_TEST_CASE(slowhash)
{
#if !defined NO_AES && (defined(__x86_64__) || (defined(_MSC_VER) && defined(_WIN64)))
    //x86/x64 with optimised sse2 instructions
    BOOST_TEST_MESSAGE("Hashing with sse2 native instructions running on X86");

#elif !defined NO_AES && (defined(__arm__) || defined(__aarch64__))
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
    //arm64 with optimised neon instructions
    BOOST_TEST_MESSAGE("Hashing with neon native instructions running on ARM64 WITH CRYPTO FEATURE");

    #else
    //arm64 without optimised neon instructions
    BOOST_TEST_MESSAGE("Hashing without neon native instructions running on ARM64 WITHOUT CRYPTO FEATURE");

    #endif
#else
    //fallback implementation with any optimization
    BOOST_TEST_MESSAGE("Hashing with FALLBACK IMPLEMENTATION");

#endif

    std::map<uint32, std::pair<std::string, std::string> > test_table = // height - proof - hash
    {
        {1, {"01000100eb40e15d701af4705c5e6fcb04efc3ca3c851c1e4d8948e10923025f54bea9b0000000004c0000000000000000000000000000000000000000000000000000000000000000000120020400c2ff12c03c315e3160659febc87ed19d705ef3a8815292604cb34873d81a12acaa922d125b4c",
                        "000000009839d734328e7c3656bf68105f08400691d6ede6eb05e67c329b44e8"}},

        {HEIGHT_HASH_MULTI_SIGNER - 1 ,{"01000100506e255e7a446c625a2d888ed987d0c20787f7dae028678a9bef9c681a7477eaae3101004c0000000000000000000000000000000000000000000000000000000000000000000122020400c59176c8c281fa0e5307b61d262224d0de76719187305ff3056e8e03162f4659558523b4b496",
                        "000000000555b3d5803c597499207e59955152a5567fc60500b6e6220f235e75"}},
        //78256
        {HEIGHT_HASH_MULTI_SIGNER,{"01000100776e255e317fc273becc976141582bff60c92aa3d62ef60aeb63e1ab79d77026af3101004c000000000000000000000000000000000000000000000000000000000000000000012302040072d094897585cdbe46d71392a989f43ad9c7d3b96aef2f5853629e55f3c7cf0100500358e387",
                        "000000000653baef49b1b12987a26e902e055a10a1042564d04d2a8f47b934af"}},
        {HEIGHT_HASH_MULTI_SIGNER + 1 ,{"01000100c36e255e43cbdc96db4e41701891b2c797cc7913e4f81248f55ac5b35e1fcb6bb03101004c0000000000000000000000000000000000000000000000000000000000000000000123020400c59176c8c281fa0e5307b61d262224d0de76719187305ff3056e8e03162f740000881ad93d35",
                        "000000001606fe6099212a8746b6b3b8419239743d250866befb10cf0a9fcfd4"}},

        {HEIGHT_HASH_TX_DATA - 1 ,{"010001004b25565e729b614daae85e9a19b08007010d63225425fe3371218ff3ae622c76c20702004c000000000000000000000000000000000000000000000000000000000000000000012202040072d094897585cdbe46d71392a989f43ad9c7d3b96aef2f5853629e55f3c70f5855b50b33e703",
                        "000000001ff239ee28bdacda17a99e1057a3bb94cb9e26f7e475ddba7e65db3f"}},
        //133060
        {HEIGHT_HASH_TX_DATA,{"010001005625565efa89a40dc2eb459a6d77aeee1d7c22612137c5eff7306837ca85b3c0c30702004c000000000000000000000000000000000000000000000000000000000000000000012202040036bf11d6954ef7236288fe9de78846334531e2715fa835581c2318cab89c07b0aa3a0d63988f",
                        "000000002777b3828480b4a96f1dcf617d9555d4be7a7a2d37565ad1a595500b"}},
        {HEIGHT_HASH_TX_DATA + 1 ,{"010001007c25565e139563114eed88711d4bd4c865500ca9f8d4a0dffefbadee251859ccc40702004c0000000000000000000000000000000000000000000000000000000000000000000123020400c59176c8c281fa0e5307b61d262224d0de76719187305ff3056e8e03162f97aeaa7a04385c07",
                        "0000000016c8bb1da5e5734257022c62f2b5add51184cf8fca13424582e04895"}},

        {581426, {"0100010022a7e95f3dac5b6ec0b4ed88fc5bc4c6c6d93c48fa8456d05c6553632c9ab80c31df08004c000000000000000000000000000000000000000000000000000000000000000000011e020400eb78f2762cb61482504af4a560053fb774901e3139008cc361f58c0b3aec2babaad23652c9b2",
                        "00000000451ee0b2fd09f02bff86c39f93889ca705a13fca602bb5339cc8c262"}},
    };

    for (const auto& ph : test_table)
    {
        std::vector<uint8> vch = ParseHexString(ph.second.first);
        uint256 hash;
        //cn_slow_hash(vch.data(), vch.size(), (char*)hash.begin(), 2, 0, 0);
        hash = CryptoPowHash(vch.data(), vch.size());
        BOOST_CHECK_MESSAGE(hash.ToString() == ph.second.second, "unexpected hashing");
        std::cout << hash.ToString() << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE_END()
