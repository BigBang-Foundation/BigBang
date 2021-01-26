// Copyright (c) 2019-2021 The Bigbang developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BIGBANG_PARAM_H
#define BIGBANG_PARAM_H

#include "uint256.h"

static const int64 COIN = 1000000;
static const int64 CENT = 10000;
static const int64 OLD_MIN_TX_FEE = CENT / 100;
static const int64 NEW_MIN_TX_FEE = CENT;
static const int64 MAX_MONEY = 1000000000000 * COIN;
inline bool MoneyRange(int64 nValue)
{
    return (nValue >= 0 && nValue <= MAX_MONEY);
}
static const int64 MAX_REWARD_MONEY = 10000 * COIN;
inline bool RewardRange(int64 nValue)
{
    return (nValue >= 0 && nValue <= MAX_REWARD_MONEY);
}

static const unsigned int MAX_BLOCK_SIZE = 2000000;
static const unsigned int MAX_TX_SIZE = (MAX_BLOCK_SIZE / 20);
static const unsigned int MAX_SIGNATURE_SIZE = 2048;
static const unsigned int MAX_TX_INPUT_COUNT = (MAX_TX_SIZE - MAX_SIGNATURE_SIZE - 4) / 33;

static const unsigned int BLOCK_TARGET_SPACING = 60; // 1-minute block spacing
static const unsigned int EXTENDED_BLOCK_SPACING = 2;
static const unsigned int PROOF_OF_WORK_DECAY_STEP = BLOCK_TARGET_SPACING;
static const unsigned int PROOF_OF_WORK_BLOCK_SPACING = 20;

static const unsigned int DAY_HEIGHT = 24 * 60 * 60 / BLOCK_TARGET_SPACING;
static const unsigned int MONTH_HEIGHT = 30 * DAY_HEIGHT;
static const unsigned int YEAR_HEIGHT = 12 * MONTH_HEIGHT;

static const unsigned int MINT_MATURITY = 120; // 120 blocks about 2 hours
static const unsigned int MIN_TOKEN_TX_SIZE = 196;

#ifdef BIGBANG_TESTNET
static const unsigned int MIN_CREATE_FORK_INTERVAL_HEIGHT = 0;
static const unsigned int MAX_JOINT_FORK_INTERVAL_HEIGHT = 0x7FFFFFFF;
#else
static const unsigned int MIN_CREATE_FORK_INTERVAL_HEIGHT = 30;
static const unsigned int MAX_JOINT_FORK_INTERVAL_HEIGHT = 1440;
#endif

enum ConsensusMethod
{
    CM_MPVSS = 0,
    CM_CRYPTONIGHT = 1,
    CM_MAX
};

#ifndef BIGBANG_TESTNET
static const std::map<uint256, std::map<int, uint256>> mapCheckPointsList = {
    {
        uint256("00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70"), //Genesis
        { { 0, uint256("00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70") },
          { 100, uint256("000000649ec479bb9944fb85905822cb707eb2e5f42a5d58e598603b642e225d") },
          { 1000, uint256("000003e86cc97e8b16aaa92216a66c2797c977a239bbd1a12476bad68580be73") },
          { 2000, uint256("000007d07acd442c737152d0cd9d8e99b6f0177781323ccbe20407664e01da8f") },
          { 5000, uint256("00001388dbb69842b373352462b869126b9fe912b4d86becbb3ad2bf1d897840") },
          { 10000, uint256("00002710c3f3cd6c931f568169c645e97744943e02b0135aae4fcb3139c0fa6f") },
          { 16000, uint256("00003e807c1e13c95e8601d7e870a1e13bc708eddad137a49ba6c0628ce901df") },
          { 23000, uint256("000059d889977b9d0cd3d3fa149aa4c6e9c9da08c05c016cb800d52b2ecb620c") },
          { 31000, uint256("000079188913bbe13cb3ff76df2ba2f9d2180854750ab9a37dc8d197668d2215") },
          { 40000, uint256("00009c40c22952179a522909e8bec05617817952f3b9aebd1d1e096413fead5b") },
          { 50000, uint256("0000c3506e5e7fae59bee39965fb45e284f86c993958e5ce682566810832e7e8") },
          { 70000, uint256("000111701e15e979b4633e45b762067c6369e6f0ca8284094f6ce476b10f50de") },
          { 90000, uint256("00015f902819ebe9915f30f0faeeb08e7cd063b882d9066af898a1c67257927c") },
          { 110000, uint256("0001adb06ed43e55b0f960a212590674c8b10575de7afa7dc0bb0e53e971f21b") },
          { 130000, uint256("0001fbd054458ec9f75e94d6779def1ee6c6d009dbbe2f7759f5c6c75c4f9630") },
          { 150000, uint256("000249f070fe5b5fcb1923080c5dcbd78a6f31182ae32717df84e708b225370b") },
          { 170000, uint256("00029810ac925d321a415e2fb83d703dcb2ebb2d42b66584c3666eb5795d8ad6") },
          { 190000, uint256("0002e6304834d0f859658c939b77f9077073f42e91bf3f512bee644bd48180e1") },
          { 210000, uint256("000334508ed90eb9419392e1fce660467973d3dede5ca51f6e457517d03f2138") },
          { 230000, uint256("00038270812d3b2f338b5f8c9d00edfd084ae38580c6837b6278f20713ff20cc") },
          { 238000, uint256("0003a1b031248f0c0060fd8afd807f30ba34f81b6fcbbe84157e380d2d7119bc") },
          { 285060, uint256("00045984ae81f672b42525e0465dd05239c742fe0b6723a15c4fd03215362eae") },
          { 366692, uint256("00059864d72f76565cb8aa190c1e73ab4eb449d6641d73f7eba4e6a849589453") },
          { 400000, uint256("00061a8020ce3ddf579e34bfa38ff95c9667bf50fce8005069d8dcfeb695f0d9") },
          { 450000, uint256("0006ddd0a514053cc0e11c1c04218a5cc40c8e01e9ad7010665cc3ce196c06b0") },
          { 521000, uint256("0007f3287379c169e8a2a771667c0cbc95f04c8a88536c8cfb58da2df6aa0c7b") },
          { 562880, uint256("000896c085ff6958f52ea35f1f19be45ca7e3a4ffa51ebf3fe78089d43e6b641") },
          { 621520, uint256("00097bd009c801f10d40e6021a2de9707624ba7f2134da917443e33eddb9e9a1") } },
    },
    {
        uint256("000493e02a0f6ef977ebd5f844014badb412b6db85847b120f162b8d913b9028"), // BBCN
        { { 300000, uint256("000493e02a0f6ef977ebd5f844014badb412b6db85847b120f162b8d913b9028") },
          { 335999, uint256("0005207f9be2e4f1a278054058d4c17029ae6733cc8f7163a4e3099000deb9ff") },
          { 521000, uint256("0007f328978a647ae670111b1c1c7649057088299be7221c21cde0bb3ec31106") },
          { 562880, uint256("000896c0796d0c3122bc60113ca0e8b1307d92e6fbac2c70adb4eeffbc47b6b2") },
          { 621520, uint256("00097bd081cca0bbe8f3ba6133cafada7bc9f770fa0f9e2c00359e374f29fb74") } },
    },
    {
        uint256("0006d42cd48439988e906be71b9f377fcbb735b7905c1ec331d17402d75da805"), // BTCA
        { { 447532, uint256("0006d42cd48439988e906be71b9f377fcbb735b7905c1ec331d17402d75da805") },
          { 450000, uint256("0006ddd04452bce958ba78a1e044108fb4e9eac31751151b01b236cd2041b9eb") },
          { 521000, uint256("0007f32802af9cccea6de77fe80d8ce4c81d6c2db887b62e15a2ddf637198362") },
          { 562880, uint256("000896c0cf669ca3375a505f14fed8da59e2f86d90d80b02149487b9282c6a4d") },
          { 621520, uint256("00097bd0c0425df0429d579220f358c71a7a6f21fb5e779802b24645530c64f7") } },
    },
    {
        uint256("00068fb1bad4194126b0d1c1fb46b9860d4e899730825bd9511de4b14277d136"), // BBCC
        { { 430001, uint256("00068fb1bad4194126b0d1c1fb46b9860d4e899730825bd9511de4b14277d136") },
          { 450000, uint256("0006ddd011ca1049c434d5b6976b1534aef6c49883460afa05f5ac541aefbb0c") },
          { 521000, uint256("0007f3280d924ff50c948bd28a79d7a0e379b042e015d2e1008daf619bccd81e") },
          { 562880, uint256("000896c0619e9812dade3b936e2b9e17fcfead9659aeb5fe687f0940ea4b1b29") },
          { 621520, uint256("00097bd071c73754774dd0c280cb55ae5bf8949325eef30c63d123a539880972") } },
    },
    {
        uint256("0007cc887adb54ff1b81c42d69922dea155375d1543f1e96bb8aabbe323689b3"), // USDTTRC20
        { { 511112, uint256("0007cc887adb54ff1b81c42d69922dea155375d1543f1e96bb8aabbe323689b3") },
          { 521000, uint256("0007f3284830c6de411c4e4eea0fb8b6802c8dba2be96777f44f09adc2a8416c") },
          { 562880, uint256("000896c08ca8d349cffcc0ab91eb5542f88b13ef8ac017ad22d74fd71b311bcf") },
          { 621520, uint256("00097bd0ccb96364a30552d09dda3c0f719e78ff7253d3e2854f700eb8b70c3c")} },
    },
    {
        uint256("0007cc88c585d8f44ca70403073869b179a2465df93bec6b18e34d370bf40a5e"), // USDTERC20
        { { 511112, uint256("0007cc88c585d8f44ca70403073869b179a2465df93bec6b18e34d370bf40a5e") },
          { 521000, uint256("0007f3281ff974cfe29259acadc6ca034e2b1109c58cc46b6bc9368eaa9ac1d4") },
          { 562880, uint256("000896c0df80fcf39e9381a142bc956a889225837382fdbc0988c5cac6dd79fa") } },
    },
    {
        uint256("0007cc880a19fc5f621d01fd583378bd6a2207568a730ac07f6f87f99a468cf3"), // MKF
        { { 511112, uint256("0007cc880a19fc5f621d01fd583378bd6a2207568a730ac07f6f87f99a468cf3") },
          { 521000, uint256("0007f328300eebaca221eb428ab2d1608d33513fb27c4597abad91bb2efc9b66") },
          { 562880, uint256("000896c084f03513ce40cc73a49206af2e4ce7fb8aac23c62af4d92afeb68dbc") } },
    },
    {
        uint256("000809d17b026c65a61112dcbbf3ef16cec1c59c6ae8b7cb7027947923a5eb2c"), // USDT BTCAlly
        {
            { 526801, uint256("000809d17b026c65a61112dcbbf3ef16cec1c59c6ae8b7cb7027947923a5eb2c") },
            { 562880, uint256("000896c038b2f7b58fe2bb9ff5f7b36cdbad84e156609bb70301186d551b6fae") } },
    },
    // {
    //     uint256("00084392ffd16a91e7f66e6271a6b3921c78b37c831470648d441f240afda9a9"), // DEFI
    //     { { 511112, uint256("") },
    //       { 521000, uint256("") },
    //       { 562880, uint256("") } },
    // },
    {
        uint256("000849041916a09744ea6d0013a7d5a02152cc8bacc69495dfd21736fdea0bf0"), // BTCC
        {
            { 542980, uint256("000849041916a09744ea6d0013a7d5a02152cc8bacc69495dfd21736fdea0bf0") },
            { 562880, uint256("000896c0b556a282356f3fe32ff8b368237da6210c5dc0986965e848fbda1ef2") } },
    },
    {
        uint256("000887352986734694ceb9a27c8ac05ebd5aaedebf822706a1ca69edc5f09d51"), // BTCE
        {
            { 558901, uint256("000887352986734694ceb9a27c8ac05ebd5aaedebf822706a1ca69edc5f09d51") },
            { 562880, uint256("000896c00e28305a4792bb6a80da1a30ab0b230c1de13127eb19f78f5d6881b9") } },
    },
    {
        uint256("00088ab9280fc0168087e43f1ff40d1611709d12332f094c95a3b054c9ef1144"), // Bit consensus fund
        {
            { 559801, uint256("00088ab9280fc0168087e43f1ff40d1611709d12332f094c95a3b054c9ef1144") },
            { 562880, uint256("000896c0ff411124228629ec23d192f77eb1cae3a742b396e930ab59bc42ea99") } },
    },
};

#endif

#endif //BIGBANG_PARAM_H
