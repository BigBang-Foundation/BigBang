去中心化交易所测试流程：
-------------------------------------------------------------------
# 实现原理：
## 一、挂单模板地址参数：
```
1）挂单地址：挂单者的地址，赎回挂单TOKEN使用该地址的私钥签名；
2）币对：买卖双方的交易对，如：BBC/MKF，指BBC与MKF交易；
3）价格：指本方的一个TOKEN兑换对方的多少TOKEN；
4）费率：指给撮合者和跨链交易者的奖励的费率，交易数量剩费率即为奖励数量，由撮合者和跨链交易者平分，缺省费率为0.2%；
5）接收地址：在对端链接收TOKEN的地址，该地址为对端链的地址格式，在该参数为字符串表示，最大长度为128字符；
6）跨链交易高度数：指完成跨链交易的有效高度数（相对高度值），从撮合完成的高度开始，在指定高度数以内，可以执行跨链交易，超过该高度数后，则不能执行跨链交易，而挂单者则可以从撮合模块地址转出TOKEN；
7）撮合者地址：挂单者指定的撮合者的地址；
8）跨链交易者地址：挂单者指定的跨链交易者的地址，该地址为买方（对端）链的地址，存储为字符串格式，最大长度为128字符；
9）挂单时间戳：挂单时间戳或随机数；
```

## 二、撮合模板地址参数：
```
1）撮合者地址：撮合者获取撮合奖励的地址，撮合交易的签名也是使用该地址对应的私钥签名；
2）币对：买卖双方的交易对，与挂单模板地址中的币对一至；
3）实际成交价：指实际撮合的成交价；
4）卖方交易数量：完成撮合的TOKEN数量，指本端卖出的TOKEN数量；
5）卖方费率：指给撮合者和跨链交易者的奖励的费率，交易数量剩费率即为奖励数量，由撮合者和跨链交易者平分，缺省费率为0.2%，该参数需要与挂单模板中的费率相同；
6）卖方秘密的HASH值：该参数为sha256的hash，由撮合者随机生成的数据（即秘密），经过sha256计算而得；
7）卖方秘密的加密值：该参数为秘密经过加密后的数据，每条链的加密方式可以自定义；
8）卖方挂单模板地址：卖方挂单交易中的挂单模板地址，与卖方的挂单模板地址相同；
9）卖方挂单地址：卖方挂单者的地址，挂单者撤回TOKEN的地址，与卖方的挂单模板地址中的挂单地址相同；
10）卖方跨链交易者地址：卖方跨链交易者地址，与卖方的挂单模板地址中的跨链交易者地址相同；
11）卖方的有效高度：卖方撮合模板地址有效高度（绝对高度值），在该高度以内，跨链交易者可以执行交易，在该高度以上，则跨链交易者将不能执行交易，挂单者可以从撮合模板地址转出TOKEN，即挂单者撤回TOKEN；
12）买方挂单者地址：买方的挂单模板地址中的挂单者地址，该地址接收买卖的TOKEN；
13）买方交易数量：买方撮合数量，该参数为数值字符串，最大64字节；
14）买方的秘密的hash值：买方的秘密的hash值；
15）买方的有效高度：买方的有效高度值（绝对高度值）；
```

## 三、BBC/MKF秘密的生成和较验：
```
1）秘密：撮合者随机生成32字节的数据；
2）秘密的HASH值：秘密经过sha256计算得到的值；
3）秘密的加密值：秘密经过ed25519+aes加密后得到的值；
4）秘密的加密方法：撮合者地址的私钥+跨链交易者地址的公钥，经过ed25519+aes加密，得到秘密的加密值；
5）秘密的解密方法：跨链交易者地址的私钥+撮合者地址的公钥，经过ed25519+aes解密，得到秘密；
6）撮合者将秘密的HASH值和秘密的加密值放在撮合模板地址参数中，用于后面的较验；
7）跨链交易者使用自已的私钥和撮合者的公钥，解密秘密的加密值，得到秘密；
8）秘密较验：将秘密经过sha256计算得到秘密的HASH值，与模板中的秘密的HASH值比对来完成较验；
```

## 四、撮合逻辑：
```
1）撮合方收集两条链的挂单信息，两条链上的挂单同时满足同一个撮合方的撮合条件时，则由该撮合方完成撮合；
2）同时满足同一个撮合方的撮合条件：两条链上的挂单的撮合地址是同一个，并且处理高度范围存在交集，并且交集的高度满足指定数量；
3）当只撮合部分TOKEN时，剩余TOKEN可以继续撮合，直到挂单模板地址中的TOKEN小于等于费率值或者当前高度超过了有效高度时为止；
```

## 五、跨链交易逻辑：
```
1）锁定高度高的一方（假设为跨链交易方A），较验对端链的撮合交易中的撮合模板参数，是否与本端链的挂单模板参数一至（如秘密的hash值是否一至，TOKEN是否一至等），如果一至，则通过自已的私钥和跨链交易者的公钥，解密秘密的HASH值，得到秘密，然后将秘密传给对端；可以采用多种途径传递给对端，如果跨链交易方A和跨链交易方B无法建立线下通讯，则可以产生一条交易（该交易的from和to都为撮合模板地址），将秘密放在vchData中，该交易在跨链交易方A的链上（即A链）；
2）锁定高度低的一方（假设为跨链交易方B），在A链上监听到秘密的交易，获得A链的秘密（或者通过其它途径获得秘密），跨链交易方B即可以将撮合模板地址B中的TOKEN转到相应的地址（包括转到挂单A的地址），该交易中需要包含秘密A和秘密B（秘密B是跨链交易方B解密得到）；
3）跨链交易方A在B链上监听到上面的转帐交易，即可获得秘密B，然后跨链交易方A就可以将撮合模板地址A中的TOKEN转到相应的地址（包括转到挂单B的地址），同样该交易中包含秘密A和秘密B，该步完成了跨链交易；
```

## 五、撤单：
```
1）挂单者从挂单后，到被撮合之前，都可以撤单，被撮合后则不能撤单；
2）挂单者从挂单模板地址转出TOKEN，即为撤单，转出地址无限制，撤单的交易需要挂单者的私钥签名；
3）撤单交易和撮合交易同时产生时，则以谁先上链，谁优先原则，后面的交易将无效处理；
```

## 六、撮合模板地址需要转出的三条交易：
```
撮合模板地址A ：跨链交易方A完成（假设费率为0.2%）
1）撮合模板地址A  ->  挂单地址B，比例：99.8%
2）撮合模板地址A  ->  撮合地址，比例：0.1%
3）撮合模板地址A  ->  跨链交易地址A，比例：0.1%

撮合模板地址B ：跨链交易方B完成（假设费率为0.2%）
1）撮合模板地址B  ->  挂单地址A，比例：99.8%
2）撮合模板地址B  ->  撮合地址，比例：0.1%
3）撮合模板地址B  ->  跨链交易地址B，比例：0.1%

转帐数量计算：
a）转帐给买方地址的amount计算：(撮合数量-0.01*3)*(1-费率)
b）转帐给撮合方地址的amount计算：(撮合数量-0.01*3)*(费率/2)
c）转帐给跨链交易方地址的amount计算：撮合数量 - ((撮合数量-0.01*3)*(1-费率)+0.01) - ((撮合数量-0.01*3)*(费率/2)+0.01) - 0.01     （即：剩余数量-0.01）
注：需要严格按上面的公式计算，否则可能较验失败。

交易费率（必须）：0.01
交易顺序（必须）：转帐给买方地址、转帐给撮合方地址、转帐给跨链交易方地址
```

# 测试方法：
## 一、测试准备：
```
1）下载代码（分支dex-master）：
git clone https://github.com/BigBang-Foundation/BigBang.git
git checkout dex-master

2）编译代码（带testnet参数，编译为测试网程序）
./INSTALL.sh testnet

3）添加目录及配置文件：
添加目录：.bigbang
添加配置文件：bigbang.conf   （在.bigbang目录下）
配置参数：
cryptonightaddress=1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm
cryptonightkey=9f1e445c2a8e74fabbb7c53e31323b2316112990078cbd8d27b2cd7100a1648d
listen4

4）启动程序：
$ bigbang -daemon -debug

5）启动客户端：
$ bigbang-cli

6）导入创世地址：
importprivkey 9df809804369829983150491d1086b99f6493356f91ccc080e661a76a976a4ee 123
```

## 二、各个地址信息：
```
1）生成卖方（本端）挂单地址：
privkey: 12d00e8b46fbdc54cbf7f47f98a98bb3ea4843131f7ed2ffc11ad07405ca4f33
pubkey: b7465560cab12b80368e133c4c4ee04391b3463be73a6073f66914624b8ece96
address: 1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn

2）生成买方（对端）挂单地址：
privkey: 2c2bd21229865dc051f246492203ee09eea60d96ffb56073032a28b763eae667
pubkey: a110983d7b9d0055285080fa5ff7d8b2364cdab4503b9f917cb7af8e7234afac
address: 1njqk8wmenyvqs4cz7d8b9pjc6tsdhxtzza050a2n02eqpfcr22ggqg47

3）生成撮合者地址：
privkey: 47a090d85d8ff12f327e8fa6d238be0fd7de05a7b92083831e50593cec9c2eae
pubkey: a844944216eeb67c2766de8487691e50ad8612e8b10f42cf45c8d61074533a2b
address: 15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd

4）生成跨链交易者地址：
privkey: 43ff83b7063a3a3ff6b8c5a2d43ce14fdcfeec7b754ee83345ae7280e1a8c85d
pubkey: 89e15f230edeb9f4d2897eebd585f4414b06584e58982fa585055d598d2a9678
address: 1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb
```

## 三、导入地址的私钥：
```
importprivkey 12d00e8b46fbdc54cbf7f47f98a98bb3ea4843131f7ed2ffc11ad07405ca4f33 123
importprivkey 2c2bd21229865dc051f246492203ee09eea60d96ffb56073032a28b763eae667 123
importprivkey 47a090d85d8ff12f327e8fa6d238be0fd7de05a7b92083831e50593cec9c2eae 123
importprivkey 43ff83b7063a3a3ff6b8c5a2d43ce14fdcfeec7b754ee83345ae7280e1a8c85d 123
```

## 四、生成秘密的HASH值：
```
1）生成卖方秘密的HASH值：
秘密：b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef
秘密的HASH值：41f73534701f620ee8f48ecd61bb422fa9243ccc6ddda5e806f5858121c47268

注：使用makesha256 命令可以生成秘密的HASH值，生成的结果信息：
hexdata：秘密
sha256：为hexdata数据经过sha256计算后的数据，该数据为秘密的HASH值；

2）生成买方秘密的HASH值：
秘密：6836ba9b8f40f968888a7376f657f97c53cfa8db02872e0f1daf8376cb80b1e7
秘密的HASH值：dfa313257be0216a498d2eb6e5a1939eb6168d4a9e3356cc20fb957d030b1ac5

3）生成秘密的加密数据：
将秘密（hexdata数据），经过ed25519+aes加密，得到秘密的加密数据，加密需要使用本端撮合者地址和买方（对端）的跨链交易者地址，本端撮合者地址需要导入并解锁；

解锁地址：
unlockkey 1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn 123

生成加密数据：
aesencrypt 1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn 1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef

加密数据：42f30c39231e1a518e437df6a71e26535ef65f852fb879157bf9903b7d8065edc66eacec81eaef841c1052978b01340e

4）解密秘密：
秘密的加密数据，经过ed25519+aes解密，得到秘密数据，解密时需要交换地址，并且本地地址需要导入并解锁；

解锁地址：
unlockkey 1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb 123

解密数据：
aesdecrypt 1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb 1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn 42f30c39231e1a518e437df6a71e26535ef65f852fb879157bf9903b7d8065edc66eacec81eaef841c1052978b01340e

秘密数据：b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef
```

## 五、生成模板地址：
```
1）生成挂单模板地址：

挂单模板地址字段信息：
"seller_address":"1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn",
"coinpair":"BBC/MKF",
"price":10,
"fee": 0.002,
"recv_address":"1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn",
"valid_height": 300,
"match_address": "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd",
"deal_address": "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb",
"timestamp": 1234

添加挂单模板地址命令：
addnewtemplate dexorder '{"seller_address":"1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn","coinpair":"BBC/MKF","price":10,"fee": 0.002,"recv_address":"1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn","valid_height": 300,"match_address": "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd","deal_address": "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb","timestamp":1234}'

挂单模板地址：2140c6rd39hpdmgv9m1m80h738gz4f2c0kmpvn707p04c7x1kcb8gawj6

2）生成撮合模板地址：

撮合模板地址字段信息：
"match_address": "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd",
"coinpair":"BBC/MKF",
"final_price":10,
"match_amount": 15,
"fee": 0.002,
"secret_hash":"41f73534701f620ee8f48ecd61bb422fa9243ccc6ddda5e806f5858121c47268",
"secret_enc": "42f30c39231e1a518e437df6a71e26535ef65f852fb879157bf9903b7d8065edc66eacec81eaef841c1052978b01340e",
"seller_order_address": "2140c6rd39hpdmgv9m1m80h738gz4f2c0kmpvn707p04c7x1kcb8gawj6",
"seller_address": "1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn",
"seller_deal_address": "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb",
"seller_valid_height": 300,
"buyer_address": "1njqk8wmenyvqs4cz7d8b9pjc6tsdhxtzza050a2n02eqpfcr22ggqg47",
"buyer_amount": "150",
"buyer_secret_hash":"dfa313257be0216a498d2eb6e5a1939eb6168d4a9e3356cc20fb957d030b1ac5",
"buyer_valid_height":320

添加撮合模板地址命令：
addnewtemplate dexmatch '{"match_address": "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd","coinpair":"BBC/MKF","final_price":10,"match_amount": 15,"fee": 0.002,"secret_hash":"41f73534701f620ee8f48ecd61bb422fa9243ccc6ddda5e806f5858121c47268","secret_enc": "42f30c39231e1a518e437df6a71e26535ef65f852fb879157bf9903b7d8065edc66eacec81eaef841c1052978b01340e","seller_order_address": "2140c6rd39hpdmgv9m1m80h738gz4f2c0kmpvn707p04c7x1kcb8gawj6","seller_address": "1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn","seller_deal_address": "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb","seller_valid_height": 300,"buyer_address": "1njqk8wmenyvqs4cz7d8b9pjc6tsdhxtzza050a2n02eqpfcr22ggqg47","buyer_amount": "150","buyer_secret_hash":"dfa313257be0216a498d2eb6e5a1939eb6168d4a9e3356cc20fb957d030b1ac5","buyer_valid_height":320}'

撮合模板地址：21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9
```

## 六、交易：
```
1）挂单交易：向挂单模板地址转帐
解锁地址：
unlockkey 1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm 123
向挂单模板地址转帐：
sendfrom 1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm 2140c6rd39hpdmgv9m1m80h738gz4f2c0kmpvn707p04c7x1kcb8gawj6 100

注：任何地址向挂单模板地址转帐都可以，帐转数量为需要交易的数量，但可能只有部分数量完成交易。

2）撮合交易：由撮合者完成交易，从挂单模板地址向撮合模板地址转帐，转帐TOKEN数为撮合模板地址中的交易数量。
解锁撮合者地址：
unlockkey 15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd 123
转帐给撮合模板地址：
sendfrom 2140c6rd39hpdmgv9m1m80h738gz4f2c0kmpvn707p04c7x1kcb8gawj6 21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9 15

3）产生跨链交易：由跨链交易者产生交易，从撮合模板地址向买方地址转帐。
解锁跨链交易者地址：
unlockkey 1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb 123
转帐给买方地址：
sendfrom 21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9 1njqk8wmenyvqs4cz7d8b9pjc6tsdhxtzza050a2n02eqpfcr22ggqg47 14.88018 0.03 -sm=b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef -ss=6836ba9b8f40f968888a7376f657f97c53cfa8db02872e0f1daf8376cb80b1e7
转帐给撮合方地址：
sendfrom 21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9 15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd 0.01491 0.03 -sm=b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef -ss=6836ba9b8f40f968888a7376f657f97c53cfa8db02872e0f1daf8376cb80b1e7
转帐给跨链交易方地址：
sendfrom 21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9 1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb 0.01491 0.03 -sm=b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef -ss=6836ba9b8f40f968888a7376f657f97c53cfa8db02872e0f1daf8376cb80b1e7

-sm：为卖方的秘密；
-ss：为买方的秘密；

转帐数量计算：
a）转帐给买方地址的amount计算：(撮合数量-0.01*3)*(1-费率)
b）转帐给撮合方地址的amount计算：(撮合数量-0.01*3)*(费率/2)
c）转帐给跨链交易方地址的amount计算：撮合数量 - ((撮合数量-0.01*3)*(1-费率)+0.01) - ((撮合数量-0.01*3)*(费率/2)+0.01) - 0.01     （即：剩余数量-0.01）
注：需要严格按上面的公式计算，否则可能较验失败。

交易费率（必须）：0.01
交易顺序（必须）：转帐给买方地址、转帐给撮合方地址、转帐给跨链交易方地址
```

## 七、所有命令集合：
```
importprivkey 9df809804369829983150491d1086b99f6493356f91ccc080e661a76a976a4ee 123
importprivkey 12d00e8b46fbdc54cbf7f47f98a98bb3ea4843131f7ed2ffc11ad07405ca4f33 123
importprivkey 2c2bd21229865dc051f246492203ee09eea60d96ffb56073032a28b763eae667 123
importprivkey 47a090d85d8ff12f327e8fa6d238be0fd7de05a7b92083831e50593cec9c2eae 123
importprivkey 43ff83b7063a3a3ff6b8c5a2d43ce14fdcfeec7b754ee83345ae7280e1a8c85d 123

addnewtemplate dexorder '{"seller_address":"1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn","coinpair":"BBC/MKF","price":10,"fee": 0.002,"recv_address":"1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn","valid_height": 300,"match_address": "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd","deal_address": "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb","timestamp":1234}'

addnewtemplate dexmatch '{"match_address": "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd","coinpair":"BBC/MKF","final_price":10,"match_amount": 15,"fee": 0.002,"secret_hash":"41f73534701f620ee8f48ecd61bb422fa9243ccc6ddda5e806f5858121c47268","secret_enc": "42f30c39231e1a518e437df6a71e26535ef65f852fb879157bf9903b7d8065edc66eacec81eaef841c1052978b01340e","seller_order_address": "2140c6rd39hpdmgv9m1m80h738gz4f2c0kmpvn707p04c7x1kcb8gawj6","seller_address": "1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn","seller_deal_address": "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb","seller_valid_height": 300,"buyer_address": "1njqk8wmenyvqs4cz7d8b9pjc6tsdhxtzza050a2n02eqpfcr22ggqg47","buyer_amount": "150","buyer_secret_hash":"dfa313257be0216a498d2eb6e5a1939eb6168d4a9e3356cc20fb957d030b1ac5","buyer_valid_height":320}'

unlockkey 1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm 123
sendfrom 1965p604xzdrffvg90ax9bk0q3xyqn5zz2vc9zpbe3wdswzazj7d144mm 2140c6rd39hpdmgv9m1m80h738gz4f2c0kmpvn707p04c7x1kcb8gawj6 100

unlockkey 15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd 123
sendfrom 2140c6rd39hpdmgv9m1m80h738gz4f2c0kmpvn707p04c7x1kcb8gawj6 21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9 15

unlockkey 1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb 123
sendfrom 21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9 1njqk8wmenyvqs4cz7d8b9pjc6tsdhxtzza050a2n02eqpfcr22ggqg47 14.94006 -sm=b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef -ss=6836ba9b8f40f968888a7376f657f97c53cfa8db02872e0f1daf8376cb80b1e7
sendfrom 21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9 15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd 0.01497 -sm=b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef -ss=6836ba9b8f40f968888a7376f657f97c53cfa8db02872e0f1daf8376cb80b1e7
sendfrom 21806854fx1t09990vbr2z1td5m9qhkw44jyq265q4xqnpky682y6n4n9 1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb 0.01497 -sm=b6103658b60234ade25b7389a08514b6803dff9c636dff92ef0edaa0f37e2eef -ss=6836ba9b8f40f968888a7376f657f97c53cfa8db02872e0f1daf8376cb80b1e7
```
