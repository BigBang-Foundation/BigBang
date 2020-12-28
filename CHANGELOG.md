

# Version 2.3.1 (2020-12-28)

### Fixs

- Adjust the calculation method of pow difficulty coefficient
* Fix some bugs

# Version 2.3.0 (2020-12-16)

### Features

- Support ubuntu 20.04 LTS build
- Change fork created coin from 100000 to 10000
- Add launch option "excludefork" to exclude some forks subscribed
- Remove restriction: parent of DeFi fork must be genesis fork, and DeFi fork can't inherit parent fork unspent
- Add Remove key and RemoveTemplate RPC
- DeFi: Add new Tx type for mint height
- Add separating making block function of super node
- Add address index, remove wallettx and optimize checkrepair for performance
- Change DPoS trust from weight * (2^bits) to 2^(weight + bits)
- DeFi: Add black hole address: 100000000000000000000000000000000000000000000000000000000
- Add dex bbc map template
- RPC: Add lock height parameter of transaction
- DeFi: Add New DeFi relation tx

### Fixs

- Fix PoW & DPoS mint rate
- Fix super node bug
- Fix txpool remove tx bug
- Fix some bugs for DeFi 

# Version 2.2.4 (2020-11-18)

### Fixs

- Remove invalid tx for Dex
- Fix resyncwallet bug: no balance
- Update Dockerfile and add build & run docker image bash script
- Change DPoS & PoW mint rate
- Reduce secure memory in Wallet Key
- Optimize the functions of fork management, mortgage redemption and fork repair
# Version 2.2.3 (2020-11-04)

### Fixs

- Remove valid addreess from DeFi black list
- Fix macOS compile issue and bug of black list on testnet

# Version 2.2.2 (2020-11-02)

### Fixs

- Add black list for invalid relation node
- DeFi Reward do not send to template address
- Modify dexmatch dest verify


# Version 2.2.1 (2020-10-29)

### Fixs

- Reduce memory usage of DeFi function
- Fix memory leak of CForest of DeFi relation
- Comparative study on avoiding the wrong matchmaking
- modify match verify height

# Version 2.2.0 (2020-10-21)

### Features
* Fix some DeFi bugs
* Add Decentral exchange(DEX) function

# Version 2.1.0 (2020-09-26)

### Features
* Add DeFi Function

# Version 2.0.5 (2020-08-04)

### Fixs
* Support fork checkpoint and Verify vacant block in fork invalid range
* Remove repeated collected in vchProof of block
* Fork rollback and extended maker
* Modify get work state
* Reduce bigbang core memory usage

### Features
* Add full-value transaction when amount=-1 for RPC CreateTransaction and SendFrom


# Version 2.0.4 (2020-07-16)

### Fixs
* Fix consensus bug: not check repeated publish
* Fix signature bug and add "sendtodata" option
* Enhance verification of CERT
* Fix crash when failing to inspect wallet tx

# Version 2.0.3 (2020-06-19)

### Fixs
* Fix bug of synchronous preamble transaction
* Fix check repair txpool bug
* Improve TxPool::ArrangeBlockTx performance


# Version 2.0.2 (2020-06-08)

### Features
* Add synctx parameter for addnewtemplate importtemplate importkey importpribkey RPCs
* Continuely start consensus result when dpos node restarted
* Update CheckPoints
* Improve RPC ListUnspent feature
* Recovery from the path of block.dat function
* Sign transaction for delegate address owned by multi-signature address without online
* Add testnet build flag for swicthing network between main net and test net
* No need to import address to vote
* Support multi-signature for owner address of vote template

### Fixs
* Improve RPCs gettransaction and getblockdetail performance
* BugFix of gettransaction
* Reduce upper and lower cache to only one cache to flush tx index

# Version 2.0.1 (2020-05-09)

### Fixs
* Bugfix of creating fork error caused by timestamp
* Update the upper limitation of voting sum to 30 million

# Version 2.0.0 (2020-05-07)

### Features
* EDPoS and CPoW consensus comes up
* Support multi-fork with extend block
* Add crossed-chain transaction feature to extend functions used to varieties of eco-system

# Version 1.1.0 (2020-01-19)

### Features
* Improve PoW hash algorithm of CryptoNight
* Enhanace the security of multiple signature


# Version 1.0.9 (2019-12-31)

### Fixs
* Fix check block valid syn bug


# Version 1.0.8 (2019-12-27)

### Fixs
* Judgement of multisig nRequired bug


# Version 1.0.4 (2019-12-12)

### Fixs
* Bug Fixs


# Version 1.0.3 (2019-12-11)

### Fixs
* Bug Fixs


# Version 1.0.2 (2019-12-05)

### Fixs
* Fix a UAF vulnerability

# Version 1.0.1 (2019-12-03)

### Fixs
* Bugfix of guarded heap memory allocation issue by a special method to avoid a failure launching bigbangcore.


# Version 1.0.0 (2019-11-19)

### Features
* Full pow featured support

# Version 0.2.0 (2019-08-29)

### Features
* Change mint bonus type.
* Support CYGWIN platform on windows.

### tools
* Add travis-ci.

# Version 0.1.0 (2019-08-14)

### Features
* Change PoW backbone: CryptoNight.
* Cross-chain template.

# Version 0.0.1 (2019-03-20)

### Features
* baseline
