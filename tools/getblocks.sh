 #!/usr/bin/env bash
 
while :
do
    curl --compressed -d '{"id":69,"method":"getblocks","jsonrpc":"2.0","params":{"fork":"0000000006854ebdc236f48dbbe5c87312ea0abd7398888374b5ee9a5eb1d291","blockhashes":["awdawrawraw44242", "0000000006854ebdc236f48dbbe5c87312ea0abd7398888374b5ee9a5eb1d291"], "num":500}}' -H 'Content-Type: application/json' -H 'Accept-Encoding: gzip, deflate' http://127.0.0.1:9908/sync/rpc
done
 
 
