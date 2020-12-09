 #!/usr/bin/env bash
 
while :
do
    curl -d '{"id":69,"method":"getblocks","jsonrpc":"2.0","params":{"fork":"00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70","blockhashes":["awdawrawraw44242", "00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70"], "num":500}}' http://192.168.199.180:9906
done
 
 
