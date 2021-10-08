#!/usr/bin/env bash

set -x
set -e

mkdir -p /etc/mangata/keys

echo "=============================="
echo "====> Node command:"
echo "/mangata/node \
        --chain $NODE_CHAIN \
        --unsafe-ws-external \
        --validator \
        --rpc-methods Unsafe \
        --rpc-cors all \
        --name $NODE_NAME $NODE_PARAMS"
echo "=============================="

/mangata/node \
  --chain "$NODE_CHAIN" \
  --unsafe-ws-external \
  --validator \
  --rpc-methods "Unsafe" \
  --rpc-cors "all" \
  --name "$NODE_NAME" $NODE_PARAMS &

node_pid=$!

ready=false

function generateKeys() {
  echo "====> Generating keys..."
  cd /etc/mangata/keys && /usr/bin/node-keygen generate --plaintext --filename validator --subkeycommand "/usr/bin/subkey"
  echo "====> Generated keys:"
  cd /etc/mangata/keys && cat keys.txt
}

function injectKeys() {
  echo "====> Injecting keys..."
  cd /etc/mangata/keys && /usr/bin/node-keygen inject --filename validator --injectionEndpoint "http://127.0.0.1:9933" --subkeycommand "/usr/bin/subkey"
}

function restartNode() {
  echo "====> Restarting node..."

  kill -SIGint "$node_pid"

  /mangata/node \
  --chain "$NODE_CHAIN" \
  --unsafe-ws-external \
  --validator \
  --rpc-methods "Unsafe" \
  --rpc-cors "all" \
  --name "$NODE_NAME" $NODE_PARAMS
}

while [ "$ready" = "false" ]; do
  node_status=$(curl --location --request POST 'http://127.0.0.1:9933' --header 'Content-Type: application/json' --data-raw '{"id": 999, "jsonrpc": "2.0", "method": "system_health"}' | jq .result.isSyncing )

  if [ "$node_status" = "false" ]; then
    ready=true
    echo "====> Node is ready, generating and injecting keys."
    generateKeys
    injectKeys
    restartNode
  else
    echo "====> Node is not ready yet, retrying in 5 seconds..."
    sleep 5s
  fi
done

echo "====> Done."