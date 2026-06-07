#!/bin/bash
echo "=== Vault Init Script ==="

# Wait for vault
until docker exec deploy-vault-1 sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=frost-dev-token vault status" > /dev/null 2>&1; do
    echo "Waiting for Vault..."
    sleep 2
done

echo "Vault ready!"

# Enable KV engine
docker exec deploy-vault-1 sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=frost-dev-token vault secrets enable -path=frost kv-v2 2>/dev/null; true"

# Store shares
SHARE1=$(python3 -c "import json; d=json.load(open('data/frost-keys.json')); print(d['shares'][0])")
SHARE2=$(python3 -c "import json; d=json.load(open('data/frost-keys.json')); print(d['shares'][1])")
SHARE3=$(python3 -c "import json; d=json.load(open('data/frost-keys.json')); print(d['shares'][2])")
SHARE4=$(python3 -c "import json; d=json.load(open('data/frost-keys.json')); print(d['shares'][3])")
SHARE5=$(python3 -c "import json; d=json.load(open('data/frost-keys.json')); print(d['shares'][4])")

docker exec deploy-vault-1 sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=frost-dev-token vault kv put frost/signer-1 share=${SHARE1}"
docker exec deploy-vault-1 sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=frost-dev-token vault kv put frost/signer-2 share=${SHARE2}"
docker exec deploy-vault-1 sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=frost-dev-token vault kv put frost/signer-3 share=${SHARE3}"
docker exec deploy-vault-1 sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=frost-dev-token vault kv put frost/signer-4 share=${SHARE4}"
docker exec deploy-vault-1 sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=frost-dev-token vault kv put frost/signer-5 share=${SHARE5}"

echo "All shares stored in Vault!"
