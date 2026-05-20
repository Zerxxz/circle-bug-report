# Circle BBP Bug Reports

Security vulnerability findings for the Circle Bug Bounty Program on HackerOne.

## Findings

### 1. Mempool Transaction Exposure (Medium)

**Asset:** `rpc.blockdaemon.testnet.arc.network`, `rpc.drpc.testnet.arc.network`

The `txpool_content` RPC method is publicly accessible on Blockdaemon and DRPC Arc testnet RPC endpoints, exposing all pending and queued transactions to any external observer.

**Impact:**
- Front-running and sandwich attack vectors on testnet
- Exposure of pending transaction details (sender, recipient, value, nonces, input data)
- User privacy violation

**Severity:** Medium

**Files:**
- [circle-bbp-mempool-exposure.md](./circle-bbp-mempool-exposure.md) — Full report
- [circle-bbp-poc.sh](./circle-bbp-poc.sh) — Live PoC script

**Run PoC:**
```bash
bash circle-bbp-poc.sh
```

---

*Reports are submitted to the Circle BBP program on HackerOne for review.*