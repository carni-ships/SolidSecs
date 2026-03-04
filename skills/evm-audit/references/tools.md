# Audit Tools Reference

CLI invocations, output formats, and interpretation notes for every supported tool.

---

## Slither

**Install:** `pip install slither-analyzer` or `uv tool install slither-analyzer`

```bash
# Auto-detect project (Foundry/Hardhat/Truffle)
slither .

# Single file
slither contracts/MyContract.sol

# JSON output for parsing
slither . --json slither-output.json

# Specific detectors only
slither . --detect reentrancy-eth,arbitrary-send-eth,controlled-delegatecall

# Exclude test/mock files
slither . --filter-paths "test,mock,Mock,Test,node_modules,lib"

# With Foundry remappings
slither . --foundry-out-directory out

# Print inheritance graph
slither . --print inheritance-graph

# Print function summary
slither . --print function-summary

# Print call graph
slither . --print call-graph
```

**Output interpretation:**
- Results sorted by impact (High → Medium → Low → Informational)
- Each finding includes: detector name, description, contract, function, line
- False positive rate ~30–50% on complex DeFi — always verify manually
- Key high-signal detectors: `reentrancy-eth`, `arbitrary-send-eth`, `controlled-delegatecall`, `uninitialized-local`, `suicidal`, `arbitrary-send-erc20`, `tautology`

---

## Aderyn

**Install:** `curl -L https://raw.githubusercontent.com/Cyfrin/aderyn/dev/cyfrinup/install | bash && cyfrinup`
Or: `cargo install aderyn`

```bash
# Analyze project (auto-detects Foundry)
aderyn .

# Specific path
aderyn src/

# Output to specific file
aderyn . --output aderyn-report.md

# JSON output
aderyn . --output aderyn-report.json

# Exclude paths
aderyn . --exclude test,script,lib
```

**Output interpretation:**
- Produces markdown report directly
- Strong at: missing access controls, centralization risks, ERC standard deviations
- Complements Slither — different detector set
- Check `HIGH` and `MEDIUM` sections first

---

## Mythril

**Install:** `pip install mythril`

```bash
# Analyze Solidity file
myth analyze contracts/MyContract.sol

# Specific contract
myth analyze contracts/MyContract.sol --contract MyContract

# With remappings
myth analyze contracts/MyContract.sol --remappings "@openzeppelin=./lib/openzeppelin-contracts"

# Markdown output
myth analyze contracts/MyContract.sol -o markdown

# Increase analysis depth (default 22)
myth analyze contracts/MyContract.sol --execution-timeout 90 --max-depth 30

# Analyze deployed bytecode
myth analyze --address 0x... --rpc https://mainnet.infura.io/v3/...

# JSON output
myth analyze contracts/MyContract.sol -o json
```

**Output interpretation:**
- Uses symbolic execution + SMT solving
- Reports: SWC ID, severity, description, code location
- False positive rate ~10–20%
- Strong at: integer overflow, delegatecall injection, ether leakage, arbitrary writes
- Can be slow on complex contracts — use `--execution-timeout 60` to bound it

---

## Semgrep (Solidity rules)

**Install:** `pip install semgrep` or `brew install semgrep`

```bash
# Use official smart contract ruleset
semgrep --config=p/smart-contracts .

# Use Decurity's comprehensive Solidity rules
semgrep --config=https://github.com/Decurity/semgrep-smart-contracts .

# JSON output
semgrep --config=p/smart-contracts . --json --output semgrep-output.json

# SARIF output
semgrep --config=p/smart-contracts . --sarif --output semgrep.sarif

# Target specific files
semgrep --config=p/smart-contracts src/
```

**Output interpretation:**
- Pattern-based — high precision on specific anti-patterns
- Key rulesets: `p/smart-contracts`, Decurity Solidity rules, Trail of Bits rules
- Lower false positive rate than symbolic tools
- Strong at: DeFi-specific patterns, known anti-patterns, gas issues

---

## Solhint

**Install:** `npm install -g solhint`

```bash
# Initialize config
solhint --init

# Lint all Solidity files
solhint "src/**/*.sol"

# With specific rules
solhint "src/**/*.sol" --rules no-unused-vars,avoid-tx-origin

# JSON output
solhint "src/**/*.sol" --formatter json

# Auto-fix
solhint "src/**/*.sol" --fix
```

**Output interpretation:**
- Linting tool — not a vulnerability scanner
- Informational/Low severity only
- Strong at: style violations, best practice deviations, visibility modifiers

---

## Halmos (Symbolic Testing)

**Install:** `pip install halmos` or `uv tool install --python 3.12 halmos`

```bash
# Run all symbolic tests (uses existing Foundry test suite)
halmos

# Specific contract
halmos --contract MyContractTest

# With verbosity
halmos -vvv

# Loop unrolling bound (default 2)
halmos --loop 10

# Parallel workers
halmos --jobs 4
```

**Output interpretation:**
- Finds counterexamples for failing assertions in existing tests
- `[PASS]` = no counterexample found within bounds
- `[FAIL]` = counterexample found — this is a real bug
- `[TIMEOUT]` = could not determine within time limit
- Strong at: invariant violations, arithmetic properties, access control

---

## Echidna

**Install:** `brew install echidna` or download from GitHub releases

```bash
# Run property tests (requires echidna test contract)
echidna-test . --contract MyContractEchidnaTest --config echidna.yaml

# Without config
echidna-test . --contract MyContractEchidnaTest

# Corpus directory for reproducing
echidna-test . --contract MyContractEchidnaTest --corpus-dir corpus/

# JSON output
echidna-test . --contract MyContractEchidnaTest --format json
```

**Example echidna.yaml:**
```yaml
testLimit: 50000
seqLen: 100
workers: 4
coverage: true
corpusDir: "corpus"
```

**Test contract pattern:**
```solidity
contract MyContractEchidnaTest is MyContract {
    function echidna_balance_invariant() public returns (bool) {
        return totalSupply() == address(this).balance;
    }
}
```

---

## Medusa

**Install:** `brew install medusa` or `go install github.com/crytic/medusa/cmd/medusa@latest`

```bash
# Initialize config
medusa init

# Run fuzzing
medusa fuzz

# With specific config
medusa fuzz --config medusa.json
```

**Example medusa.json:**
```json
{
  "fuzzing": {
    "workers": 10,
    "testLimit": 0,
    "callSequenceLength": 100,
    "targetContracts": ["MyContractFuzzTest"],
    "coverageEnabled": true
  }
}
```

---

## Foundry (forge)

**Install:** `curl -L https://foundry.paradigm.xyz | bash && foundryup`

```bash
# Run all tests including fuzz
forge test -vvv

# Run invariant tests only
forge test --match-test "invariant" -vvv

# Increase fuzz runs
forge test --fuzz-runs 10000

# Run with fork
forge test --fork-url https://mainnet.infura.io/v3/... -vvv

# Coverage report
forge coverage

# Gas snapshot
forge snapshot

# Check storage layout
forge inspect MyContract storage-layout

# Check contract size
forge build --sizes

# Flatten contract (for Mythril)
forge flatten src/MyContract.sol
```

---

## Wake (Ackee Blockchain)

**Install:** `pip install eth-wake`

```bash
# Initialize
wake up

# Run built-in detectors
wake detect all

# Run tests
wake test

# LSP for VS Code
wake lsp
```

---

## Pyrometer

**Install:** Build from source (Rust)

```bash
git clone https://github.com/nascentxyz/pyrometer
cd pyrometer/crates/cli && cargo install --path .

# Analyze file
pyrometer contracts/MyContract.sol

# With remappings
pyrometer contracts/MyContract.sol --remappings "@oz=./lib/openzeppelin-contracts/contracts"
```

---

## Heimdall-rs (Bytecode Analysis)

**Install:** Via bifrost installer (see repo)

```bash
# Decompile deployed contract
heimdall decompile 0xContractAddress

# Recover ABI from bytecode
heimdall decode 0xContractAddress

# Disassemble
heimdall disassemble 0xContractAddress
```

**Use when:** Analyzing unverified contracts, checking bytecode matches source.

---

## Tool Matrix

| Tool | Speed | FP Rate | Best For |
|------|-------|---------|----------|
| Slither | Fast | Medium | Broad coverage, quick wins |
| Aderyn | Fast | Low | Access control, Cyfrin patterns |
| Mythril | Slow | Low-Med | Bytecode-level, arithmetic |
| Semgrep | Fast | Low | Known patterns, DeFi rules |
| Solhint | Fast | Low | Best practices |
| Halmos | Med | Near-zero | Invariant proofs |
| Echidna | Slow | Near-zero | Property violations |
| Medusa | Slow | Near-zero | Parallel fuzzing |
| Forge | Fast | Near-zero | Existing test suite |
| Wake | Med | Med | Python-based analysis |
