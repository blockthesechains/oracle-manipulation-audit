# Oracle Manipulation — Lending Vault Audit

A self-contained smart contract security study: a realistic collateralized lending vault, the
**price oracle manipulation** bug that drains it, a hardened rebuild, and a professional audit
report — every finding proven by a passing test.

> **The headline:** the vulnerable vault values collateral from an AMM **spot price**. An attacker
> deposits **1 WETH (~$2,000)**, spikes the pool price with a flash-loan-style swap, and borrows the
> vault's entire **$20,000** of liquidity. A **20× over-borrow** from a single manipulated number.

📄 **Read the full write-up: [`audit-report.md`](./audit-report.md)**

## Findings

| ID | Title | Severity |
|------|-------------------------------------------------|----------|
| C-01 | Collateral priced from a manipulable AMM spot source | Critical |
| H-01 | `setCollateralFactor` has no access control | High |
| M-01 | Unchecked ERC20 `transfer` / `transferFrom` return values | Medium |
| L-01 | Precision loss from divide-before-multiply | Low |

Each finding is reproduced in [`test/LendingVault.t.sol`](./test/LendingVault.t.sol) and remediated
in [`LendingVaultSecured.sol`](./contracts/LendingVaultSecured.sol).

## Layout

```
contracts/
  LendingVaultVulnerable.sol   # the audited target (intentionally vulnerable)
  LendingVaultSecured.sol      # hardened reference implementation
  interfaces/AggregatorV3Interface.sol
  mocks/
    MockERC20.sol
    MockAMM.sol                # manipulable spot "oracle"
    MockV3Aggregator.sol       # independent Chainlink-style feed
test/
  LendingVault.t.sol           # PoC: exploit works on vulnerable, fails on secured
audit-report.md                # the deliverable
```

## Run it

Requires [Foundry](https://book.getfoundry.sh/) (the industry-standard toolchain for smart
contract security).

```bash
# install dependencies (OpenZeppelin + forge-std)
forge install foundry-rs/forge-std openzeppelin/openzeppelin-contracts@v5.1.0

# run the suite
forge test -vv
```

Expected:

```
Ran 5 tests for test/LendingVault.t.sol:LendingVaultTest
[PASS] test_C01_OracleManipulation_DrainsVulnerableVault()
[PASS] test_C01_Remediated_SecuredVaultResistsManipulation()
[PASS] test_H01_AccessControl()
[PASS] test_Secured_HappyPathBorrowAndRepay()
[PASS] test_Secured_RejectsStalePrice()
Suite result: ok. 5 passed; 0 failed; 0 skipped
```

(CI runs this on every push — see `.github/workflows/test.yml`.)

## The takeaway

Oracle manipulation is one of the most damaging and common bug classes in DeFi. The root cause is
simple: **a price you can move in one transaction is not a price you can trust.** Collateral must be
valued from a decentralized, aggregated, and *validated* feed — never a DEX spot reading — and
every price response should be checked for staleness and sanity before a protocol trades on it.
