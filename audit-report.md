# Security Audit — SimpleLend Collateralized Lending Vault

**Auditor:** Anthony McElwee ([blockthesechains](https://github.com/blockthesechains))
**Target:** `LendingVaultVulnerable.sol`
**Commit scope:** `contracts/LendingVaultVulnerable.sol`, `contracts/mocks/*`
**Date:** October 2026
**Methodology:** Manual review + Foundry proof-of-concept tests

> **Disclaimer.** This is a self-directed security research exercise. The target contract was
> written to be intentionally vulnerable to demonstrate a realistic set of findings and their
> remediations. `LendingVaultSecured.sol` is the hardened reference implementation. Every finding
> below is reproduced by an automated test in `test/LendingVault.t.sol`.

---

## 1. Overview

SimpleLend is a single-asset collateralized lending vault. Users deposit a collateral token
(WETH) and borrow a stable asset (USD) against it, up to `collateralFactor`% of their collateral's
value. To value collateral, the vault must consult a price oracle.

The review found **1 Critical, 1 High, 1 Medium, and 1 Low** severity issue. The Critical issue
alone allows an attacker to drain the entire vault for a fraction of its value.

## 2. Severity classification

Severity is a function of **impact** (how bad is the outcome) and **likelihood** (how easy is it
to trigger).

| | Low impact | Medium impact | High impact |
|-----------------|-----------|---------------|-------------|
| **High likelihood** | Medium | High | Critical |
| **Medium likelihood** | Low | Medium | High |
| **Low likelihood** | Low | Low | Medium |

## 3. Findings summary

| ID | Title | Severity | Status |
|------|-------------------------------------------------|----------|------------|
| C-01 | Collateral priced from a manipulable AMM spot source | Critical | ✅ Fixed |
| H-01 | `setCollateralFactor` has no access control | High | ✅ Fixed |
| M-01 | Unchecked ERC20 `transfer` / `transferFrom` return values | Medium | ✅ Fixed |
| L-01 | Precision loss from divide-before-multiply in borrow limit | Low | ✅ Fixed |

---

## 4. Detailed findings

### C-01 — Collateral priced from a manipulable AMM spot source  · Critical

**Location:** `LendingVaultVulnerable.borrow()` → `priceSource.getPrice()`

**Description.**
The vault derives collateral value from the *spot* reserves of an AMM pool:

```solidity
uint256 price = priceSource.getPrice();                       // reserveStable / reserveCollateral
uint256 collateralValue = (collateralOf[msg.sender] * price) / 1e18;
uint256 maxBorrow = (collateralValue / 100) * collateralFactor;
require(debtOf[msg.sender] + amount <= maxBorrow, "undercollateralized");
```

An AMM spot price is just a ratio of current reserves, and **anyone can move those reserves inside
a single transaction** by swapping — classically funded by a flash loan, which requires no upfront
capital. Because the borrow check reads this spot value, an attacker can inflate their apparent
collateral value to any number they like and borrow against the lie.

**Impact.**
Total loss of vault funds. In the PoC, an attacker deposits **1 WETH (true value ≈ 2,000 USD)**,
spikes the pool's spot price with a large swap, and borrows the vault's entire **20,000 USD** of
liquidity — a **20× over-borrow** — then walks away. Realized loss ≈ 18,000 USD per 2,000 USD
of attacker collateral.

**Proof of Concept.** `test_C01_OracleManipulation_DrainsVulnerableVault`:

```
Collateral deposited (USD value): 2000.0
Fair borrow limit:                1000.0
Actually borrowed (stolen):       20000.0
Vault USD balance after:          0
```

**Recommendation.**
Never use a DEX spot price as an oracle. Use a decentralized, aggregated price feed
(e.g. Chainlink) and **validate the response**: reject non-positive answers and reject prices older
than a staleness threshold. If an on-chain source is unavoidable, use a manipulation-resistant TWAP
over a sufficient window. The hardened vault does the former:

```solidity
(, int256 answer,, uint256 updatedAt,) = priceFeed.latestRoundData();
require(answer > 0, "invalid price");
require(updatedAt != 0 && block.timestamp - updatedAt <= STALENESS_THRESHOLD, "stale price");
return (uint256(answer) * 1e18) / (10 ** priceFeed.decimals());
```

Verified by `test_C01_Remediated_SecuredVaultResistsManipulation` (the same attack is rejected) and
`test_Secured_RejectsStalePrice`.

---

### H-01 — `setCollateralFactor` has no access control  · High

**Location:** `LendingVaultVulnerable.setCollateralFactor()`

**Description.**
A core risk parameter is writable by anyone:

```solidity
function setCollateralFactor(uint256 newFactor) external {
    collateralFactor = newFactor;
}
```

**Impact.**
Any user can raise the collateral factor arbitrarily (e.g. to 1000%), making every position wildly
over-leveraged and letting borrowers extract far more than their collateral is worth — a second,
independent path to draining the vault. It also enables griefing of liquidations.

**Proof of Concept.** `test_H01_AccessControl` — `attacker` sets `collateralFactor` to 100 with no
revert.

**Recommendation.**
Restrict the setter to a trusted owner/governance role and bound the value:

```solidity
function setCollateralFactor(uint256 newFactor) external onlyOwner {
    require(newFactor <= MAX_COLLATERAL_FACTOR, "factor too high");
    collateralFactor = newFactor;
}
```

Verified by `test_H01_AccessControl` (non-owner reverts with `OwnableUnauthorizedAccount`; owner
cannot exceed `MAX_COLLATERAL_FACTOR`).

---

### M-01 — Unchecked ERC20 `transfer` / `transferFrom` return values  · Medium

**Location:** `deposit()`, `borrow()`, `withdraw()`

**Description.**
Token movements ignore the boolean return value:

```solidity
collateralToken.transferFrom(msg.sender, address(this), amount); // return ignored
stableToken.transfer(msg.sender, amount);                        // return ignored
```

Some widely-used tokens (e.g. USDT, BNB, ZRX) do not revert on failure and/or do not return a
`bool`. Against such tokens a "failed" transfer is silently treated as success, corrupting the
vault's accounting (e.g. crediting collateral that never arrived).

**Impact.**
Accounting divergence from actual balances, up to loss of funds, depending on the token in use.
Rated Medium as it is contingent on the deployed token's conformance.

**Recommendation.**
Use OpenZeppelin `SafeERC20` (`safeTransfer` / `safeTransferFrom`), which reverts on failure and
tolerates non-standard return data. Applied throughout `LendingVaultSecured`.

---

### L-01 — Precision loss from divide-before-multiply in borrow limit  · Low

**Location:** `borrow()`, `withdraw()`

**Description.**

```solidity
uint256 maxBorrow = (collateralValue / 100) * collateralFactor;
```

Dividing by 100 before multiplying truncates up to 99 wei of value *before* it is scaled by
`collateralFactor`, so the computed borrow limit is slightly lower than intended.

**Impact.**
Minor, rounding-scale value error that is systematically unfavorable to users. No direct theft, but
incorrect math in a financial primitive should be fixed.

**Recommendation.**
Multiply before dividing:

```solidity
return (collateralValue * collateralFactor) / 100;
```

Applied in `LendingVaultSecured._maxBorrow`.

---

## 5. Remediation summary

| Finding | Fix in `LendingVaultSecured.sol` |
|---------|----------------------------------|
| C-01 | Chainlink-style aggregated feed with positivity + staleness checks |
| H-01 | `onlyOwner` + `MAX_COLLATERAL_FACTOR` bound |
| M-01 | `SafeERC20` for all token movements |
| L-01 | Multiply-before-divide in the borrow-limit calculation |
| Defense-in-depth | `ReentrancyGuard` + checks-effects-interactions ordering |

## 6. Test results

```
Ran 5 tests for test/LendingVault.t.sol:LendingVaultTest
[PASS] test_C01_OracleManipulation_DrainsVulnerableVault()
[PASS] test_C01_Remediated_SecuredVaultResistsManipulation()
[PASS] test_H01_AccessControl()
[PASS] test_Secured_HappyPathBorrowAndRepay()
[PASS] test_Secured_RejectsStalePrice()
Suite result: ok. 5 passed; 0 failed; 0 skipped
```
