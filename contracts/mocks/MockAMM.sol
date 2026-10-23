// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice A minimal Uniswap-style constant-product pool (collateral <> stable).
/// @dev The vulnerable vault (mis)uses this pool's *spot* reserves as a price oracle.
///      Because anyone can swap and move the reserves within a single transaction
///      (e.g. funded by a flash loan), the spot price is trivially manipulable.
contract MockAMM {
    uint256 public reserveCollateral; // units of collateral token (18 dp)
    uint256 public reserveStable; // units of stable token (18 dp)

    constructor(uint256 _reserveCollateral, uint256 _reserveStable) {
        reserveCollateral = _reserveCollateral;
        reserveStable = _reserveStable;
    }

    /// @notice Spot price of ONE collateral token, denominated in stable (1e18 precision).
    function getPrice() external view returns (uint256) {
        return (reserveStable * 1e18) / reserveCollateral;
    }

    /// @notice Swap `stableIn` into the pool, receiving collateral out (constant product, no fee).
    /// @dev Pushing stable in and pulling collateral out RAISES reserveStable and LOWERS
    ///      reserveCollateral, so getPrice() (stable/collateral) spikes upward. This is the
    ///      lever an attacker pulls to inflate the apparent collateral price.
    function swapStableForCollateral(uint256 stableIn) external returns (uint256 collateralOut) {
        uint256 k = reserveCollateral * reserveStable;
        uint256 newStable = reserveStable + stableIn;
        uint256 newCollateral = k / newStable;
        collateralOut = reserveCollateral - newCollateral;
        reserveStable = newStable;
        reserveCollateral = newCollateral;
    }
}
