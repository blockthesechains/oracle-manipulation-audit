// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AggregatorV3Interface} from "./interfaces/AggregatorV3Interface.sol";

/// @title LendingVaultSecured
/// @notice Hardened version of LendingVaultVulnerable. Same economic behaviour, every finding
///         from the audit report remediated. See audit-report.md for the before/after.
///
/// Remediations:
///   C-01  Price comes from a Chainlink-style aggregated feed, with staleness & positivity
///         checks — not a manipulable AMM spot source.
///   H-01  setCollateralFactor() is onlyOwner and bounded by MAX_COLLATERAL_FACTOR.
///   M-01  All token movements use SafeERC20.
///   L-01  Borrow limit multiplies before dividing (no precision loss).
///   Defense-in-depth: ReentrancyGuard + checks-effects-interactions on state-changing calls.
contract LendingVaultSecured is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable collateralToken;
    IERC20 public immutable stableToken;
    AggregatorV3Interface public immutable priceFeed;

    uint256 public constant MAX_COLLATERAL_FACTOR = 90; // percent
    uint256 public constant STALENESS_THRESHOLD = 1 hours;

    uint256 public collateralFactor = 50; // percent (0-100)

    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(IERC20 _collateral, IERC20 _stable, AggregatorV3Interface _priceFeed)
        Ownable(msg.sender)
    {
        collateralToken = _collateral;
        stableToken = _stable;
        priceFeed = _priceFeed;
    }

    /// @notice Price of ONE collateral token in stable terms, normalized to 1e18.
    /// @dev Reverts on a non-positive or stale answer rather than trading on bad data.
    function _collateralPrice() internal view returns (uint256) {
        (, int256 answer,, uint256 updatedAt,) = priceFeed.latestRoundData();
        require(answer > 0, "invalid price");
        require(updatedAt != 0 && block.timestamp - updatedAt <= STALENESS_THRESHOLD, "stale price");
        return (uint256(answer) * 1e18) / (10 ** priceFeed.decimals());
    }

    function _maxBorrow(address user) internal view returns (uint256) {
        uint256 collateralValue = (collateralOf[user] * _collateralPrice()) / 1e18;
        // L-01 fix: multiply before dividing.
        return (collateralValue * collateralFactor) / 100;
    }

    function deposit(uint256 amount) external nonReentrant {
        collateralOf[msg.sender] += amount; // effects before interaction
        collateralToken.safeTransferFrom(msg.sender, address(this), amount);
    }

    function borrow(uint256 amount) external nonReentrant {
        require(debtOf[msg.sender] + amount <= _maxBorrow(msg.sender), "undercollateralized");
        debtOf[msg.sender] += amount; // effects
        stableToken.safeTransfer(msg.sender, amount); // interaction
    }

    function repay(uint256 amount) external nonReentrant {
        require(debtOf[msg.sender] >= amount, "repay exceeds debt");
        debtOf[msg.sender] -= amount; // effects
        stableToken.safeTransferFrom(msg.sender, address(this), amount); // interaction
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(collateralOf[msg.sender] >= amount, "insufficient collateral");
        collateralOf[msg.sender] -= amount; // effects
        require(debtOf[msg.sender] <= _maxBorrow(msg.sender), "would be undercollateralized");
        collateralToken.safeTransfer(msg.sender, amount); // interaction
    }

    /// @notice H-01 fix: onlyOwner and bounded.
    function setCollateralFactor(uint256 newFactor) external onlyOwner {
        require(newFactor <= MAX_COLLATERAL_FACTOR, "factor too high");
        collateralFactor = newFactor;
    }
}
