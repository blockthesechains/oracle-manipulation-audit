// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface ISpotPriceSource {
    /// @return price of ONE collateral token denominated in the stable asset (1e18 precision)
    function getPrice() external view returns (uint256);
}

/// @title LendingVaultVulnerable
/// @notice A collateralized lending vault: users deposit a collateral token and borrow a
///         stable asset against it, up to `collateralFactor`% of their collateral's value.
///
/// @dev    *** THIS CONTRACT IS INTENTIONALLY VULNERABLE — FOR SECURITY RESEARCH ONLY. ***
///         It is the "in-scope" target of the accompanying audit report. See audit-report.md.
///         Known issues (by design):
///           C-01  Price is read from a manipulable AMM spot source (oracle manipulation).
///           H-01  setCollateralFactor() has no access control.
///           M-01  ERC20 transfer/transferFrom return values are unchecked.
///           L-01  maxBorrow divides before multiplying (precision loss).
contract LendingVaultVulnerable {
    IERC20 public immutable collateralToken;
    IERC20 public immutable stableToken;
    ISpotPriceSource public immutable priceSource;

    address public owner;
    uint256 public collateralFactor = 50; // percent (0-100): borrow up to 50% of collateral value

    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(IERC20 _collateral, IERC20 _stable, ISpotPriceSource _priceSource) {
        collateralToken = _collateral;
        stableToken = _stable;
        priceSource = _priceSource;
        owner = msg.sender;
    }

    function deposit(uint256 amount) external {
        // M-01: return value ignored; a token that returns false on failure would be treated as success.
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        // C-01: spot price from an AMM is attacker-controllable within a single transaction
        //       (e.g. via a flash loan), so collateralValue can be inflated arbitrarily.
        uint256 price = priceSource.getPrice();
        uint256 collateralValue = (collateralOf[msg.sender] * price) / 1e18;

        // L-01: dividing by 100 before multiplying truncates, losing precision.
        uint256 maxBorrow = (collateralValue / 100) * collateralFactor;

        require(debtOf[msg.sender] + amount <= maxBorrow, "undercollateralized");

        debtOf[msg.sender] += amount;
        // M-01: unchecked return value.
        stableToken.transfer(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        require(debtOf[msg.sender] >= amount, "repay exceeds debt");
        stableToken.transferFrom(msg.sender, address(this), amount);
        debtOf[msg.sender] -= amount;
    }

    function withdraw(uint256 amount) external {
        require(collateralOf[msg.sender] >= amount, "insufficient collateral");
        uint256 price = priceSource.getPrice();
        uint256 remainingValue = ((collateralOf[msg.sender] - amount) * price) / 1e18;
        require(debtOf[msg.sender] <= (remainingValue / 100) * collateralFactor, "would be undercollateralized");
        collateralOf[msg.sender] -= amount;
        collateralToken.transfer(msg.sender, amount);
    }

    /// @notice H-01: NO ACCESS CONTROL. Anyone can change the collateral factor for the whole protocol.
    function setCollateralFactor(uint256 newFactor) external {
        collateralFactor = newFactor;
    }
}
