// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {AggregatorV3Interface} from "../interfaces/AggregatorV3Interface.sol";

/// @notice Mock Chainlink price feed. Unlike the AMM, this is an independent, aggregated
///         data source: an attacker's in-transaction swaps do NOT move it, which is exactly
///         why the secured vault is immune to the flash-loan price manipulation.
contract MockV3Aggregator is AggregatorV3Interface {
    uint8 public override decimals;
    int256 public answer;
    uint256 public updatedAt;
    uint80 public roundId;

    constructor(uint8 _decimals, int256 _initialAnswer) {
        decimals = _decimals;
        _update(_initialAnswer);
    }

    function _update(int256 _answer) internal {
        answer = _answer;
        roundId += 1;
        updatedAt = block.timestamp;
    }

    /// @notice Test helper to push a new price / refresh the timestamp.
    function updateAnswer(int256 _answer) external {
        _update(_answer);
    }

    /// @notice Test helper to force a stale feed (old updatedAt) without changing the price.
    function setStale(uint256 _updatedAt) external {
        updatedAt = _updatedAt;
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (roundId, answer, updatedAt, updatedAt, roundId);
    }
}
