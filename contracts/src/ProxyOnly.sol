// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Enforces that functions are called through a proxy (delegatecall).
abstract contract ProxyOnly {
    address private immutable __self = address(this);

    modifier onlyProxyCall() {
        require(address(this) != __self, "ProxyOnly: direct call blocked");
        _;
    }
}

