//! Error conversion helpers and parsing utilities for MCP tool implementations.

use std::borrow::Cow;

use alloy::primitives::{Address, FixedBytes, U256};
use rmcp::model::ErrorCode;
use rmcp::ErrorData;

/// Convert an [`erc8004::Error`] into an [`ErrorData`].
#[allow(clippy::needless_pass_by_value)]
pub fn to_mcp_error(err: erc8004::Error) -> ErrorData {
    ErrorData {
        code: ErrorCode(-32000),
        message: Cow::Owned(format!("{err}")),
        data: None,
    }
}

/// Parse a decimal string into a [`U256`].
///
/// # Errors
///
/// Returns an [`ErrorData`] if the string cannot be parsed.
pub fn parse_u256(s: &str) -> Result<U256, ErrorData> {
    U256::from_str_radix(s.trim(), 10).map_err(|e| ErrorData {
        code: ErrorCode(-32001),
        message: Cow::Owned(format!("invalid U256 decimal string '{s}': {e}")),
        data: None,
    })
}

/// Parse a hex string into an [`Address`].
///
/// # Errors
///
/// Returns an [`ErrorData`] if the string cannot be parsed.
pub fn parse_address(s: &str) -> Result<Address, ErrorData> {
    s.trim().parse::<Address>().map_err(|e| ErrorData {
        code: ErrorCode(-32001),
        message: Cow::Owned(format!("invalid address '{s}': {e}")),
        data: None,
    })
}

/// Parse a hex string into a [`FixedBytes<32>`].
///
/// # Errors
///
/// Returns an [`ErrorData`] if the string cannot be parsed.
pub fn parse_bytes32(s: &str) -> Result<FixedBytes<32>, ErrorData> {
    s.trim().parse::<FixedBytes<32>>().map_err(|e| ErrorData {
        code: ErrorCode(-32001),
        message: Cow::Owned(format!("invalid bytes32 hex '{s}': {e}")),
        data: None,
    })
}
