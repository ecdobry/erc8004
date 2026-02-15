//! MCP server struct, tool definitions, and `ServerHandler` implementation.

use std::borrow::Cow;
use std::sync::Arc;

use alloy::primitives::{Bytes, U256, address};
use alloy::providers::DynProvider;
use alloy::sol;
use alloy::sol_types::SolCall;
use erc8004::Erc8004;
use erc8004::contracts::IdentityRegistry;
use rmcp::handler::server::tool::{ToolCallContext, ToolRouter};
use rmcp::model::{
    CallToolRequestParam, CallToolResult, Implementation, InitializeRequestParam,
    InitializeResult, ListToolsResult, PaginatedRequestParam, ProtocolVersion,
    ServerCapabilities, ToolsCapability,
};
use rmcp::schemars::JsonSchema;
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, Json, ServerHandler, tool, tool_router};
use serde::{Deserialize, Serialize};

use crate::error::{
    http_error, json_parse_error, parse_address, parse_bytes32, parse_u256,
    to_mcp_error,
};

sol! {
    /// Multicall3 — batch multiple `eth_call` into a single RPC round-trip.
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 {
            address target;
            bool allowFailure;
            bytes callData;
        }
        struct Result {
            bool success;
            bytes returnData;
        }
        function aggregate3(
            Call3[] calldata calls
        ) external payable returns (Result[] memory returnData);
    }
}

/// Standard Multicall3 deployment address (same on all EVM chains).
const MULTICALL3_ADDRESS: alloy::primitives::Address =
    address!("cA11bde05977b3631167028862bE2a173976CA11");

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

type Parameters<T> = rmcp::handler::server::tool::Parameters<T>;

/// The ERC-8004 MCP server.
#[derive(Clone)]
pub struct Erc8004McpServer {
    client: Arc<Erc8004<DynProvider>>,
    has_signer: bool,
    network_name: String,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl Erc8004McpServer {
    /// Create a new MCP server wrapping the given ERC-8004 client.
    #[must_use]
    pub fn new(client: Erc8004<DynProvider>, has_signer: bool, network_name: String) -> Self {
        let tool_router = Self::tool_router();
        Self {
            client: Arc::new(client),
            has_signer,
            network_name,
            tool_router,
        }
    }

    /// Return an error if no signer (private key) was configured.
    const fn require_signer(&self) -> Result<(), ErrorData> {
        if self.has_signer {
            Ok(())
        } else {
            Err(ErrorData {
                code: rmcp::model::ErrorCode(-32002),
                message: Cow::Borrowed(
                    "This tool requires a signer. Start the server with --private-key.",
                ),
                data: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

// -- Identity Read --

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AgentIdRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VersionResponse {
    /// The contract version string.
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OwnerOfResponse {
    /// The owner address (0x-prefixed hex).
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TokenUriResponse {
    /// The agent URI string.
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AgentWalletResponse {
    /// The agent wallet address (0x-prefixed hex).
    pub wallet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetMetadataRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// The metadata key.
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetMetadataResponse {
    /// The metadata value (hex-encoded bytes).
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IsAuthorizedRequest {
    /// The spender address (0x-prefixed hex).
    pub spender: String,
    /// The agent ID (decimal string).
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IsAuthorizedResponse {
    /// Whether the spender is the owner or approved.
    pub authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BalanceOfRequest {
    /// The owner address (0x-prefixed hex).
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BalanceOfResponse {
    /// The token balance (decimal string).
    pub balance: String,
}

// -- Identity Write --

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterResponse {
    /// The newly minted agent ID (decimal string).
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterWithUriRequest {
    /// The agent URI to set during registration.
    pub agent_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetAgentUriRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// The new URI to set.
    pub new_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetMetadataRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// The metadata key.
    pub key: String,
    /// The metadata value (hex-encoded bytes).
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuccessResponse {
    /// Whether the operation succeeded.
    pub success: bool,
}

// -- Reputation Read --

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetSummaryRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// Client addresses to filter by (0x-prefixed hex).
    pub client_addresses: Vec<String>,
    /// Primary categorization tag.
    #[serde(default)]
    pub tag1: String,
    /// Secondary categorization tag.
    #[serde(default)]
    pub tag2: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReputationSummaryResponse {
    /// Number of non-revoked feedback entries.
    pub count: u64,
    /// Aggregated value (as string for precision).
    pub summary_value: String,
    /// Decimal places for the summary value.
    pub summary_value_decimals: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReadFeedbackRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// The client address (0x-prefixed hex).
    pub client_address: String,
    /// The feedback index.
    pub feedback_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FeedbackResponse {
    /// Feedback value (as string for precision).
    pub value: String,
    /// Decimal places for the value.
    pub value_decimals: u8,
    /// Primary categorization tag.
    pub tag1: String,
    /// Secondary categorization tag.
    pub tag2: String,
    /// Whether the feedback has been revoked.
    pub is_revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetClientsResponse {
    /// List of client addresses that have submitted feedback.
    pub clients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetLastIndexRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// The client address (0x-prefixed hex).
    pub client_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetLastIndexResponse {
    /// The last feedback index for this client-agent pair.
    pub last_index: u64,
}

// -- Reputation Write --

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GiveFeedbackRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// Signed feedback value (integer, as string).
    pub value: String,
    /// Decimal places for the value.
    pub value_decimals: u8,
    /// Primary categorization tag.
    #[serde(default)]
    pub tag1: String,
    /// Secondary categorization tag.
    #[serde(default)]
    pub tag2: String,
    /// The endpoint this feedback relates to.
    #[serde(default)]
    pub endpoint: String,
    /// URI pointing to off-chain feedback details.
    #[serde(default)]
    pub feedback_uri: String,
    /// Keccak-256 hash of the feedback URI content (0x-prefixed hex, 32 bytes).
    #[serde(default)]
    pub feedback_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RevokeFeedbackRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// The feedback index to revoke.
    pub feedback_index: u64,
}

// -- Validation Read --

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetValidationStatusRequest {
    /// The request hash (0x-prefixed hex, 32 bytes).
    pub request_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ValidationStatusResponse {
    /// Validator address (0x-prefixed hex).
    pub validator_address: String,
    /// Agent ID (decimal string).
    pub agent_id: String,
    /// Response score (0-100).
    pub response: u8,
    /// Response hash (0x-prefixed hex, 32 bytes).
    pub response_hash: String,
    /// Categorization tag.
    pub tag: String,
    /// Block timestamp of last update (decimal string).
    pub last_update: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetValidationSummaryRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// Validator addresses to filter by (0x-prefixed hex).
    #[serde(default)]
    pub validator_addresses: Vec<String>,
    /// Categorization tag filter.
    #[serde(default)]
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ValidationSummaryResponse {
    /// Number of validation responses.
    pub count: u64,
    /// Average response score (0-100).
    pub avg_response: u8,
}

// -- Identity Exploration --

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanAgentsRequest {
    /// Start agent ID (decimal string, inclusive).
    pub start_id: String,
    /// End agent ID (decimal string, inclusive). Max range is 100.
    pub end_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScannedAgent {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// The owner address (0x-prefixed hex).
    pub owner: String,
    /// The agent URI string.
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanAgentsResponse {
    /// Agents found in the scanned range.
    pub agents: Vec<ScannedAgent>,
    /// Number of IDs probed.
    pub scanned: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegistrationFileResponse {
    /// Registration file type URI.
    #[serde(rename = "type")]
    pub type_field: String,
    /// Agent name.
    pub name: String,
    /// Agent description.
    pub description: String,
    /// Agent image URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Service endpoints.
    pub services: Vec<ServiceEndpointResponse>,
    /// Whether the agent supports x402.
    pub x402_support: bool,
    /// Whether the agent is active.
    pub active: bool,
    /// On-chain registrations.
    pub registrations: Vec<RegistrationResponse>,
    /// Supported trust frameworks.
    pub supported_trust: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServiceEndpointResponse {
    /// Service protocol name (A2A, MCP, etc.).
    pub name: String,
    /// Service endpoint URL.
    pub endpoint: String,
    /// Protocol version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Agent skills.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills: Option<Vec<String>>,
    /// Agent domains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegistrationResponse {
    /// On-chain agent ID.
    pub agent_id: u64,
    /// Registry identifier (namespace:chainId:address).
    pub agent_registry: String,
}

// -- Reputation Exploration --

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReadAllFeedbackRequest {
    /// The agent ID (decimal string).
    pub agent_id: String,
    /// Client addresses to filter by (0x-prefixed hex). Empty = all.
    #[serde(default)]
    pub client_addresses: Vec<String>,
    /// Primary categorization tag filter.
    #[serde(default)]
    pub tag1: String,
    /// Secondary categorization tag filter.
    #[serde(default)]
    pub tag2: String,
    /// Whether to include revoked feedback entries.
    #[serde(default)]
    pub include_revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllFeedbackEntry {
    /// Client address (0x-prefixed hex).
    pub client: String,
    /// Feedback index for this client.
    pub feedback_index: u64,
    /// Feedback value (as string for precision).
    pub value: String,
    /// Decimal places for the value.
    pub value_decimals: u8,
    /// Primary categorization tag.
    pub tag1: String,
    /// Secondary categorization tag.
    pub tag2: String,
    /// Whether the feedback has been revoked.
    pub is_revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllFeedbackResponse {
    /// All feedback entries matching the filter.
    pub entries: Vec<AllFeedbackEntry>,
}

// -- Validation Exploration --

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ValidationHashesResponse {
    /// Validation request hashes (0x-prefixed hex, 32 bytes each).
    pub request_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetValidatorRequestsRequest {
    /// The validator address (0x-prefixed hex).
    pub validator_address: String,
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[tool_router]
impl Erc8004McpServer {
    // -----------------------------------------------------------------------
    // Identity Registry - Read
    // -----------------------------------------------------------------------

    #[tool(description = "Get the Identity Registry contract version string.")]
    async fn identity_get_version(&self) -> Result<Json<VersionResponse>, ErrorData> {
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let version = identity.get_version().await.map_err(to_mcp_error)?;
        Ok(Json(VersionResponse { version }))
    }

    #[tool(description = "Get the owner address of an agent by its on-chain ID.")]
    async fn identity_owner_of(
        &self,
        params: Parameters<AgentIdRequest>,
    ) -> Result<Json<OwnerOfResponse>, ErrorData> {
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let owner = identity.owner_of(agent_id).await.map_err(to_mcp_error)?;
        Ok(Json(OwnerOfResponse {
            owner: format!("{owner:#}"),
        }))
    }

    #[tool(description = "Get the agent URI (tokenURI) for an agent.")]
    async fn identity_token_uri(
        &self,
        params: Parameters<AgentIdRequest>,
    ) -> Result<Json<TokenUriResponse>, ErrorData> {
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let uri = identity.token_uri(agent_id).await.map_err(to_mcp_error)?;
        Ok(Json(TokenUriResponse { uri }))
    }

    #[tool(description = "Get the agent wallet address for an agent.")]
    async fn identity_get_agent_wallet(
        &self,
        params: Parameters<AgentIdRequest>,
    ) -> Result<Json<AgentWalletResponse>, ErrorData> {
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let wallet = identity
            .get_agent_wallet(agent_id)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(AgentWalletResponse {
            wallet: format!("{wallet:#}"),
        }))
    }

    #[tool(description = "Get a metadata value by key for an agent.")]
    async fn identity_get_metadata(
        &self,
        params: Parameters<GetMetadataRequest>,
    ) -> Result<Json<GetMetadataResponse>, ErrorData> {
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let value = identity
            .get_metadata(agent_id, &params.0.key)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(GetMetadataResponse {
            value: format!("{value}"),
        }))
    }

    #[tool(
        description = "Check whether a spender is the owner or an approved operator for an agent."
    )]
    async fn identity_is_authorized(
        &self,
        params: Parameters<IsAuthorizedRequest>,
    ) -> Result<Json<IsAuthorizedResponse>, ErrorData> {
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let spender = parse_address(&params.0.spender)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let authorized = identity
            .is_authorized_or_owner(spender, agent_id)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(IsAuthorizedResponse { authorized }))
    }

    #[tool(description = "Get the number of agents (ERC-721 tokens) owned by an address.")]
    async fn identity_balance_of(
        &self,
        params: Parameters<BalanceOfRequest>,
    ) -> Result<Json<BalanceOfResponse>, ErrorData> {
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let owner = parse_address(&params.0.owner)?;
        let balance = identity.balance_of(owner).await.map_err(to_mcp_error)?;
        Ok(Json(BalanceOfResponse {
            balance: balance.to_string(),
        }))
    }

    // -----------------------------------------------------------------------
    // Identity Registry - Write
    // -----------------------------------------------------------------------

    #[tool(description = "Register a new agent (no URI). Requires a signer (--private-key).")]
    async fn identity_register(&self) -> Result<Json<RegisterResponse>, ErrorData> {
        self.require_signer()?;
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = identity.register().await.map_err(to_mcp_error)?;
        Ok(Json(RegisterResponse {
            agent_id: agent_id.to_string(),
        }))
    }

    #[tool(
        description = "Register a new agent with a URI. Requires a signer (--private-key)."
    )]
    async fn identity_register_with_uri(
        &self,
        params: Parameters<RegisterWithUriRequest>,
    ) -> Result<Json<RegisterResponse>, ErrorData> {
        self.require_signer()?;
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = identity
            .register_with_uri(&params.0.agent_uri)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(RegisterResponse {
            agent_id: agent_id.to_string(),
        }))
    }

    #[tool(description = "Update the URI for an existing agent. Requires a signer (--private-key).")]
    async fn identity_set_agent_uri(
        &self,
        params: Parameters<SetAgentUriRequest>,
    ) -> Result<Json<SuccessResponse>, ErrorData> {
        self.require_signer()?;
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        identity
            .set_agent_uri(agent_id, &params.0.new_uri)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(SuccessResponse { success: true }))
    }

    #[tool(
        description = "Set a metadata key-value pair for an agent. Value is hex-encoded bytes. Requires a signer (--private-key)."
    )]
    async fn identity_set_metadata(
        &self,
        params: Parameters<SetMetadataRequest>,
    ) -> Result<Json<SuccessResponse>, ErrorData> {
        self.require_signer()?;
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let value_bytes: Bytes = params.0.value.parse().map_err(|e| ErrorData {
            code: rmcp::model::ErrorCode(-32001),
            message: Cow::Owned(format!("invalid hex value: {e}")),
            data: None,
        })?;
        identity
            .set_metadata(agent_id, &params.0.key, value_bytes)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(SuccessResponse { success: true }))
    }

    // -----------------------------------------------------------------------
    // Reputation Registry - Read
    // -----------------------------------------------------------------------

    #[tool(description = "Get an aggregated reputation summary for an agent. Client addresses \
                          should be provided to avoid Sybil/spam (per ERC-8004 spec).")]
    async fn reputation_get_summary(
        &self,
        params: Parameters<GetSummaryRequest>,
    ) -> Result<Json<ReputationSummaryResponse>, ErrorData> {
        let reputation = self.client.reputation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let client_addresses = params
            .0
            .client_addresses
            .iter()
            .map(|s| parse_address(s))
            .collect::<Result<Vec<_>, _>>()?;
        let summary = reputation
            .get_summary(agent_id, client_addresses, &params.0.tag1, &params.0.tag2)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(ReputationSummaryResponse {
            count: summary.count,
            summary_value: summary.summary_value.to_string(),
            summary_value_decimals: summary.summary_value_decimals,
        }))
    }

    #[tool(description = "Read a single feedback entry for an agent from a specific client.")]
    async fn reputation_read_feedback(
        &self,
        params: Parameters<ReadFeedbackRequest>,
    ) -> Result<Json<FeedbackResponse>, ErrorData> {
        let reputation = self.client.reputation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let client_address = parse_address(&params.0.client_address)?;
        let feedback = reputation
            .read_feedback(agent_id, client_address, params.0.feedback_index)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(FeedbackResponse {
            value: feedback.value.to_string(),
            value_decimals: feedback.value_decimals,
            tag1: feedback.tag1,
            tag2: feedback.tag2,
            is_revoked: feedback.is_revoked,
        }))
    }

    #[tool(description = "Get all client addresses that have submitted feedback for an agent.")]
    async fn reputation_get_clients(
        &self,
        params: Parameters<AgentIdRequest>,
    ) -> Result<Json<GetClientsResponse>, ErrorData> {
        let reputation = self.client.reputation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let clients = reputation
            .get_clients(agent_id)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(GetClientsResponse {
            clients: clients.iter().map(|a| format!("{a:#}")).collect(),
        }))
    }

    #[tool(
        description = "Get the last feedback index for a specific client-agent pair."
    )]
    async fn reputation_get_last_index(
        &self,
        params: Parameters<GetLastIndexRequest>,
    ) -> Result<Json<GetLastIndexResponse>, ErrorData> {
        let reputation = self.client.reputation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let client_address = parse_address(&params.0.client_address)?;
        let last_index = reputation
            .get_last_index(agent_id, client_address)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(GetLastIndexResponse { last_index }))
    }

    #[tool(description = "Get the Reputation Registry contract version string.")]
    async fn reputation_get_version(&self) -> Result<Json<VersionResponse>, ErrorData> {
        let reputation = self.client.reputation().map_err(to_mcp_error)?;
        let version = reputation.get_version().await.map_err(to_mcp_error)?;
        Ok(Json(VersionResponse { version }))
    }

    // -----------------------------------------------------------------------
    // Reputation Registry - Write
    // -----------------------------------------------------------------------

    #[tool(
        description = "Submit feedback for an agent. Requires a signer (--private-key). \
                       The feedback_hash should be the keccak256 of the feedback_uri content, \
                       or 0x0...0 if not applicable."
    )]
    async fn reputation_give_feedback(
        &self,
        params: Parameters<GiveFeedbackRequest>,
    ) -> Result<Json<SuccessResponse>, ErrorData> {
        self.require_signer()?;
        let reputation = self.client.reputation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let value: i128 = params.0.value.trim().parse().map_err(|e| ErrorData {
            code: rmcp::model::ErrorCode(-32001),
            message: Cow::Owned(format!("invalid i128 value '{}': {e}", params.0.value)),
            data: None,
        })?;
        let feedback_hash = if params.0.feedback_hash.is_empty() {
            alloy::primitives::FixedBytes::ZERO
        } else {
            parse_bytes32(&params.0.feedback_hash)?
        };
        reputation
            .give_feedback(
                agent_id,
                value,
                params.0.value_decimals,
                &params.0.tag1,
                &params.0.tag2,
                &params.0.endpoint,
                &params.0.feedback_uri,
                feedback_hash,
            )
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(SuccessResponse { success: true }))
    }

    #[tool(
        description = "Revoke previously submitted feedback. Must be called by the original feedback submitter. Requires a signer (--private-key)."
    )]
    async fn reputation_revoke_feedback(
        &self,
        params: Parameters<RevokeFeedbackRequest>,
    ) -> Result<Json<SuccessResponse>, ErrorData> {
        self.require_signer()?;
        let reputation = self.client.reputation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        reputation
            .revoke_feedback(agent_id, params.0.feedback_index)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(SuccessResponse { success: true }))
    }

    // -----------------------------------------------------------------------
    // Validation Registry - Read
    // -----------------------------------------------------------------------

    #[tool(
        description = "Get the current status of a validation request by its hash. Requires --validation-address."
    )]
    async fn validation_get_status(
        &self,
        params: Parameters<GetValidationStatusRequest>,
    ) -> Result<Json<ValidationStatusResponse>, ErrorData> {
        let validation = self.client.validation().map_err(to_mcp_error)?;
        let request_hash = parse_bytes32(&params.0.request_hash)?;
        let status = validation
            .get_validation_status(request_hash)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(ValidationStatusResponse {
            validator_address: format!("{:#}", status.validator_address),
            agent_id: status.agent_id.to_string(),
            response: status.response,
            response_hash: format!("{}", status.response_hash),
            tag: status.tag,
            last_update: status.last_update.to_string(),
        }))
    }

    #[tool(
        description = "Get an aggregated validation summary for an agent. Requires --validation-address."
    )]
    async fn validation_get_summary(
        &self,
        params: Parameters<GetValidationSummaryRequest>,
    ) -> Result<Json<ValidationSummaryResponse>, ErrorData> {
        let validation = self.client.validation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let validator_addresses = params
            .0
            .validator_addresses
            .iter()
            .map(|s| parse_address(s))
            .collect::<Result<Vec<_>, _>>()?;
        let summary = validation
            .get_summary(agent_id, validator_addresses, &params.0.tag)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(ValidationSummaryResponse {
            count: summary.count,
            avg_response: summary.avg_response,
        }))
    }

    #[tool(
        description = "List all validation request hashes for an agent. \
                       Requires --validation-address."
    )]
    async fn validation_get_agent_validations(
        &self,
        params: Parameters<AgentIdRequest>,
    ) -> Result<Json<ValidationHashesResponse>, ErrorData> {
        let validation = self.client.validation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let hashes = validation
            .get_agent_validations(agent_id)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(ValidationHashesResponse {
            request_hashes: hashes.iter().map(|h| format!("{h}")).collect(),
        }))
    }

    #[tool(
        description = "List all validation request hashes for a validator. \
                       Requires --validation-address."
    )]
    async fn validation_get_validator_requests(
        &self,
        params: Parameters<GetValidatorRequestsRequest>,
    ) -> Result<Json<ValidationHashesResponse>, ErrorData> {
        let validation = self.client.validation().map_err(to_mcp_error)?;
        let validator_address = parse_address(&params.0.validator_address)?;
        let hashes = validation
            .get_validator_requests(validator_address)
            .await
            .map_err(to_mcp_error)?;
        Ok(Json(ValidationHashesResponse {
            request_hashes: hashes.iter().map(|h| format!("{h}")).collect(),
        }))
    }

    // -----------------------------------------------------------------------
    // Reputation Registry - Exploration
    // -----------------------------------------------------------------------

    #[tool(
        description = "Batch read all feedback for an agent with optional \
                       client, tag, and revoked filters."
    )]
    async fn reputation_read_all_feedback(
        &self,
        params: Parameters<ReadAllFeedbackRequest>,
    ) -> Result<Json<AllFeedbackResponse>, ErrorData> {
        let reputation = self.client.reputation().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let client_addresses = params
            .0
            .client_addresses
            .iter()
            .map(|s| parse_address(s))
            .collect::<Result<Vec<_>, _>>()?;
        let raw = reputation
            .read_all_feedback(
                agent_id,
                client_addresses,
                &params.0.tag1,
                &params.0.tag2,
                params.0.include_revoked,
            )
            .await
            .map_err(to_mcp_error)?;
        let entries = raw
            .clients
            .into_iter()
            .zip(raw.feedbackIndexes)
            .zip(raw.values)
            .zip(raw.valueDecimals)
            .zip(raw.tag1s)
            .zip(raw.tag2s)
            .zip(raw.revokedStatuses)
            .map(
                |((((((client, idx), val), dec), t1), t2), revoked)| {
                    AllFeedbackEntry {
                        client: format!("{client:#}"),
                        feedback_index: idx,
                        value: val.to_string(),
                        value_decimals: dec,
                        tag1: t1,
                        tag2: t2,
                        is_revoked: revoked,
                    }
                },
            )
            .collect();
        Ok(Json(AllFeedbackResponse { entries }))
    }

    // -----------------------------------------------------------------------
    // Identity Registry - Exploration
    // -----------------------------------------------------------------------

    #[tool(
        description = "Probe a range of agent IDs (max 100), returning \
                       owner + URI for each existing agent."
    )]
    async fn identity_scan_agents(
        &self,
        params: Parameters<ScanAgentsRequest>,
    ) -> Result<Json<ScanAgentsResponse>, ErrorData> {
        let start = parse_u256(&params.0.start_id)?;
        let end = parse_u256(&params.0.end_id)?;
        if end < start {
            return Err(ErrorData {
                code: rmcp::model::ErrorCode(-32001),
                message: Cow::Borrowed("end_id must be >= start_id"),
                data: None,
            });
        }
        let range_size = end - start + U256::from(1);
        if range_size > U256::from(100) {
            return Err(ErrorData {
                code: rmcp::model::ErrorCode(-32001),
                message: Cow::Borrowed(
                    "range too large: max 100 IDs per scan",
                ),
                data: None,
            });
        }
        let scanned: u64 = range_size.try_into().map_err(|_| ErrorData {
            code: rmcp::model::ErrorCode(-32001),
            message: Cow::Borrowed("range overflow"),
            data: None,
        })?;
        let identity_address =
            self.client.identity_address().ok_or(ErrorData {
                code: rmcp::model::ErrorCode(-32000),
                message: Cow::Borrowed(
                    "identity registry not configured",
                ),
                data: None,
            })?;

        // Build Multicall3 batch: ownerOf + tokenURI per ID
        let ids: Vec<U256> = (0..scanned)
            .map(|offset| start + U256::from(offset))
            .collect();
        let calls: Vec<Multicall3::Call3> = ids
            .iter()
            .flat_map(|&id| {
                let owner_data =
                    IdentityRegistry::ownerOfCall { tokenId: id }
                        .abi_encode();
                let uri_data =
                    IdentityRegistry::tokenURICall { tokenId: id }
                        .abi_encode();
                [
                    Multicall3::Call3 {
                        target: identity_address,
                        allowFailure: true,
                        callData: owner_data.into(),
                    },
                    Multicall3::Call3 {
                        target: identity_address,
                        allowFailure: true,
                        callData: uri_data.into(),
                    },
                ]
            })
            .collect();

        let multicall =
            Multicall3::new(MULTICALL3_ADDRESS, self.client.provider());
        let results = multicall
            .aggregate3(calls)
            .call()
            .await
            .map_err(|e| to_mcp_error(e.into()))?;

        // Decode pairs of (ownerOf result, tokenURI result)
        let agents = ids
            .iter()
            .zip(results.chunks(2))
            .filter_map(|(id, chunk): (&U256, &[Multicall3::Result])| {
                let owner_res = &chunk[0];
                if !owner_res.success {
                    return None;
                }
                let owner: alloy::primitives::Address =
                    IdentityRegistry::ownerOfCall::abi_decode_returns(
                        &owner_res.returnData,
                    )
                    .ok()?;
                let uri: String = chunk
                    .get(1)
                    .filter(|r| r.success)
                    .and_then(|r| {
                        IdentityRegistry::tokenURICall::abi_decode_returns(
                            &r.returnData,
                        )
                        .ok()
                    })
                    .unwrap_or_default();
                Some(ScannedAgent {
                    agent_id: id.to_string(),
                    owner: format!("{owner:#}"),
                    uri,
                })
            })
            .collect();
        Ok(Json(ScanAgentsResponse { agents, scanned }))
    }

    #[tool(
        description = "Fetch an agent's registration file (tokenURI content) \
                       and parse it as a RegistrationFile with name, \
                       description, services, and protocols."
    )]
    async fn identity_fetch_registration_file(
        &self,
        params: Parameters<AgentIdRequest>,
    ) -> Result<Json<RegistrationFileResponse>, ErrorData> {
        let identity = self.client.identity().map_err(to_mcp_error)?;
        let agent_id = parse_u256(&params.0.agent_id)?;
        let uri = identity
            .token_uri(agent_id)
            .await
            .map_err(to_mcp_error)?;
        if uri.is_empty() {
            return Err(ErrorData {
                code: rmcp::model::ErrorCode(-32002),
                message: Cow::Owned(format!(
                    "agent {agent_id} has no URI set"
                )),
                data: None,
            });
        }
        let body = reqwest::get(&uri)
            .await
            .map_err(|e| http_error(&uri, &e))?
            .text()
            .await
            .map_err(|e| http_error(&uri, &e))?;
        let reg = erc8004::types::RegistrationFile::from_json(&body)
            .map_err(json_parse_error)?;
        Ok(Json(RegistrationFileResponse::from(reg)))
    }
}

impl From<erc8004::types::RegistrationFile> for RegistrationFileResponse {
    fn from(r: erc8004::types::RegistrationFile) -> Self {
        Self {
            type_field: r.type_field,
            name: r.name,
            description: r.description,
            image: r.image,
            services: r
                .services
                .into_iter()
                .map(|s| ServiceEndpointResponse {
                    name: s.name,
                    endpoint: s.endpoint,
                    version: s.version,
                    skills: s.skills,
                    domains: s.domains,
                })
                .collect(),
            x402_support: r.x402_support,
            active: r.active,
            registrations: r
                .registrations
                .into_iter()
                .map(|reg| RegistrationResponse {
                    agent_id: reg.agent_id,
                    agent_registry: reg.agent_registry,
                })
                .collect(),
            supported_trust: r.supported_trust,
        }
    }
}

// ---------------------------------------------------------------------------
// ServerHandler implementation
// ---------------------------------------------------------------------------

impl ServerHandler for Erc8004McpServer {
    async fn initialize(
        &self,
        _params: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        Ok(InitializeResult {
            protocol_version: ProtocolVersion::V_2024_11_05,
            server_info: Implementation {
                name: "erc8004-mcp".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                ..Default::default()
            },
            instructions: Some(format!(
                "ERC-8004 MCP Server — interact with on-chain agent identity, reputation, and \
                 validation registries on {}. Signer available: {}.",
                self.network_name, self.has_signer
            )),
        })
    }

    async fn list_tools(
        &self,
        _pagination: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let ctx = ToolCallContext::new(self, request, context);
        self.tool_router.call(ctx).await
    }
}
