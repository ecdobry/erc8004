//! ERC-8004 MCP Server — exposes the ERC-8004 SDK as MCP tools.

mod error;
mod server;

use alloy::{
    network::EthereumWallet,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use erc8004::{Erc8004, Network};
use rmcp::ServiceExt;
use server::Erc8004McpServer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// MCP server for AI-assisted interaction with ERC-8004 on-chain registries.
#[derive(Parser, Debug)]
#[command(name = "erc8004-mcp")]
#[command(about = "MCP server exposing ERC-8004 identity, reputation, and validation registries")]
#[command(version)]
struct Args {
    /// JSON-RPC URL for the EVM node.
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// Network name for contract addresses.
    #[arg(long, env = "NETWORK", default_value = "ethereum-mainnet")]
    network: String,

    /// Hex-encoded private key for write operations.
    #[arg(long, env = "PRIVATE_KEY")]
    private_key: Option<String>,

    /// Override Identity Registry address (0x-prefixed hex).
    #[arg(long, env = "IDENTITY_ADDRESS")]
    identity_address: Option<String>,

    /// Override Reputation Registry address (0x-prefixed hex).
    #[arg(long, env = "REPUTATION_ADDRESS")]
    reputation_address: Option<String>,

    /// Override Validation Registry address (0x-prefixed hex).
    #[arg(long, env = "VALIDATION_ADDRESS")]
    validation_address: Option<String>,
}

fn parse_network(name: &str) -> anyhow::Result<Network> {
    match name.to_lowercase().replace('_', "-").as_str() {
        "ethereum-mainnet" | "ethereum" | "mainnet" => Ok(Network::EthereumMainnet),
        "ethereum-sepolia" | "sepolia" => Ok(Network::EthereumSepolia),
        "base-mainnet" | "base" => Ok(Network::BaseMainnet),
        "base-sepolia" => Ok(Network::BaseSepolia),
        "polygon-mainnet" | "polygon" => Ok(Network::PolygonMainnet),
        "polygon-amoy" | "amoy" => Ok(Network::PolygonAmoy),
        "arbitrum-mainnet" | "arbitrum" => Ok(Network::ArbitrumMainnet),
        "arbitrum-sepolia" => Ok(Network::ArbitrumSepolia),
        "celo-mainnet" | "celo" => Ok(Network::CeloMainnet),
        "celo-alfajores" | "alfajores" => Ok(Network::CeloAlfajores),
        "gnosis-mainnet" | "gnosis" => Ok(Network::GnosisMainnet),
        "scroll-mainnet" | "scroll" => Ok(Network::ScrollMainnet),
        "scroll-sepolia" => Ok(Network::ScrollSepolia),
        "taiko-mainnet" | "taiko" => Ok(Network::TaikoMainnet),
        "monad-mainnet" | "monad" => Ok(Network::MonadMainnet),
        "monad-testnet" => Ok(Network::MonadTestnet),
        "bsc-mainnet" | "bsc" => Ok(Network::BscMainnet),
        "bsc-testnet" => Ok(Network::BscTestnet),
        other => anyhow::bail!("unknown network: {other}"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Tracing to stderr — stdout is reserved for MCP protocol.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "erc8004_mcp=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let network = parse_network(&args.network)?;
    let has_signer = args.private_key.is_some();

    tracing::info!(network = %args.network, signer = has_signer, "Starting ERC-8004 MCP server");

    // Build the provider (with or without a wallet signer).
    let provider = if let Some(ref pk) = args.private_key {
        let signer: PrivateKeySigner = pk.parse()?;
        let wallet = EthereumWallet::from(signer);
        ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(args.rpc_url.parse()?)
            .erased()
    } else {
        ProviderBuilder::new()
            .connect_http(args.rpc_url.parse()?)
            .erased()
    };

    // Build the ERC-8004 client with network defaults + overrides.
    let mut client = Erc8004::new(provider).with_network(network);

    if let Some(ref addr) = args.identity_address {
        client = client.with_identity_address(addr.parse::<Address>()?);
    }
    if let Some(ref addr) = args.reputation_address {
        client = client.with_reputation_address(addr.parse::<Address>()?);
    }
    if let Some(ref addr) = args.validation_address {
        client = client.with_validation_address(addr.parse::<Address>()?);
    }

    let server = Erc8004McpServer::new(client, has_signer, args.network.clone());

    // Run over stdio transport.
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let service = server.serve((stdin, stdout)).await?;
    tracing::info!("ERC-8004 MCP server connected, waiting for requests...");
    service.waiting().await?;

    tracing::info!("ERC-8004 MCP server shutting down");

    Ok(())
}
