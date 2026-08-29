#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eal_api_server::run().await
}
