#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(output) = eal_api_server::flags::process_control().map_err(anyhow::Error::msg)? {
        print!("{output}");
        return Ok(());
    }
    eal_api_server::run().await
}
