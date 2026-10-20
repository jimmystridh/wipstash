#[tokio::main]
async fn main() {
    std::process::exit(wipstash::cli::main().await);
}
