use std::{path::Path, sync::Arc, time::Duration};
use wipstash_mcp_events::{
    auth::AuthStore,
    callback::HttpsCallbackTransport,
    config::{Config, ConfigResult},
    events::EventService,
    http, project_access, App,
};

const USAGE: &str = "Usage:
  wipstash-mcp-events CONFIG.json check-config
  wipstash-mcp-events CONFIG.json serve
  wipstash-mcp-events CONFIG.json admin grant GITHUB_NUMERIC_ID PROJECT_ID
  wipstash-mcp-events CONFIG.json admin revoke GITHUB_NUMERIC_ID PROJECT_ID
  wipstash-mcp-events CONFIG.json admin invite GITHUB_NUMERIC_ID PROJECT_ID
  wipstash-mcp-events CONFIG.json admin revoke-user GITHUB_NUMERIC_ID
  wipstash-mcp-events CONFIG.json admin revoke-invite < invitation-token.txt

Only serve starts a listener. Admin commands require private local database ownership.
Verify numeric GitHub account IDs before provisioning; usernames alone are not identity.
No OAuth application, credentials, or project grants are created automatically.";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return;
    }
    if let Err(error) = run(&args).await {
        // Never log requests, full config, URI, GitHub response, token or cookie.
        eprintln!("Wipstash MCP Events: {error}");
        std::process::exit(1);
    }
}
async fn run(args: &[String]) -> ConfigResult<()> {
    if args.len() < 2 {
        return Err(USAGE.into());
    }
    let config = Config::load(Path::new(&args[0]))?;
    match args[1].as_str() {
        "check-config" if args.len() == 2 => {
            // Offline shape/security validation, without secrets, DBs or network.
            config.auth_config().validate()?;
            println!("Configuration valid. Credentials, TLS files, live GitHub sign-in and ChatGPT delivery have not been tested.");
            Ok(())
        }
        "admin" => http::administer(&config, &args[2..]),
        "serve" if args.len() == 2 => {
            let auth = Arc::new(AuthStore::open(
                &config.auth_database,
                config.auth_config(),
            )?);
            let grants = project_access(auth.clone(), config.projects.clone());
            let events = Arc::new(
                EventService::open(
                    &config.event_database,
                    grants,
                    Arc::new(HttpsCallbackTransport::default()),
                    config.event_capacity,
                )
                .map_err(|_| "event subscription storage unavailable")?,
            );
            let app = Arc::new(App::new(auth.clone(), events, config.projects.clone())?);
            // Slow callbacks never postpone polling or block engine integration.
            let poll_app = app.clone();
            let poller = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let app = poll_app.clone();
                    // One blocking poll at a time, with no missed-tick buildup.
                    let _ = tokio::task::spawn_blocking(move || app.poll(http::now())).await;
                }
            });
            let delivery_app = app.clone();
            let delivery = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    delivery_app.deliver(http::now()).await;
                }
            });
            let maintenance_auth = auth.clone();
            let maintenance = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let auth = maintenance_auth.clone();
                    // Refresh reuse evidence survives until family expiry.
                    let _ =
                        tokio::task::spawn_blocking(move || auth.prune_expired(http::now())).await;
                }
            });
            let result = http::serve(config, app, auth).await;
            poller.abort();
            delivery.abort();
            maintenance.abort();
            let _ = poller.await;
            let _ = delivery.await;
            let _ = maintenance.await;
            result
        }
        _ => Err(USAGE.into()),
    }
}
