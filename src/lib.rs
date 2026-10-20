mod adoption;
pub mod audit;
mod backup;
pub mod cli;
pub mod client_journal;
pub mod engine;
mod git;
mod policy;
mod replication;
mod restore;
mod transfer;
pub mod vocabulary;

pub fn request(state: &std::path::Path, value: serde_json::Value) -> serde_json::Value {
    vocabulary::request(value)
        .and_then(|v| engine::execute(state, v))
        .map(vocabulary::response)
        .unwrap_or_else(|e| vocabulary::response(engine::error_response(&e)))
}
