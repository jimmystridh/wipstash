use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "wip",
    version,
    about = "Source control for independent local working directories",
    after_help = "Exit codes: 0 completed, 1 rejected/error, 2 invalid arguments, 3 saved or queued but not yet shared, 4 merge conflict. No client daemon or MCP is required."
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(
        long,
        global = true,
        help = "Use local state and retain pending delivery"
    )]
    pub offline: bool,
    #[arg(short = 'C', global = true, default_value = ".")]
    pub directory: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize a local repository in an existing source directory.
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Clone a local repository, saved remote profile, or authenticated HTTPS origin.
    Clone {
        source: String,
        path: PathBuf,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Preserve and register an existing Wipstash workspace with the CLI.
    Attach {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Import or inspect private device connection profiles.
    Remote {
        #[command(subcommand)]
        command: Remote,
    },
    /// Stage exact current file contents, additions and deletions.
    Add {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Remove paths from the staging area without editing working files.
    Restore {
        #[arg(long, required = true)]
        staged: bool,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Commit staged contents and deliver them directly to the server.
    Commit {
        #[arg(short, long)]
        message: String,
        #[arg(short = 'a', long, help = "Stage all eligible changes first")]
        all: bool,
        #[arg(long)]
        allow_empty: bool,
        #[arg(long)]
        operation_id: Option<String>,
        #[arg(long)]
        expected_head: Option<String>,
        #[arg(long, value_delimiter = ',', num_args=0..)]
        resolved_conflicts: Option<Vec<String>>,
    },
    /// Inspect live files, staging, sharing, incoming work and repair notices.
    Status {
        #[arg(long)]
        quick: bool,
    },
    /// Inspect working, staged or exact public-version changes.
    Diff {
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        head: Option<String>,
        path: Option<String>,
    },
    /// Read shared commit history.
    Log {
        #[arg(short='n', long, default_value_t=20, value_parser=clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
    },
    /// Fetch incoming commits without changing working files.
    #[command(alias = "fetch")]
    GetLatest,
    /// Deliberately merge shared changes, preserving local edits.
    Merge {
        #[arg(default_value = "latest")]
        target: String,
    },
    /// Deliver pending commits, coordination and audit, then get latest.
    Sync,
    /// Inspect an exact commit's sharing and validation outcome.
    CommitStatus { commit_id: String },
    /// Inspect recorded requests and safely retry an exact retained operation.
    Operation {
        #[command(subcommand)]
        command: Operation,
    },
    /// Inspect, claim and update advisory tasks.
    Task {
        #[command(subcommand)]
        command: Task,
    },
    /// Inspect and lease a background-check repair.
    Repair {
        #[command(subcommand)]
        command: Repair,
    },
    /// Add or inspect task and repair discussions.
    Comment {
        #[command(subcommand)]
        command: Comment,
    },
    /// Review and resolve merge conflicts in a prepared directory.
    Conflict {
        #[command(subcommand)]
        command: Conflict,
    },
    /// Inspect or archive workspace registrations; files are preserved.
    Workspace {
        #[command(subcommand)]
        command: Workspace,
    },
    /// Inspect exact-head server validation and timings.
    Check {
        #[arg(long)]
        head: Option<String>,
        #[arg(long)]
        timings: bool,
    },
    /// Inspect and deliver central audit, or import explicit activity records.
    Audit {
        #[command(subcommand)]
        command: Audit,
    },
    /// Execute another public engine operation with JSON parameters.
    Request {
        operation: String,
        #[arg(long, default_value = "{}")]
        params: String,
    },
    /// Trusted operator access to policy, backups, enrollment and recovery.
    Admin {
        operation: String,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long, default_value = "{}")]
        params: String,
    },
}

#[derive(Subcommand)]
#[command(
    after_help = "Native operator commands are also available: setup, join, device, serve, status and doctor. Run wip remote guide for their flags."
)]
pub enum Remote {
    /// Import a provisioned private device profile; keys remain at their existing paths.
    Add {
        name: String,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        default: bool,
    },
    List,
    Guide,
    #[command(external_subcommand)]
    Native(Vec<String>),
}
#[derive(Subcommand)]
pub enum Operation {
    List {
        #[command(flatten)]
        page: Page,
    },
    Show {
        id: String,
    },
    Retry {
        id: String,
    },
}
#[derive(Args)]
pub struct Page {
    #[arg(long, default_value_t = 0)]
    pub cursor: u64,
    #[arg(long, default_value_t=16, value_parser=clap::value_parser!(u32).range(1..=32))]
    pub limit: u32,
}
#[derive(Args)]
pub struct Lease {
    pub id: String,
    #[arg(long)]
    pub revision: u64,
    #[arg(long)]
    pub lease: Option<u64>,
}
#[derive(Subcommand)]
pub enum Task {
    List {
        #[command(flatten)]
        page: Page,
    },
    Claim {
        id: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        acceptance: String,
        #[arg(long, required=true, num_args=1..)]
        paths: Vec<String>,
        #[arg(long, default_value_t = 300)]
        lease: u64,
    },
    Renew(Lease),
    Complete(Lease),
    Release(Lease),
}
#[derive(Subcommand)]
pub enum Repair {
    List {
        #[command(flatten)]
        page: Page,
    },
    Acknowledge(Lease),
    Claim(Lease),
    Renew(Lease),
    Release(Lease),
}
#[derive(Subcommand)]
pub enum Comment {
    Add {
        #[arg(value_parser=["task","repair"])]
        subject_type: String,
        subject_id: String,
        #[arg(short, long)]
        message: String,
        #[arg(long, value_delimiter = ',')]
        mentions: Vec<String>,
    },
    List {
        #[arg(long)]
        subject_type: Option<String>,
        #[arg(long)]
        subject_id: Option<String>,
        #[command(flatten)]
        page: Page,
    },
}
#[derive(Subcommand)]
pub enum Conflict {
    List,
    Show {
        candidate: String,
    },
    Open {
        path: PathBuf,
        #[arg(
            long,
            conflicts_with = "candidate",
            required_unless_present = "candidate"
        )]
        commit: Option<String>,
        #[arg(long)]
        candidate: Option<String>,
    },
    Resolve {
        #[arg(long)]
        resolution: PathBuf,
        #[arg(long)]
        candidate: String,
        #[arg(long)]
        target: String,
        #[arg(long, value_delimiter=',', num_args=0..)]
        paths: Vec<String>,
    },
}
#[derive(Subcommand)]
pub enum Workspace {
    List {
        #[command(flatten)]
        page: Page,
    },
    Close {
        #[arg(long, required = true)]
        writers_stopped: bool,
        #[arg(long, default_value = "Finished")]
        reason: String,
    },
    Reopen,
}
#[derive(Subcommand)]
pub enum Audit {
    Status,
    Log {
        #[command(flatten)]
        page: Page,
    },
    Verify,
    Record {
        #[arg(long)]
        file: PathBuf,
    },
    /// Import normalized activity JSONL; optional native collection uses audit collect.
    Import {
        #[arg(long)]
        file: PathBuf,
    },
    /// Run the existing native-history collector once; never install a service.
    Collect {
        #[arg(long)]
        collector: PathBuf,
    },
}
