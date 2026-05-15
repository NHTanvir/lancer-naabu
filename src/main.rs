//! lancer-naabu
//! Rust clone of naabu. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-naabu", version, about = "Rust clone of naabu")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-naabu - scaffold ready. Implement per plan.md.");
    Ok(())
}
