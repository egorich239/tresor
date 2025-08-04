use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, group = "mode")]
    config: Option<String>,

    #[arg(short, long, group = "mode")]
    server: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Other client-side commands will go here.
}

fn main() -> Result<()> {
    let _cli = Cli::parse();

    // Logic for client-side commands will be added here.
    println!("Tresor CLI (client commands to be implemented)");

    Ok(())
}
