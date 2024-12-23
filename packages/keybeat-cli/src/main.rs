use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use clap::{Args, Parser, Subcommand};
use clap_stdin::{FileOrStdin, MaybeStdin};
use cryptosystem::{CryptoExport, CryptoImport, Ed25519Cryptosystem, PublicKey, SecretKey};
use keybeat_core::Proof;
use std::path::PathBuf;

fn main() {
    match core() {
        Ok(_) => {}
        Err(err) => {
            eprintln!("Error: {err:?}");
            std::process::exit(1)
        }
    }
}

fn core() -> Result<(), anyhow::Error> {
    let opts = Opts::parse();

    match opts.command {
        Command::Create {
            key,
            output,
            message_args,
        } => {
            let secret_key_base64 = key
                .contents()
                .with_context(|| "failed to read secret key")?;
            let secret_key =
                SecretKey::<Ed25519Cryptosystem>::from_base64(&secret_key_base64, false)
                    .with_context(|| "invalid or corrupted secret key")?;
            let message = message_args
                .message()
                .with_context(|| "failed to read message")?;

            eprintln!("Retrieving latest Bitcoin block hash...");
            let proof = Proof::new_latest(message, &secret_key)
                .with_context(|| "failed to create proof")?;
            eprintln!("Done, proof generated and signed!");
            let proof_str = proof.to_string();

            if let Some(output) = output {
                std::fs::write(output, proof_str)?;
            } else {
                println!("{}", proof_str);
            }
        }
        Command::Validate { key, proof } => {
            let public_key_base64 = key
                .contents()
                .with_context(|| "failed to read public key")?;
            let public_key =
                PublicKey::<Ed25519Cryptosystem>::from_base64(&public_key_base64, false)
                    .with_context(|| "invalid or corrupted public key")?;
            let proof_str = proof.contents().with_context(|| "failed to read proof")?;
            let proof = Proof::<Ed25519Cryptosystem>::parse(&proof_str)
                .with_context(|| "invalid or corrupted proof")?;

            eprintln!("Validating proof...");
            let earliest_time = proof
                .validate(&public_key)
                .with_context(|| "failed to validate proof")?
                .with_context(|| "failed to get proof time (this could indicate a fraudulent proof, but from the right person)")?;

            // Now report the time nicely to the user
            let human_readable_time = earliest_time.format("%Y-%m-%d %H:%M:%S");

            eprintln!(
                "Valid! The earliest this proof could have been created is {}.",
                time_ago(earliest_time)
            );
            eprintln!();
            println!("Earliest time UTC: {human_readable_time}");
            println!("{}", proof.message());
        }
        Command::GenerateKeypair { output } => {
            let (public_key, secret_key) = SecretKey::<Ed25519Cryptosystem>::generate_keypair();
            let secret_key_str = secret_key.to_base64(false);
            let public_key_str = public_key.to_base64(false);

            if let Some(output) = output {
                let pub_output = output.with_extension("pub");

                std::fs::write(&output, secret_key_str)?;
                eprintln!("Secret key written to {output:?}");
                std::fs::write(&pub_output, public_key_str)?;
                eprintln!("Public key written to {pub_output:?}",);
            } else {
                println!("Secret key (NEVER reveal this!): {}", secret_key_str);
                println!("Public key: {}", public_key_str);
            }
        }
    }

    Ok(())
}

/// Displays the time that has elapsed since the given timestamp in a human-readable form.
fn time_ago(timestamp: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(timestamp);

    if duration < Duration::seconds(1) {
        "less than a second ago".to_string()
    } else if duration < Duration::minutes(1) {
        format!("{} second(s) ago", duration.num_seconds())
    } else if duration < Duration::hours(1) {
        format!("{} minute(s) ago", duration.num_minutes())
    } else if duration < Duration::days(1) {
        format!("{} hour(s) ago", duration.num_hours())
    } else if duration < Duration::days(30) {
        format!("{} day(s) ago", duration.num_days())
    } else if duration < Duration::days(365) {
        format!("{} month(s) ago", duration.num_days() / 30)
    } else {
        format!("{} year(s) ago", duration.num_days() / 365)
    }
}

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates a new time-based proof
    Create {
        /// The path to the secret key to sign the proof with, or `-` to read from stdin
        #[arg(short, long)]
        key: FileOrStdin,
        /// A file to write the proof to, or stdout if not present
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        message_args: MessageArgs,
    },
    /// Validates the given time-based proof, returning the earliest time it could have been
    /// created and the message
    Validate {
        /// The path to the public key to validate the proof with, or `-` to read from stdin
        #[arg(short, long)]
        key: FileOrStdin,
        /// The file to read the proof from, or `-` to read from stdin
        proof: FileOrStdin,
    },
    /// Generates a new keypair for time-based proofs
    #[clap(name = "gen-keypair")]
    GenerateKeypair {
        /// A file to write the secret key to, or stdout if not present (the public key will be
        /// written to this, with `.pub` appended)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// Arguments related to the message to sign (we can get it from the CLI, a file, or stdin).
#[derive(Args)]
#[group(required = true, multiple = false)]
struct MessageArgs {
    /// The message to sign, or `-` to read from stdin
    #[arg(short, long)]
    message: Option<MaybeStdin<String>>,
    /// A file to read the message from
    #[arg(long)]
    message_file: Option<PathBuf>,
}
impl MessageArgs {
    fn message(&self) -> Result<String, anyhow::Error> {
        match (self.message.as_deref(), self.message_file.as_ref()) {
            (Some(msg), None) => Ok(msg.clone()),
            (None, Some(file)) => Ok(std::fs::read_to_string(file)?),
            // Clap ensures we will get exactly one specified
            _ => unreachable!(),
        }
    }
}
