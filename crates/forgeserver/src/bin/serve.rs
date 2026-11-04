//! Headless download server.
//!
//! Serves a store directory of payloads over HTTP. Meant for running on a VPS or
//! behind a VPN over SSH, where the GUI can't run.
//!
//! Usage:
//!     serve [--dir <path>] [--port <n>] [--bind <addr>]
//!     serve --public-ip
//!
//! Examples:
//!     serve --dir ./forge-data/store --port 57065
//!     serve --public-ip        # print the public IP (VPN exit IP if a VPN is up)

use std::path::PathBuf;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "--public-ip") {
        match forgeserver::public_ip() {
            Some(ip) => println!("{ip}"),
            None => {
                eprintln!("could not determine public IP");
                exit(1);
            }
        }
        return;
    }

    let mut dir = PathBuf::from("forge-data/store");
    let mut port: u16 = 8080;
    let mut bind = String::from("0.0.0.0");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                dir = PathBuf::from(expect_value(&args, &mut i, "--dir"));
            }
            "--port" => {
                port = expect_value(&args, &mut i, "--port")
                    .parse()
                    .unwrap_or_else(|_| fail("--port must be a number 1-65535"));
            }
            "--bind" => {
                bind = expect_value(&args, &mut i, "--bind");
            }
            other => fail(&format!("unknown argument: {other}  (try --help)")),
        }
        i += 1;
    }

    println!("Installer Forge — download server");
    println!("  serving : {}", dir.display());
    println!("  listen  : {bind}:{port}");
    if let Some(ip) = forgeserver::local_ip() {
        println!("  local   : http://{ip}:{port}");
    }
    println!("  (Ctrl-C to stop)\n");

    if let Err(e) = forgeserver::serve_blocking(dir, &bind, port) {
        eprintln!("server error: {e}");
        exit(1);
    }
}

fn expect_value(args: &[String], i: &mut usize, flag: &str) -> String {
    *i += 1;
    args.get(*i)
        .cloned()
        .unwrap_or_else(|| fail(&format!("{flag} needs a value")))
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(2);
}

fn print_help() {
    println!(
        "serve — Installer Forge headless download server\n\n\
         USAGE:\n    serve [--dir <path>] [--port <n>] [--bind <addr>]\n    serve --public-ip\n\n\
         OPTIONS:\n\
         \t--dir <path>   Directory of payloads to serve (default: forge-data/store)\n\
         \t--port <n>     Port to listen on (default: 8080)\n\
         \t--bind <addr>  Address to bind (default: 0.0.0.0)\n\
         \t--public-ip    Print the public IP (VPN exit IP if a VPN is up) and exit\n\
         \t-h, --help     Show this help"
    );
}
