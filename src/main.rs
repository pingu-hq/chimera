use std::env;

const RESET: &str = "\x1b[0m";

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

const CYAN: &str = "\x1b[36m";
const WHITE: &str = "\x1b[37m";
const GREEN: &str = "\x1b[32m";

fn help() {
    println!(
        r#"{cyan}{bold}
 ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
{reset}
{dim}declarative syscall policy engine{reset}

{white}{bold}usage{reset}
  {green}chimera{reset} <command>

{white}{bold}commands{reset}
  {green}conjure{reset} <policy.chmp> <rootfs> <command relative to rootfs>
      create a sandbox from a policy and run a command in it

  {green}embroider{reset} <policy.chmp>
      compile a policy into Rust source

  {green}setup_perms{reset} [--uid U] [--gid G] <rootfs>
      seed user.chimera.meta xattrs across the rootfs so the sandbox
      sees a coherent file owner (defaults to 0:0, host modes kept)

  {green}help{reset}
      display this page

{white}{bold}examples{reset}
  {green}chimera conjure sandbox.chmp /srv/rootfs /bin/sh{reset}
  {green}chimera setup_perms /srv/rootfs{reset}
  {green}chimera embroider sandbox.chmp{reset}
  {green}chimera help{reset}

{dim}pingu chimera v0.1.0{reset}
"#,
        reset = RESET,
        bold = BOLD,
        dim = DIM,
        white = WHITE,
        green = GREEN,
        cyan = CYAN,
    );
}

fn conjure(policy_path: &str, rootfs: &str, command: &str, cmd_args: &[String]) -> i32 {
    let (policy, warnings) = match chimera::embroider::load(policy_path) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{CYAN}{BOLD}[chimera]{RESET} conjure: {e}");
            return 1;
        }
    };

    for w in &warnings {
        eprintln!("{CYAN}{BOLD}[chimera]{RESET} warn: {w}");
    }

    match chimera::runtime::conjure(&policy, rootfs, command, cmd_args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{CYAN}{BOLD}[chimera]{RESET} conjure: {e}");
            1
        }
    }
}

fn setup_perms(uid: u32, gid: u32, rootfs: &str) -> i32 {
    match chimera::setup::setup_perms(rootfs, uid, gid) {
        Ok(report) => {
            println!(
                "{CYAN}{BOLD}[chimera]{RESET} setup_perms: {} entries, {} xattr set, {} symlinks, {} skipped",
                report.entries,
                report.xattr_ok,
                report.symlinks,
                report.skipped.len()
            );
            for s in report.skipped.iter().take(10) {
                eprintln!("{CYAN}{BOLD}[chimera]{RESET} warn: skipped: {s}");
            }
            if report.skipped.is_empty() { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("{CYAN}{BOLD}[chimera]{RESET} setup_perms: {e}");
            1
        }
    }
}

fn main() {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("help") => {
            help();
        }
        Some("embroider") => match args.next().as_deref() {
            Some(path) => match chimera::embroider::analyze(path) {
                Ok((code, plan, warnings)) => {
                    for w in &warnings {
                        eprintln!("{CYAN}{BOLD}[chimera]{RESET} warn: {w}");
                    }
                    eprintln!(
                        "{CYAN}{BOLD}[chimera]{RESET} trap {} syscalls: {}",
                        plan.trap.len(),
                        plan.trap.join(" ")
                    );
                    eprintln!(
                        "{CYAN}{BOLD}[chimera]{RESET} emulated {} syscalls: {}",
                        plan.emulated.len(),
                        plan.emulated.join(" ")
                    );
                    eprintln!(
                        "{CYAN}{BOLD}[chimera]{RESET} policy-modified {} syscalls (run as supervisor): {}",
                        plan.modified.len(),
                        plan.modified.join(" ")
                    );
                    if !plan.unknown.is_empty() {
                        eprintln!(
                            "{CYAN}{BOLD}[chimera]{RESET} warn: unknown syscalls not in table: {}",
                            plan.unknown.join(" ")
                        );
                    }
                    print!("{code}");
                }
                Err(e) => {
                    eprintln!("{CYAN}{BOLD}[chimera]{RESET} embroider: {e}");
                    std::process::exit(1);
                }
            },
            None => eprintln!("{CYAN}{BOLD}[chimera]{RESET} policy file (*.chmp) required"),
        },
        Some("conjure") => match (args.next(), args.next()) {
            (Some(policy), Some(rootfs)) => {
                let command = match args.next() {
                    Some(c) => c,
                    None => {
                        eprintln!(
                            "{CYAN}{BOLD}[chimera]{RESET} usage: chimera conjure <policy.chmp> <rootfs> <command relative to rootfs>"
                        );
                        std::process::exit(1);
                    }
                };
                let cmd_args: Vec<String> = args.collect();
                println!(
                    "{CYAN}{BOLD}[chimera]{RESET} conjuring {policy} into {rootfs}: {command}"
                );
                let code = conjure(&policy, &rootfs, &command, &cmd_args);
                std::process::exit(code);
            }
            _ => eprintln!(
                "{CYAN}{BOLD}[chimera]{RESET} usage: chimera conjure <policy.chmp> <rootfs> <command relative to rootfs>"
            ),
        },
        Some("setup_perms") => {
            let mut uid: u32 = 0;
            let mut gid: u32 = 0;
            let mut positional: Vec<String> = Vec::new();
            while let Some(a) = args.next() {
                if let Some(v) = a.strip_prefix("--uid=") {
                    match v.parse::<u32>() {
                        Ok(u) => uid = u,
                        Err(_) => {
                            eprintln!("{CYAN}{BOLD}[chimera]{RESET} invalid --uid={v}");
                            std::process::exit(1);
                        }
                    }
                } else if a == "--uid" {
                    match args.next().and_then(|v| v.parse::<u32>().ok()) {
                        Some(u) => uid = u,
                        None => {
                            eprintln!("{CYAN}{BOLD}[chimera]{RESET} --uid requires a number");
                            std::process::exit(1);
                        }
                    }
                } else if let Some(v) = a.strip_prefix("--gid=") {
                    match v.parse::<u32>() {
                        Ok(g) => gid = g,
                        Err(_) => {
                            eprintln!("{CYAN}{BOLD}[chimera]{RESET} invalid --gid={v}");
                            std::process::exit(1);
                        }
                    }
                } else if a == "--gid" {
                    match args.next().and_then(|v| v.parse::<u32>().ok()) {
                        Some(g) => gid = g,
                        None => {
                            eprintln!("{CYAN}{BOLD}[chimera]{RESET} --gid requires a number");
                            std::process::exit(1);
                        }
                    }
                } else {
                    positional.push(a);
                }
            }
            if positional.len() != 1 {
                eprintln!(
                    "{CYAN}{BOLD}[chimera]{RESET} usage: chimera setup_perms [--uid U] [--gid G] <rootfs>"
                );
                std::process::exit(1);
            }
            std::process::exit(setup_perms(uid, gid, &positional[0]));
        }
        Some(cmd) => eprintln!("unknown command: {cmd}"),
        None => help(),
    }
}
