use std::env;

const RESET: &str = "\x1b[0m";

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";
const WHITE: &str = "\x1b[37m";

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
  {green}conjure{reset} <policy.chmp> <root>
      create a sandbox from a policy

  {green}embroider{reset} <policy.chmp>
      compile a policy into Rust source

  {green}help{reset}
      display this page

{white}{bold}examples{reset}
  {green}chimera conjure sandbox.chmp /srv/rootfs{reset}
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

fn conjure(policy: &str, root: &str) {
    todo!()
}

fn main() {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("help") => {
            help();
        }
        Some("embroider") => match args.next().as_deref() {
            Some(path) => match chimera::embroider::compile(path) {
                Ok(code) => print!("{code}"),
                Err(e) => {
                    eprintln!("{CYAN}{BOLD}[chimera]{RESET} embroider: {e}");
                    std::process::exit(1);
                }
            },
            None => eprintln!("{CYAN}{BOLD}[chimera]{RESET} policy file (*.chmp) required"),
        },
        Some("conjure") => match args.next().as_deref() {
            Some(policy) => {
                if let Some(root) = args.next().as_deref() {
                    println!("{CYAN}{BOLD}[chimera]{RESET} conjuring {policy} into {root}");
                    conjure(policy, root);
                } else {
                    eprintln!("{CYAN}{BOLD}[chimera]{RESET} root directory required");
                }
            }
            None => eprintln!("{CYAN}{BOLD}[chimera]{RESET} policy file (*.chmp) required"),
        },
        Some(cmd) => eprintln!("unknown command: {cmd}"),
        None => help(),
    }
}
