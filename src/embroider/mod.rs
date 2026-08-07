pub mod chmp;
pub mod lexer;
pub mod parser;
pub mod plan;
pub mod validate;

pub use plan::{plan, TrapPlan};

pub fn load(path: &str) -> Result<(chmp::Policy, Vec<String>), String> {
    let src = std::fs::read_to_string(path).map_err(|e| e.to_string())?;

    let tokens = lexer::tokenize(&src)?;
    let mut policy = parser::parse(&tokens)?;
    let warnings = validate::validate(&mut policy)?;

    Ok((policy, warnings))
}

pub fn compile(path: &str) -> Result<(String, Vec<String>), String> {
    let (policy, warnings) = load(path)?;

    let tree = parser::render_ast(&policy);

    Ok((tree, warnings))
}

/// compile `path` into a renderable ast tree plus the compiler's planning
/// pass: the trap/emulated/modified sets the runtime and cli use.
pub fn analyze(path: &str) -> Result<(String, TrapPlan, Vec<String>), String> {
    let (policy, warnings) = load(path)?;
    let arch = crate::arch::load_arch_table()?;
    let plan = plan(&policy, &arch);
    let tree = parser::render_ast(&policy);
    Ok((tree, plan, warnings))
}
