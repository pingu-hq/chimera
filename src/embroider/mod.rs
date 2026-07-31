pub mod chmp;
pub mod encode;
pub mod lexer;
pub mod parser;

pub fn compile(path: &str) -> Result<String, String> {
    let src = std::fs::read_to_string(path).map_err(|e| e.to_string())?;

    let modname = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("policy")
        .strip_suffix(".chmp")
        .unwrap_or("policy");

    let tokens = lexer::tokenize(&src)?;
    let policy = parser::parse(&tokens)?;
    Ok(encode::encode(&policy, modname, path))
}

// Generated policies — built by the embroider compiler
include!("gen.rs");
