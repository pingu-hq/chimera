#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// metadata from the optional `-t>` ... `-t>` section at the top of the
    /// file (name, version, xattr, arch).
    pub meta: Meta,
    pub on_startup: Vec<Statement>,
    pub on_exit: Vec<Statement>,
    pub groups: Vec<Group>,
    pub handles: Vec<Handle>,
    pub overrides: Vec<Override>,
}

/// the policy metadata section (`-t>` ... `-t>`). `raw` keeps every key/value
/// verbatim so validation can warn about unknown keys.
#[derive(Debug, Clone, Default)]
pub struct Meta {
    pub present: bool,
    pub name: Option<String>,
    pub version: Option<String>,
    /// when true the sandbox enforces per-file identity carried in the
    /// `user.chimera.meta` xattr.
    pub xattr: bool,
    pub arch: Option<String>,
    pub raw: Vec<(String, String)>,
}

impl Meta {
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.version.is_none() && !self.xattr && self.arch.is_none()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Group {
    pub name: String,
    pub syscalls: Vec<String>,
    pub includes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Handle {
    pub group: String,
    pub body: Vec<Statement>,
}

#[derive(Debug, Clone, Default)]
pub struct Override {
    pub name: String,
    pub body: Vec<Statement>,
}

#[derive(Debug, Clone)]
pub enum Statement {
    Allow,
    /// block the syscall; optional errno expression (negative convention),
    /// e.g. `deny` (eperm) or `deny -enoent`.
    Deny(Option<Expr>),
    /// reply with an arbitrary data value instead of running the syscall,
    /// e.g. `respond 1000`.
    Respond(Expr),
    Echo(String),
    EchoArgs,
    Assign(String, Expr),
    Bind(String, String),
    Conditional(Conditional),
}

#[derive(Debug, Clone)]
pub struct Conditional {
    pub expr: Expr,
    pub then: Vec<Statement>,
    pub otherwise: Option<Vec<Statement>>,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Ident(String),
    String(String),
    Call(String, Vec<Expr>),
    BinOp(Box<Expr>, Op, Box<Expr>),
    Neg(Box<Expr>),
}

#[derive(Debug, Clone)]
pub enum Op {
    BitOr,
    BitAnd,
    Or,
    And,
    Eq,
}

pub const GLOBAL_ROOT: &str = "root";
pub const GLOBAL_CWD: &str = "cwd";
