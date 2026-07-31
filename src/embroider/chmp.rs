#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub on_startup: Vec<Statement>,
    pub on_exit: Vec<Statement>,
    pub groups: Vec<Group>,
    pub handles: Vec<Handle>,
    pub overrides: Vec<Override>,
}

#[derive(Debug, Clone, Default)]
pub struct Group {
    pub name: String,
    pub syscalls: Vec<String>,
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
    Deny,
    Echo(String),
    EchoArgs,
    Assign(String, Expr),
    Modify(String, Expr),
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
}

#[derive(Debug, Clone)]
pub enum Op {
    BitOr,
    BitAnd,
    Or,
    And,
}
