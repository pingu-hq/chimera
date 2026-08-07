use super::chmp::*;
use super::lexer::{Tok, Token};

pub struct Parser<'a> {
    toks: &'a [Token],
    pos: usize,
}

pub fn parse(toks: &[Token]) -> Result<Policy, String> {
    Parser { toks, pos: 0 }.parse()
}

impl<'a> Parser<'a> {
    fn parse(mut self) -> Result<Policy, String> {
        let mut policy = Policy::default();

        while !self.at_end() {
            if self.peek_tok() == Some(&Tok::Meta) {
                self.parse_meta_block(&mut policy)?;
                continue;
            }
            let kw = self.take_ident("block header")?;
            match kw.as_str() {
                "on_startup" => policy.on_startup = self.parse_body("on_startup")?,
                "on_exit" => policy.on_exit = self.parse_body("on_exit")?,
                "group" => {
                    let name = self.take_ident("group name")?;
                    let (syscalls, includes) = self.parse_group_body()?;
                    policy.groups.push(Group {
                        name,
                        syscalls,
                        includes,
                    });
                }
                "handle" => {
                    let name = self.take_ident("handle name")?;
                    let body = self.parse_body("handle")?;
                    policy.handles.push(Handle { group: name, body });
                }
                "syscall" => {
                    let name = self.take_ident("syscall name")?;
                    let body = self.parse_body("syscall")?;
                    policy.overrides.push(Override { name, body });
                }
                other => {
                    return Err(format!("line {}: unexpected '{}'", self.line(), other));
                }
            }
        }

        Ok(policy)
    }

    /// parse a `-t> ... -t>` metadata section: `key = value` lines where the
    /// value is a bare ident, number, or string. unknown keys are preserved in
    /// `meta.raw` for validation warnings.
    fn parse_meta_block(&mut self, policy: &mut Policy) -> Result<(), String> {
        self.expect(Tok::Meta, "'-t>' opening metadata")?;
        policy.meta.present = true;

        while !self.at_end() && self.peek_tok() != Some(&Tok::Meta) {
            let key = self.take_ident("metadata key")?;
            self.expect(Tok::Eq, "'=' after metadata key")?;
            let value = match self.peek_tok() {
                Some(Tok::Ident(s)) | Some(Tok::Num(s)) => {
                    let s = s.clone();
                    self.pos += 1;
                    s
                }
                Some(Tok::Str(s)) => {
                    let s = s.clone();
                    self.pos += 1;
                    s
                }
                _ => {
                    return Err(format!(
                        "line {}: expected metadata value for '{key}'",
                        self.line()
                    ));
                }
            };

            let meta = &mut policy.meta;
            match key.as_str() {
                "name" => meta.name = Some(value.clone()),
                "version" => meta.version = Some(value.clone()),
                "xattr" => meta.xattr = is_truthy_meta(&value),
                "arch" => meta.arch = Some(value.clone()),
                _ => {}
            }
            meta.raw.push((key, value));
        }

        if self.at_end() {
            return Err(format!("line {}: unclosed metadata section", self.line()));
        }
        self.expect(Tok::Meta, "'-t>' closing metadata")?;
        Ok(())
    }

    fn parse_body(&mut self, what: &str) -> Result<Vec<Statement>, String> {
        self.expect(Tok::LBrace, &format!("'{{' opening {what} block"))?;
        let stmts = self.parse_statement_list(what)?;
        self.expect(Tok::RBrace, &format!("'}}' closing {what} block"))?;
        Ok(stmts)
    }

    fn parse_group_body(&mut self) -> Result<(Vec<String>, Vec<String>), String> {
        self.expect(Tok::LBrace, "'{' opening group block")?;
        let mut syscalls = Vec::new();
        let mut includes = Vec::new();
        while !self.at_end() && !self.at_rbrace() {
            if self.peek_tok() == Some(&Tok::At) {
                self.pos += 1;
                includes.push(self.take_ident("group include (after '@')")?);
            } else {
                syscalls.push(self.take_ident("syscall name")?);
            }
        }
        self.expect(Tok::RBrace, "'}' closing group block")?;
        Ok((syscalls, includes))
    }

    fn parse_statement_list(&mut self, what: &str) -> Result<Vec<Statement>, String> {
        let mut stmts = Vec::new();
        while !self.at_end() && !self.at_rbrace() {
            stmts.push(self.parse_statement()?);
        }
        if self.at_end() {
            return Err(format!("line {}: unclosed {what} block", self.line()));
        }
        Ok(stmts)
    }

    fn parse_statement(&mut self) -> Result<Statement, String> {
        let ident = self.peek_ident().ok_or_else(|| {
            format!("line {}: expected statement", self.line())
        })?;

        match ident {
            "allow" => {
                self.pos += 1;
                Ok(Statement::Allow)
            }
            "deny" => {
                self.pos += 1;
                // optional errno argument: `deny` (eperm) or `deny -enoent`.
                // a bare ident is treated as the next statement.
                let arg = match self.peek_tok() {
                    Some(Tok::Minus) | Some(Tok::Num(_)) => Some(self.parse_expr()?),
                    _ => None,
                };
                Ok(Statement::Deny(arg))
            }
            "respond" => {
                self.pos += 1;
                let expr = self.parse_expr()?;
                Ok(Statement::Respond(expr))
            }
            "echo_args" => {
                self.pos += 1;
                Ok(Statement::EchoArgs)
            }
            "if" => self.parse_if(),
            "modify" => Err(format!(
                "line {}: modify() has been removed; assign the arg directly, e.g. 'path = map_path(root, path)'",
                self.line()
            )),
            "echo" => {
                self.pos += 1;
                self.expect(Tok::LParen, "'(' after echo")?;
                let msg = self.take_str("echo message")?;
                self.expect(Tok::RParen, "')' after echo message")?;
                Ok(Statement::Echo(msg))
            }
            "bind" => {
                self.pos += 1;
                self.expect(Tok::LParen, "'(' after bind")?;
                let source = self.take_str("bind source")?;
                self.expect(Tok::Comma, "',' after bind source")?;
                let destination = self.take_str("bind destination")?;
                self.expect(Tok::RParen, "')' after bind destination")?;
                Ok(Statement::Bind(source, destination))
            }
            _ => {
                let name = self.take_ident("assignment target")?;
                self.expect(Tok::Eq, "'=' after assignment target")?;
                let value = self.parse_expr()?;
                Ok(Statement::Assign(name, value))
            }
        }
    }

    fn parse_if(&mut self) -> Result<Statement, String> {
        self.pos += 1;
        let expr = self.parse_expr()?;
        self.expect(Tok::LBrace, "'{' opening if body")?;

        let then = self.parse_statement_list("if")?;
        self.expect(Tok::RBrace, "'}' closing if body")?;

        let otherwise = if self.peek_ident() == Some("else") {
            self.pos += 1;
            self.expect(Tok::LBrace, "'{' opening else body")?;
            let stmts = self.parse_statement_list("else")?;
            self.expect(Tok::RBrace, "'}' closing else body")?;
            Some(stmts)
        } else {
            None
        };

        Ok(Statement::Conditional(Conditional {
            expr,
            then,
            otherwise,
        }))
    }

    fn parse_expr(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_eq()?;
        while self.peek_tok() == Some(&Tok::Pipe) {
            self.pos += 1;
            let right = self.parse_eq()?;
            left = Expr::BinOp(Box::new(left), Op::BitOr, Box::new(right));
        }
        Ok(left)
    }

    fn parse_eq(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_primary()?;
        while self.peek_tok() == Some(&Tok::EqEq) {
            self.pos += 1;
            let right = self.parse_primary()?;
            left = Expr::BinOp(Box::new(left), Op::Eq, Box::new(right));
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek_tok() {
            Some(Tok::Minus) => {
                self.pos += 1;
                Ok(Expr::Neg(Box::new(self.parse_primary()?)))
            }
            Some(Tok::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(Expr::String(s))
            }
            Some(Tok::Num(n)) => {
                let n = n.clone();
                self.pos += 1;
                Ok(Expr::String(n))
            }
            Some(Tok::Ident(name)) => {
                let name = name.clone();
                self.pos += 1;
                if self.peek_tok() == Some(&Tok::LParen) {
                    self.pos += 1;
                    let mut args = Vec::new();
                    if self.peek_tok() != Some(&Tok::RParen) {
                        loop {
                            args.push(self.parse_expr()?);
                            match self.peek_tok() {
                                Some(Tok::Comma) => self.pos += 1,
                                Some(Tok::RParen) => break,
                                _ => {
                                    return Err(format!(
                                        "line {}: expected ',' or ')' in call arguments",
                                        self.line()
                                    ));
                                }
                            }
                        }
                    }
                    self.expect(Tok::RParen, "')' closing call")?;
                    Ok(Expr::Call(name, args))
                } else {
                    Ok(Expr::Ident(name))
                }
            }
            _ => Err(format!("line {}: expected expression", self.line())),
        }
    }

    fn take_str(&mut self, what: &str) -> Result<String, String> {
        match self.peek_tok() {
            Some(Tok::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            _ => Err(format!("line {}: expected {what}", self.line())),
        }
    }

    fn take_ident(&mut self, what: &str) -> Result<String, String> {
        match self.peek_tok() {
            Some(Tok::Ident(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            _ => Err(format!("line {}: expected {what}", self.line())),
        }
    }

    fn expect(&mut self, tok: Tok, what: &str) -> Result<(), String> {
        if self.peek_tok() == Some(&tok) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("line {}: expected {what}", self.line()))
        }
    }

    fn peek_tok(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.tok)
    }

    fn peek_ident(&self) -> Option<&str> {
        match self.peek_tok() {
            Some(Tok::Ident(s)) => Some(s),
            _ => None,
        }
    }

    fn at_rbrace(&self) -> bool {
        self.peek_tok() == Some(&Tok::RBrace)
    }

    fn at_end(&self) -> bool {
        self.pos >= self.toks.len()
    }

    fn line(&self) -> usize {
        self.toks.get(self.pos).map_or(1, |t| t.line)
    }
}

fn is_truthy_meta(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on")
}

// ==============================
// ast tree output

/// render the parsed policy as a readable ast tree; the old rust-code
/// generation is gone. this is what `chimera embroider` prints.
pub fn render_ast(policy: &Policy) -> String {
    let mut out = String::new();

    let meta = &policy.meta;
    let label = meta.name.as_deref().unwrap_or("<unnamed>");
    out.push_str(&format!("policy {label:?}\n"));
    if meta.present {
        out.push_str("  meta\n");
        if let Some(n) = &meta.name {
            out.push_str(&format!("    name = {n:?}\n"));
        }
        if let Some(v) = &meta.version {
            out.push_str(&format!("    version = {v:?}\n"));
        }
        out.push_str(&format!("    xattr = {}\n", yes_no(meta.xattr)));
        if let Some(a) = &meta.arch {
            out.push_str(&format!("    arch = {a:?}\n"));
        }
        for (k, v) in &meta.raw {
            out.push_str(&format!("    {k} = {v:?}\n"));
        }
    }

    render_stmts(&mut out, "on_startup", &policy.on_startup);
    render_stmts(&mut out, "on_exit", &policy.on_exit);

    out.push_str(&format!("  groups ({})\n", policy.groups.len()));
    for g in &policy.groups {
        out.push_str(&format!("    {}\n", g.name));
        for inc in &g.includes {
            out.push_str(&format!("      @{inc}\n"));
        }
        for s in &g.syscalls {
            out.push_str(&format!("      {s}\n"));
        }
    }

    out.push_str(&format!("  handles ({})\n", policy.handles.len()));
    for h in &policy.handles {
        out.push_str(&format!("    {}\n", h.group));
        for s in &h.body {
            out.push_str(&format!("      {}\n", ast_stmt(s, "")));
        }
    }

    out.push_str(&format!("  overrides ({})\n", policy.overrides.len()));
    for o in &policy.overrides {
        out.push_str(&format!("    {}\n", o.name));
        for s in &o.body {
            out.push_str(&format!("      {}\n", ast_stmt(s, "")));
        }
    }

    out
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn render_stmts(out: &mut String, label: &str, stmts: &[Statement]) {
    out.push_str(&format!("  {label} ({})\n", stmts.len()));
    for s in stmts {
        out.push_str(&format!("    {}\n", ast_stmt(s, "")));
    }
}

fn ast_stmt(s: &Statement, _indent: &str) -> String {
    match s {
        Statement::Allow => "allow".to_string(),
        Statement::Deny(None) => "deny".to_string(),
        Statement::Deny(Some(e)) => format!("deny -{}", ast_expr(e)),
        Statement::Respond(e) => format!("respond {}", ast_expr(e)),
        Statement::Echo(msg) => format!("echo {msg:?}"),
        Statement::EchoArgs => "echo_args".to_string(),
        Statement::Assign(name, e) => format!("{name} = {}", ast_expr(e)),
        Statement::Bind(src, dst) => format!("bind({src:?}, {dst:?})"),
        Statement::Conditional(c) => {
            let mut s = format!("if {} {{", ast_expr(&c.expr));
            for st in &c.then {
                s.push_str(&format!(" {};", ast_stmt(st, "")));
            }
            s.push_str(" }");
            if let Some(o) = &c.otherwise {
                s.push_str(" else {");
                for st in o {
                    s.push_str(&format!(" {};", ast_stmt(st, "")));
                }
                s.push_str(" }");
            }
            s
        }
    }
}

fn ast_expr(e: &Expr) -> String {
    match e {
        Expr::Ident(name) => name.clone(),
        Expr::String(s) => format!("{s:?}"),
        Expr::Call(name, args) => {
            let args: Vec<String> = args.iter().map(ast_expr).collect();
            format!("{name}({})", args.join(", "))
        }
        Expr::BinOp(l, op, r) => {
            let op = match op {
                Op::BitOr => "|",
                Op::BitAnd => "&",
                Op::Or => "or",
                Op::And => "and",
                Op::Eq => "==",
            };
            format!("{} {op} {}", ast_expr(l), ast_expr(r))
        }
        Expr::Neg(inner) => format!("-{}", ast_expr(inner)),
    }
}
