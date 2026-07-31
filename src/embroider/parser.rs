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
            let kw = self.take_ident("block header")?;
            match kw.as_str() {
                "on_startup" => policy.on_startup = self.parse_body("on_startup")?,
                "on_exit" => policy.on_exit = self.parse_body("on_exit")?,
                "group" => {
                    let name = self.take_ident("group name")?;
                    let syscalls = self.parse_syscall_body()?;
                    policy.groups.push(Group { name, syscalls });
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

    fn parse_body(&mut self, what: &str) -> Result<Vec<Statement>, String> {
        self.expect(Tok::LBrace, &format!("'{{' opening {what} block"))?;
        let stmts = self.parse_statement_list(what)?;
        self.expect(Tok::RBrace, &format!("'}}' closing {what} block"))?;
        Ok(stmts)
    }

    fn parse_syscall_body(&mut self) -> Result<Vec<String>, String> {
        self.expect(Tok::LBrace, "'{' opening group block")?;
        let mut syscalls = Vec::new();
        while !self.at_end() && !self.at_rbrace() {
            syscalls.push(self.take_ident("syscall name")?);
        }
        self.expect(Tok::RBrace, "'}' closing group block")?;
        Ok(syscalls)
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
                Ok(Statement::Deny)
            }
            "echo_args" => {
                self.pos += 1;
                Ok(Statement::EchoArgs)
            }
            "if" => self.parse_if(),
            "echo" => {
                self.pos += 1;
                self.expect(Tok::LParen, "'(' after echo")?;
                let msg = self.take_str("echo message")?;
                self.expect(Tok::RParen, "')' after echo message")?;
                Ok(Statement::Echo(msg))
            }
            "modify" => {
                self.pos += 1;
                self.expect(Tok::LParen, "'(' after modify")?;
                let arg = self.take_ident("modify argument")?;
                self.expect(Tok::Comma, "',' after modify argument")?;
                let value = self.parse_expr()?;
                self.expect(Tok::RParen, "')' after modify value")?;
                Ok(Statement::Modify(arg, value))
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
        let mut left = self.parse_primary()?;
        while self.peek_tok() == Some(&Tok::Pipe) {
            self.pos += 1;
            let right = self.parse_primary()?;
            left = Expr::BinOp(Box::new(left), Op::BitOr, Box::new(right));
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek_tok() {
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
