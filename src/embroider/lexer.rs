#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    Str(String),
    Num(String),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Comma,
    Eq,
    Pipe,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
}

pub fn tokenize(src: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    let mut line = 1;
    let n = chars.len();

    while i < n {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\r' => i += 1,
            '\n' => {
                line += 1;
                i += 1;
            }
            '#' => {
                while i < n && chars[i] != '\n' {
                    i += 1;
                }
            }
            '{' => {
                toks.push(Token { tok: Tok::LBrace, line });
                i += 1;
            }
            '}' => {
                toks.push(Token { tok: Tok::RBrace, line });
                i += 1;
            }
            '(' => {
                toks.push(Token { tok: Tok::LParen, line });
                i += 1;
            }
            ')' => {
                toks.push(Token { tok: Tok::RParen, line });
                i += 1;
            }
            ',' => {
                toks.push(Token { tok: Tok::Comma, line });
                i += 1;
            }
            '=' => {
                toks.push(Token { tok: Tok::Eq, line });
                i += 1;
            }
            '|' => {
                toks.push(Token { tok: Tok::Pipe, line });
                i += 1;
            }
            '"' => {
                let mut j = i + 1;
                while j < n && chars[j] != '"' {
                    j += 1;
                }
                if j >= n {
                    return Err(format!("line {line}: unterminated string"));
                }
                let s: String = chars[i + 1..j].iter().collect();
                toks.push(Token { tok: Tok::Str(s), line });
                i = j + 1;
            }
            '0'..='9' => {
                let mut j = i;
                while j < n && chars[j].is_ascii_digit() {
                    j += 1;
                }
                let s: String = chars[i..j].iter().collect();
                toks.push(Token { tok: Tok::Num(s), line });
                i = j;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut j = i;
                while j < n && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                let s: String = chars[i..j].iter().collect();
                toks.push(Token { tok: Tok::Ident(s), line });
                i = j;
            }
            _ => return Err(format!("line {line}: unexpected character '{c}'")),
        }
    }

    Ok(toks)
}
