//! Lexer for the expression language.

use crate::error::ExprError;

#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    Ident(String),
    String(String),
    Int(i64),
    Float(f64),
    True,
    False,
    Null,
    And,
    Or,
    Not,
    Matches,
    Contains,
    StartsWith,
    EndsWith,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Dot,
    LParen,
    RParen,
    Comma,
    Eof,
}

pub struct Lexer<'a> {
    input: &'a str,
    chars: Vec<char>,
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.chars().collect(),
            pos: 0,
        }
    }

    pub fn next_token(&mut self) -> Result<Token, ExprError> {
        self.skip_ws_and_comments();
        if self.pos >= self.chars.len() {
            return Ok(Token::Eof);
        }
        let start = self.pos;
        let c = self.chars[self.pos];

        match c {
            '.' => {
                self.pos += 1;
                Ok(Token::Dot)
            }
            '(' => {
                self.pos += 1;
                Ok(Token::LParen)
            }
            ')' => {
                self.pos += 1;
                Ok(Token::RParen)
            }
            ',' => {
                self.pos += 1;
                Ok(Token::Comma)
            }
            '=' if self.chars.get(self.pos + 1) == Some(&'=') => {
                self.pos += 2;
                Ok(Token::Eq)
            }
            '!' if self.chars.get(self.pos + 1) == Some(&'=') => {
                self.pos += 2;
                Ok(Token::Ne)
            }
            '<' if self.chars.get(self.pos + 1) == Some(&'=') => {
                self.pos += 2;
                Ok(Token::Le)
            }
            '>' if self.chars.get(self.pos + 1) == Some(&'=') => {
                self.pos += 2;
                Ok(Token::Ge)
            }
            '<' => {
                self.pos += 1;
                Ok(Token::Lt)
            }
            '>' => {
                self.pos += 1;
                Ok(Token::Gt)
            }
            '"' | '\'' => self.string(c),
            '0'..='9' => self.number(),
            '-' if matches!(self.peek_char(), Some('0'..='9')) => self.number(),
            c if is_ident_start(c) => self.ident_or_keyword(start),
            _ => Err(ExprError::Parse {
                message: format!("unexpected character {c:?}"),
                position: self.byte_pos(start),
            }),
        }
    }

    fn ident_or_keyword(&mut self, start: usize) -> Result<Token, ExprError> {
        self.pos += 1;
        while let Some(c) = self.peek_char() {
            if is_ident_continue(c) {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s: String = self.chars[start..self.pos].iter().collect();
        Ok(match s.as_str() {
            "and" => Token::And,
            "or" => Token::Or,
            "not" => Token::Not,
            "matches" => Token::Matches,
            "contains" => Token::Contains,
            "starts_with" => Token::StartsWith,
            "ends_with" => Token::EndsWith,
            "true" => Token::True,
            "false" => Token::False,
            "null" => Token::Null,
            _ => Token::Ident(s),
        })
    }

    fn string(&mut self, quote: char) -> Result<Token, ExprError> {
        let start = self.pos;
        self.pos += 1; // opening quote
        let mut out = String::new();
        while self.pos < self.chars.len() {
            let c = self.chars[self.pos];
            if c == quote {
                self.pos += 1;
                return Ok(Token::String(out));
            }
            if c == '\\' {
                self.pos += 1;
                let Some(esc) = self.peek_char() else {
                    return Err(ExprError::Parse {
                        message: "unterminated string escape".into(),
                        position: self.byte_pos(start),
                    });
                };
                self.pos += 1;
                match esc {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    '\'' => out.push('\''),
                    // Preserve unrecognized escapes (e.g. regex `\[`) as `\` + char.
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
                continue;
            }
            self.pos += 1;
            out.push(c);
        }
        Err(ExprError::Parse {
            message: "unterminated string".into(),
            position: self.byte_pos(start),
        })
    }

    fn number(&mut self) -> Result<Token, ExprError> {
        let start = self.pos;
        if self.chars[self.pos] == '-' {
            self.pos += 1;
        }
        while matches!(self.peek_char(), Some('0'..='9')) {
            self.pos += 1;
        }
        let mut is_float = false;
        if self.peek_char() == Some('.')
            && matches!(self.chars.get(self.pos + 1), Some('0'..='9'))
        {
            is_float = true;
            self.pos += 1;
            while matches!(self.peek_char(), Some('0'..='9')) {
                self.pos += 1;
            }
        }
        let s: String = self.chars[start..self.pos].iter().collect();
        if is_float {
            let v: f64 = s.parse().map_err(|_| ExprError::Parse {
                message: format!("invalid float {s}"),
                position: self.byte_pos(start),
            })?;
            Ok(Token::Float(v))
        } else {
            let v: i64 = s.parse().map_err(|_| ExprError::Parse {
                message: format!("invalid int {s}"),
                position: self.byte_pos(start),
            })?;
            Ok(Token::Int(v))
        }
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            while matches!(self.peek_char(), Some(c) if c.is_whitespace()) {
                self.pos += 1;
            }
            if self.peek_char() == Some('#') {
                while let Some(c) = self.peek_char() {
                    self.pos += 1;
                    if c == '\n' {
                        break;
                    }
                }
                continue;
            }
            if self.peek_char() == Some('/') && self.chars.get(self.pos + 1) == Some(&'/') {
                self.pos += 2;
                while let Some(c) = self.peek_char() {
                    self.pos += 1;
                    if c == '\n' {
                        break;
                    }
                }
                continue;
            }
            break;
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn byte_pos(&self, char_idx: usize) -> usize {
        self.chars[..char_idx]
            .iter()
            .map(|c| c.len_utf8())
            .sum::<usize>()
            .min(self.input.len())
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
