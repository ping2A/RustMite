//! Recursive-descent parser.

use regex::Regex;

use crate::ast::{BinOp, Expr, Literal};
use crate::error::ExprError;
use crate::lexer::{Lexer, Token};

const MAX_REGEX_PATTERN_LEN: usize = 512;

pub struct Parser<'a> {
    lexer: Lexer<'a>,
    cur: Token,
    regexes: Vec<Regex>,
}

impl<'a> Parser<'a> {
    pub fn new(input: &'a str) -> Result<Self, ExprError> {
        let mut lexer = Lexer::new(input);
        let cur = lexer.next_token()?;
        Ok(Self {
            lexer,
            cur,
            regexes: Vec::new(),
        })
    }

    pub fn parse(mut self) -> Result<(Expr, Vec<Regex>), ExprError> {
        let expr = self.parse_or()?;
        if self.cur != Token::Eof {
            return Err(ExprError::Parse {
                message: format!("unexpected token after expression: {:?}", self.cur),
                position: 0,
            });
        }
        Ok((expr, self.regexes))
    }

    fn bump(&mut self) -> Result<(), ExprError> {
        self.cur = self.lexer.next_token()?;
        Ok(())
    }

    fn parse_or(&mut self) -> Result<Expr, ExprError> {
        let mut left = self.parse_and()?;
        while self.cur == Token::Or {
            self.bump()?;
            let right = self.parse_and()?;
            left = Expr::Binary {
                op: BinOp::Or,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ExprError> {
        let mut left = self.parse_not()?;
        while self.cur == Token::And {
            self.bump()?;
            let right = self.parse_not()?;
            left = Expr::Binary {
                op: BinOp::And,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, ExprError> {
        if self.cur == Token::Not {
            self.bump()?;
            let expr = self.parse_not()?;
            return Ok(Expr::UnaryNot(Box::new(expr)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Expr, ExprError> {
        let left = self.parse_postfix()?;
        let op = match &self.cur {
            Token::Eq => Some(BinOp::Eq),
            Token::Ne => Some(BinOp::Ne),
            Token::Lt => Some(BinOp::Lt),
            Token::Le => Some(BinOp::Le),
            Token::Gt => Some(BinOp::Gt),
            Token::Ge => Some(BinOp::Ge),
            Token::Contains => Some(BinOp::Contains),
            Token::StartsWith => Some(BinOp::StartsWith),
            Token::EndsWith => Some(BinOp::EndsWith),
            Token::Matches => {
                self.bump()?;
                let Token::String(pat) = self.cur.clone() else {
                    return Err(ExprError::Parse {
                        message: "expected string after matches".into(),
                        position: 0,
                    });
                };
                self.bump()?;
                let idx = self.compile_regex(&pat)?;
                return Ok(Expr::Matches {
                    expr: Box::new(left),
                    regex_idx: idx,
                });
            }
            _ => None,
        };
        if let Some(op) = op {
            self.bump()?;
            let right = self.parse_postfix()?;
            Ok(Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            })
        } else {
            Ok(left)
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, ExprError> {
        let mut expr = self.parse_primary()?;
        loop {
            match &self.cur {
                Token::Dot => {
                    self.bump()?;
                    let Token::Ident(name) = self.cur.clone() else {
                        return Err(ExprError::Parse {
                            message: "expected field name after '.'".into(),
                            position: 0,
                        });
                    };
                    self.bump()?;
                    if self.cur == Token::LParen {
                        // method call: expr.name(args)
                        self.bump()?;
                        let args = self.parse_args()?;
                        expr = Expr::Call {
                            callee: Box::new(Expr::Field {
                                base: Box::new(expr),
                                name,
                            }),
                            args,
                        };
                    } else {
                        expr = Expr::Field {
                            base: Box::new(expr),
                            name,
                        };
                    }
                }
                Token::LParen => {
                    // function call on primary (e.g. path_under("/tmp") as free function needs 2 args)
                    self.bump()?;
                    let args = self.parse_args()?;
                    expr = Expr::Call {
                        callee: Box::new(expr),
                        args,
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>, ExprError> {
        let mut args = Vec::new();
        if self.cur == Token::RParen {
            self.bump()?;
            return Ok(args);
        }
        loop {
            args.push(self.parse_or()?);
            match &self.cur {
                Token::Comma => {
                    self.bump()?;
                }
                Token::RParen => {
                    self.bump()?;
                    break;
                }
                other => {
                    return Err(ExprError::Parse {
                        message: format!("expected ',' or ')' in argument list, got {other:?}"),
                        position: 0,
                    });
                }
            }
        }
        Ok(args)
    }

    fn parse_primary(&mut self) -> Result<Expr, ExprError> {
        match self.cur.clone() {
            Token::Null => {
                self.bump()?;
                Ok(Expr::Literal(Literal::Null))
            }
            Token::True => {
                self.bump()?;
                Ok(Expr::Literal(Literal::Bool(true)))
            }
            Token::False => {
                self.bump()?;
                Ok(Expr::Literal(Literal::Bool(false)))
            }
            Token::Int(v) => {
                self.bump()?;
                Ok(Expr::Literal(Literal::Int(v)))
            }
            Token::Float(v) => {
                self.bump()?;
                Ok(Expr::Literal(Literal::Float(v)))
            }
            Token::String(s) => {
                self.bump()?;
                Ok(Expr::Literal(Literal::String(s)))
            }
            Token::Ident(name) => {
                self.bump()?;
                Ok(Expr::Ident(name))
            }
            Token::LParen => {
                self.bump()?;
                let expr = self.parse_or()?;
                if self.cur != Token::RParen {
                    return Err(ExprError::Parse {
                        message: "expected ')'".into(),
                        position: 0,
                    });
                }
                self.bump()?;
                Ok(expr)
            }
            other => Err(ExprError::Parse {
                message: format!("unexpected token {other:?}"),
                position: 0,
            }),
        }
    }

    fn compile_regex(&mut self, pat: &str) -> Result<usize, ExprError> {
        if pat.len() > MAX_REGEX_PATTERN_LEN {
            return Err(ExprError::Compile(format!(
                "regex pattern exceeds {MAX_REGEX_PATTERN_LEN} bytes"
            )));
        }
        let re = Regex::new(pat).map_err(|e| ExprError::Regex(e.to_string()))?;
        let idx = self.regexes.len();
        self.regexes.push(re);
        Ok(idx)
    }
}
