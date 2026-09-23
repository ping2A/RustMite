//! Abstract syntax tree.

#[derive(Clone, Debug)]
pub enum Expr {
    Literal(Literal),
    Ident(String),
    Field {
        base: Box<Expr>,
        name: String,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
    UnaryNot(Box<Expr>),
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// `expr matches "pattern"` — `regex_idx` indexes into `CompiledExpr::regexes`.
    Matches {
        expr: Box<Expr>,
        regex_idx: usize,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Literal {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    StartsWith,
    EndsWith,
}
