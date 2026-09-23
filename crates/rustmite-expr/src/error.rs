//! Expression errors.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExprError {
    #[error("parse error at {position}: {message}")]
    Parse { message: String, position: usize },

    #[error("compile error: {0}")]
    Compile(String),

    #[error("type error: {0}")]
    Type(String),

    #[error("unknown field or name: {0}")]
    UnknownName(String),

    #[error("step budget exceeded (max_steps)")]
    StepBudgetExceeded,

    #[error("regex error: {0}")]
    Regex(String),

    #[error("division by zero")]
    DivByZero,

    #[error("arity error for {func}: expected {expected}, got {got}")]
    Arity {
        func: String,
        expected: usize,
        got: usize,
    },
}
