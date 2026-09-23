//! Compile and evaluate expressions.

use regex::Regex;

use crate::ast::{BinOp, Expr, Literal};
use crate::context::EvalContext;
use crate::error::ExprError;
use crate::parser::Parser;
use crate::value::{path_is_under, Value};

pub const DEFAULT_MAX_STEPS: usize = 10_000;

/// A compiled (parsed + regex-cached) expression.
#[derive(Clone, Debug)]
pub struct CompiledExpr {
    pub(crate) ast: Expr,
    pub(crate) regexes: Vec<Regex>,
    pub max_steps: usize,
}

/// Compile a `where` expression string.
pub fn compile(where_expr: &str) -> Result<CompiledExpr, ExprError> {
    let parser = Parser::new(where_expr)?;
    let (ast, regexes) = parser.parse()?;
    Ok(CompiledExpr {
        ast,
        regexes,
        max_steps: DEFAULT_MAX_STEPS,
    })
}

/// Evaluate a compiled expression to a boolean match result.
pub fn eval(expr: &CompiledExpr, ctx: &EvalContext) -> Result<bool, ExprError> {
    let mut steps = 0usize;
    let v = eval_expr(&expr.ast, ctx, &expr.regexes, &mut steps, expr.max_steps)?;
    match v {
        Value::Bool(b) => Ok(b),
        other => Err(ExprError::Type(format!(
            "where expression must yield bool, got {}",
            other.to_display_string()
        ))),
    }
}

fn bump(steps: &mut usize, max: usize) -> Result<(), ExprError> {
    *steps = steps.saturating_add(1);
    if *steps > max {
        return Err(ExprError::StepBudgetExceeded);
    }
    Ok(())
}

fn eval_expr(
    expr: &Expr,
    ctx: &EvalContext,
    regexes: &[Regex],
    steps: &mut usize,
    max_steps: usize,
) -> Result<Value, ExprError> {
    bump(steps, max_steps)?;
    match expr {
        Expr::Literal(lit) => Ok(literal_value(lit)),
        Expr::Ident(name) => Ok(ctx.get(name)),
        Expr::Field { base, name } => {
            let base_v = eval_expr(base, ctx, regexes, steps, max_steps)?;
            Ok(base_v.get_field(name))
        }
        Expr::UnaryNot(inner) => {
            let v = eval_expr(inner, ctx, regexes, steps, max_steps)?;
            let b = truthy(&v)?;
            Ok(Value::Bool(!b))
        }
        Expr::Binary { op, left, right } => {
            eval_binary(*op, left, right, ctx, regexes, steps, max_steps)
        }
        Expr::Matches { expr, regex_idx } => {
            let v = eval_expr(expr, ctx, regexes, steps, max_steps)?;
            let Some(s) = v.as_path_str() else {
                return Ok(Value::Bool(false));
            };
            let re = regexes.get(*regex_idx).ok_or_else(|| {
                ExprError::Compile(format!("invalid regex index {regex_idx}"))
            })?;
            Ok(Value::Bool(re.is_match(&s)))
        }
        Expr::Call { callee, args } => eval_call(callee, args, ctx, regexes, steps, max_steps),
    }
}

fn literal_value(lit: &Literal) -> Value {
    match lit {
        Literal::Null => Value::Null,
        Literal::Bool(b) => Value::Bool(*b),
        Literal::Int(i) => Value::Int(*i),
        Literal::Float(f) => Value::Float(*f),
        Literal::String(s) => Value::String(s.clone()),
    }
}

fn truthy(v: &Value) -> Result<bool, ExprError> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(ExprError::Type(format!(
            "expected bool, got {}",
            v.to_display_string()
        ))),
    }
}

fn eval_binary(
    op: BinOp,
    left: &Expr,
    right: &Expr,
    ctx: &EvalContext,
    regexes: &[Regex],
    steps: &mut usize,
    max_steps: usize,
) -> Result<Value, ExprError> {
    match op {
        BinOp::And => {
            let l = eval_expr(left, ctx, regexes, steps, max_steps)?;
            if !truthy(&l)? {
                return Ok(Value::Bool(false));
            }
            let r = eval_expr(right, ctx, regexes, steps, max_steps)?;
            Ok(Value::Bool(truthy(&r)?))
        }
        BinOp::Or => {
            let l = eval_expr(left, ctx, regexes, steps, max_steps)?;
            if truthy(&l)? {
                return Ok(Value::Bool(true));
            }
            let r = eval_expr(right, ctx, regexes, steps, max_steps)?;
            Ok(Value::Bool(truthy(&r)?))
        }
        BinOp::Eq => {
            let l = eval_expr(left, ctx, regexes, steps, max_steps)?;
            let r = eval_expr(right, ctx, regexes, steps, max_steps)?;
            Ok(Value::Bool(values_eq(&l, &r)))
        }
        BinOp::Ne => {
            let l = eval_expr(left, ctx, regexes, steps, max_steps)?;
            let r = eval_expr(right, ctx, regexes, steps, max_steps)?;
            Ok(Value::Bool(!values_eq(&l, &r)))
        }
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
            let l = eval_expr(left, ctx, regexes, steps, max_steps)?;
            let r = eval_expr(right, ctx, regexes, steps, max_steps)?;
            Ok(Value::Bool(compare_ord(op, &l, &r)?))
        }
        BinOp::Contains => {
            let l = eval_expr(left, ctx, regexes, steps, max_steps)?;
            let r = eval_expr(right, ctx, regexes, steps, max_steps)?;
            Ok(Value::Bool(value_contains(&l, &r)))
        }
        BinOp::StartsWith => {
            let l = eval_expr(left, ctx, regexes, steps, max_steps)?;
            let r = eval_expr(right, ctx, regexes, steps, max_steps)?;
            Ok(Value::Bool(match (l.as_path_str(), r.as_str()) {
                (Some(hay), Some(needle)) => hay.starts_with(needle),
                _ => false,
            }))
        }
        BinOp::EndsWith => {
            let l = eval_expr(left, ctx, regexes, steps, max_steps)?;
            let r = eval_expr(right, ctx, regexes, steps, max_steps)?;
            Ok(Value::Bool(match (l.as_path_str(), r.as_str()) {
                (Some(hay), Some(needle)) => hay.ends_with(needle),
                _ => false,
            }))
        }
    }
}

fn values_eq(l: &Value, r: &Value) -> bool {
    match (l, r) {
        (Value::Null, Value::Null) => true,
        (Value::Null, _) | (_, Value::Null) => false,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Float(a), Value::Float(b)) => a == b,
        (Value::Int(a), Value::Float(b)) => (*a as f64) == *b,
        (Value::Float(a), Value::Int(b)) => *a == (*b as f64),
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Bytes(a), Value::Bytes(b)) => a == b,
        (Value::Bytes(a), Value::String(b)) => String::from_utf8_lossy(a).as_ref() == b.as_str(),
        (Value::String(a), Value::Bytes(b)) => a.as_str() == String::from_utf8_lossy(b).as_ref(),
        _ => false,
    }
}

fn compare_ord(op: BinOp, l: &Value, r: &Value) -> Result<bool, ExprError> {
    if matches!(l, Value::Null) || matches!(r, Value::Null) {
        return Ok(false);
    }
    let ord = match (as_number(l), as_number(r)) {
        (Some(a), Some(b)) => a.partial_cmp(&b),
        _ => match (l.as_path_str(), r.as_path_str()) {
            (Some(a), Some(b)) => Some(a.cmp(&b)),
            _ => None,
        },
    };
    let Some(ord) = ord else {
        return Err(ExprError::Type(format!(
            "cannot compare {} and {}",
            l.to_display_string(),
            r.to_display_string()
        )));
    };
    Ok(match op {
        BinOp::Lt => ord == std::cmp::Ordering::Less,
        BinOp::Le => ord != std::cmp::Ordering::Greater,
        BinOp::Gt => ord == std::cmp::Ordering::Greater,
        BinOp::Ge => ord != std::cmp::Ordering::Less,
        _ => false,
    })
}

fn as_number(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

fn value_contains(hay: &Value, needle: &Value) -> bool {
    match hay {
        Value::String(s) => needle
            .as_str()
            .map(|n| s.contains(n))
            .unwrap_or(false),
        Value::Bytes(b) => {
            let s = String::from_utf8_lossy(b);
            needle.as_str().map(|n| s.contains(n)).unwrap_or(false)
        }
        Value::List(items) => items.iter().any(|item| {
            if values_eq(item, needle) {
                return true;
            }
            if let (Some(is), Some(ns)) = (item.as_str(), needle.as_str()) {
                return is.eq_ignore_ascii_case(ns) || is.to_ascii_lowercase().contains(&ns.to_ascii_lowercase());
            }
            false
        }),
        _ => false,
    }
}

fn eval_call(
    callee: &Expr,
    args: &[Expr],
    ctx: &EvalContext,
    regexes: &[Regex],
    steps: &mut usize,
    max_steps: usize,
) -> Result<Value, ExprError> {
    // Method form: Field { base, name: "path_under" }
    if let Expr::Field { base, name } = callee {
        let recv = eval_expr(base, ctx, regexes, steps, max_steps)?;
        let mut arg_vals = Vec::with_capacity(args.len());
        for a in args {
            arg_vals.push(eval_expr(a, ctx, regexes, steps, max_steps)?);
        }
        return dispatch_method(name, &recv, &arg_vals);
    }

    // Free function: Ident("path_under")(path, prefix) or Ident("path_under")(prefix) — latter needs context
    if let Expr::Ident(name) = callee {
        let mut arg_vals = Vec::with_capacity(args.len());
        for a in args {
            arg_vals.push(eval_expr(a, ctx, regexes, steps, max_steps)?);
        }
        return dispatch_free(name, &arg_vals);
    }

    Err(ExprError::Type("invalid call target".into()))
}

fn dispatch_method(name: &str, recv: &Value, args: &[Value]) -> Result<Value, ExprError> {
    match name {
        "path_under" => {
            if args.len() != 1 {
                return Err(ExprError::Arity {
                    func: "path_under".into(),
                    expected: 1,
                    got: args.len(),
                });
            }
            let prefix = args[0]
                .as_str()
                .ok_or_else(|| ExprError::Type("path_under prefix must be string".into()))?;
            Ok(Value::Bool(recv.path_under(prefix)))
        }
        "starts_with" => {
            if args.len() != 1 {
                return Err(ExprError::Arity {
                    func: "starts_with".into(),
                    expected: 1,
                    got: args.len(),
                });
            }
            Ok(Value::Bool(match (recv.as_path_str(), args[0].as_str()) {
                (Some(h), Some(n)) => h.starts_with(n),
                _ => false,
            }))
        }
        "ends_with" => {
            if args.len() != 1 {
                return Err(ExprError::Arity {
                    func: "ends_with".into(),
                    expected: 1,
                    got: args.len(),
                });
            }
            Ok(Value::Bool(match (recv.as_path_str(), args[0].as_str()) {
                (Some(h), Some(n)) => h.ends_with(n),
                _ => false,
            }))
        }
        "contains" => {
            if args.len() != 1 {
                return Err(ExprError::Arity {
                    func: "contains".into(),
                    expected: 1,
                    got: args.len(),
                });
            }
            Ok(Value::Bool(value_contains(recv, &args[0])))
        }
        "basename" => {
            if !args.is_empty() {
                return Err(ExprError::Arity {
                    func: "basename".into(),
                    expected: 0,
                    got: args.len(),
                });
            }
            let Some(path) = recv.as_path_str() else {
                return Ok(Value::Null);
            };
            let base = path.rsplit('/').next().unwrap_or(&path);
            Ok(Value::String(base.to_string()))
        }
        "lower" => {
            if !args.is_empty() {
                return Err(ExprError::Arity {
                    func: "lower".into(),
                    expected: 0,
                    got: args.len(),
                });
            }
            Ok(match recv.as_path_str() {
                Some(s) => Value::String(s.to_ascii_lowercase()),
                None => Value::Null,
            })
        }
        "len" => {
            if !args.is_empty() {
                return Err(ExprError::Arity {
                    func: "len".into(),
                    expected: 0,
                    got: args.len(),
                });
            }
            Ok(Value::Int(match recv {
                Value::String(s) => s.len() as i64,
                Value::Bytes(b) => b.len() as i64,
                Value::List(l) => l.len() as i64,
                Value::Null => 0,
                _ => {
                    return Err(ExprError::Type("len() on unsupported type".into()));
                }
            }))
        }
        other => Err(ExprError::UnknownName(format!("method {other}"))),
    }
}

fn dispatch_free(name: &str, args: &[Value]) -> Result<Value, ExprError> {
    match name {
        "path_under" => {
            // path_under(path, prefix)
            if args.len() != 2 {
                return Err(ExprError::Arity {
                    func: "path_under".into(),
                    expected: 2,
                    got: args.len(),
                });
            }
            let path = args[0]
                .as_path_str()
                .ok_or_else(|| ExprError::Type("path_under path must be string".into()))?;
            let prefix = args[1]
                .as_str()
                .ok_or_else(|| ExprError::Type("path_under prefix must be string".into()))?;
            Ok(Value::Bool(path_is_under(&path, prefix)))
        }
        other => Err(ExprError::UnknownName(format!("function {other}"))),
    }
}
