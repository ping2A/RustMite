//! Runtime values for the expression language.

use std::collections::BTreeMap;
use std::fmt;

/// Typed value in the expression language.
///
/// `Record` is used for observation object trees (not a language literal).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Record(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_display_string(&self) -> String {
        match self {
            Value::Null => "null".into(),
            Value::Bool(b) => b.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => f.to_string(),
            Value::String(s) => s.clone(),
            Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            Value::List(items) => {
                let parts: Vec<String> = items.iter().map(|v| v.to_display_string()).collect();
                format!("[{}]", parts.join(", "))
            }
            Value::Record(_) => "<record>".into(),
        }
    }

    pub fn get_field(&self, name: &str) -> Value {
        match self {
            Value::Record(map) => map.get(name).cloned().unwrap_or(Value::Null),
            Value::Null => Value::Null,
            _ => Value::Null,
        }
    }

    /// Coerce to a path/string for path helpers and string ops.
    pub fn as_path_str(&self) -> Option<String> {
        match self {
            Value::String(s) => Some(s.clone()),
            Value::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
            Value::Null => None,
            _ => None,
        }
    }

    pub fn path_under(&self, prefix: &str) -> bool {
        match self.as_path_str() {
            Some(path) => path_is_under(&path, prefix),
            None => false,
        }
    }
}

pub fn path_is_under(path: &str, prefix: &str) -> bool {
    path == prefix
        || path.starts_with(&format!("{prefix}/"))
        // Allow non-directory prefixes such as "/memfd:".
        || (prefix.ends_with(':') && path.starts_with(prefix))
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_string())
    }
}
