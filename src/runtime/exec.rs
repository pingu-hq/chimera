use crate::embroider::chmp::{Expr, Op, Statement};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Str(String),
}

pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Str(s) => !s.is_empty() && s != "0",
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Decision {
    Allow,
    /// block the syscall with the given (positive) errno.
    Deny(i32),
    /// chimera answers the syscall with a raw data value instead of the
    /// kernel, e.g. `respond 1000`.
    Respond(i64),
}

pub struct Scope<'a> {
    pub args: &'a HashMap<String, String>,
    pub root: &'a str,
    pub cwd: &'a str,
    pub binds: &'a [(String, String)],
    pub locals: HashMap<String, Value>,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub decision: Option<Decision>,
    /// (arg name, new value) for every syscall arg the policy reassigned.
    pub modified: Vec<(String, String)>,
}

pub fn run_body(body: &[Statement], scope: &mut Scope) -> Outcome {
    let mut outcome = Outcome::default();
    for s in body {
        exec_stmt(s, scope, &mut outcome);
    }
    outcome
}

fn exec_stmt(s: &Statement, scope: &mut Scope, outcome: &mut Outcome) {
    match s {
        Statement::Allow => {
            if outcome.decision.is_none() {
                outcome.decision = Some(Decision::Allow);
            }
        }
        Statement::Deny(arg) => {
            let errno = match arg {
                Some(expr) => {
                    let v = as_i64(&eval(expr, scope));
                    if v < 0 {
                        v.unsigned_abs().min(i32::MAX as u64) as i32
                    } else {
                        v.min(i32::MAX as i64) as i32
                    }
                }
                None => libc::EPERM,
            };
            outcome.decision = Some(Decision::Deny(errno));
        }
        Statement::Respond(expr) => {
            outcome.decision = Some(Decision::Respond(as_i64(&eval(expr, scope))));
        }
        Statement::Echo(msg) => println!("{} {msg}", crate::log::tag("chimera")),
        Statement::EchoArgs => {
            let mut args: Vec<String> =
                scope.args.iter().map(|(k, v)| format!("{k}={v}")).collect();
            args.sort();
            println!("{} args: {}", crate::log::tag("chimera"), args.join(" "));
        }
        Statement::Assign(name, expr) => {
            let value = eval(expr, scope);
            if name == crate::embroider::chmp::GLOBAL_ROOT
                || name == crate::embroider::chmp::GLOBAL_CWD
            {
                eprintln!("{} warn: assignment to read-only '{}' ignored", crate::log::tag("chimera"), name);
            } else if scope.args.contains_key(name) {
                let s = match &value {
                    Value::Str(s) => s.clone(),
                    Value::Bool(b) => b.to_string(),
                };
                outcome.modified.push((name.clone(), s));
            } else {
                scope.locals.insert(name.clone(), value);
            }
        }
        Statement::Bind(source, destination) => {
            println!("{} bind {} -> {}", crate::log::tag("chimera"), source, destination);
        }
        Statement::Conditional(c) => {
            if truthy(&eval(&c.expr, scope)) {
                for s in &c.then {
                    exec_stmt(s, scope, outcome);
                }
            } else if let Some(o) = &c.otherwise {
                for s in o {
                    exec_stmt(s, scope, outcome);
                }
            }
        }
    }
}

fn eval(expr: &Expr, scope: &mut Scope) -> Value {
    match expr {
        Expr::Ident(name) => {
            if let Some(v) = scope.args.get(name) {
                return Value::Str(v.clone());
            }
            if name == crate::embroider::chmp::GLOBAL_ROOT {
                return Value::Str(scope.root.to_string());
            }
            if name == crate::embroider::chmp::GLOBAL_CWD {
                return Value::Str(scope.cwd.to_string());
            }
            if let Some(v) = scope.locals.get(name) {
                return v.clone();
            }
            if let Some(e) = errno_value(name) {
                return Value::Str(e.to_string());
            }
            Value::Str(String::new())
        }
        Expr::String(s) => Value::Str(s.clone()),
        Expr::Neg(inner) => {
            let v = eval(inner, scope);
            let n = as_i64(&v);
            Value::Str((-n).to_string())
        }
        Expr::Call(name, args) => {
            let vals: Vec<Value> = args.iter().map(|a| eval(a, scope)).collect();
            call_fn(name, &vals, scope)
        }
        Expr::BinOp(l, op, r) => {
            let l = eval(l, scope);
            let r = eval(r, scope);
            match op {
                Op::BitOr | Op::Or => Value::Bool(truthy(&l) || truthy(&r)),
                Op::BitAnd | Op::And => Value::Bool(truthy(&l) && truthy(&r)),
                Op::Eq => Value::Bool(l == r),
            }
        }
    }
}

/// interpret a value as an integer for `respond`: numbers parse directly,
/// booleans become 1/0, anything else is 0.
fn as_i64(v: &Value) -> i64 {
    match v {
        Value::Str(s) => s.trim().parse::<i64>().unwrap_or(0),
        Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
    }
}

/// linux (x86_64) errno constants, usable directly in `respond` expressions,
/// e.g. `respond -enoent`.
fn errno_value(name: &str) -> Option<i64> {
    Some(match name {
        "EPERM" => 1,
        "ENOENT" => 2,
        "ESRCH" => 3,
        "EINTR" => 4,
        "EIO" => 5,
        "ENXIO" => 6,
        "E2BIG" => 7,
        "ENOEXEC" => 8,
        "EBADF" => 9,
        "ECHILD" => 10,
        "EAGAIN" => 11,
        "EWOULDBLOCK" => 11,
        "ENOMEM" => 12,
        "EACCES" => 13,
        "EFAULT" => 14,
        "ENOTBLK" => 15,
        "EBUSY" => 16,
        "EEXIST" => 17,
        "EXDEV" => 18,
        "ENODEV" => 19,
        "ENOTDIR" => 20,
        "EISDIR" => 21,
        "EINVAL" => 22,
        "ENFILE" => 23,
        "EMFILE" => 24,
        "ENOTTY" => 25,
        "ETXTBSY" => 26,
        "EFBIG" => 27,
        "ENOSPC" => 28,
        "ESPIPE" => 29,
        "EROFS" => 30,
        "EMLINK" => 31,
        "EPIPE" => 32,
        "EDOM" => 33,
        "ERANGE" => 34,
        "EDEADLK" => 35,
        "ENAMETOOLONG" => 36,
        "ENOLCK" => 37,
        "ENOSYS" => 38,
        "ENOTEMPTY" => 39,
        "ELOOP" => 40,
        "ENOMSG" => 42,
        "EIDRM" => 43,
        "ENOSTR" => 60,
        "ENODATA" => 61,
        "ETIME" => 62,
        "ENOSR" => 63,
        "ENONET" => 64,
        "ENOPKG" => 65,
        "EREMOTE" => 66,
        "ENOLINK" => 67,
        "EADV" => 68,
        "ESRMNT" => 69,
        "ECOMM" => 70,
        "EPROTO" => 71,
        "EMULTIHOP" => 72,
        "EDOTDOT" => 73,
        "EBADMSG" => 74,
        "EOVERFLOW" => 75,
        "ENOTUNIQ" => 76,
        "EBADFD" => 77,
        "EREMCHG" => 78,
        "ELIBACC" => 79,
        "ELIBBAD" => 80,
        "ELIBSCN" => 81,
        "ELIBMAX" => 82,
        "ELIBEXEC" => 83,
        "EILSEQ" => 84,
        "ERESTART" => 85,
        "ESTRPIPE" => 86,
        "EUSERS" => 87,
        "ENOTSOCK" => 88,
        "EDESTADDRREQ" => 89,
        "EMSGSIZE" => 90,
        "EPROTOTYPE" => 91,
        "ENOPROTOOPT" => 92,
        "EPROTONOSUPPORT" => 93,
        "ESOCKTNOSUPPORT" => 94,
        "EOPNOTSUPP" => 95,
        "ENOTSUP" => 95,
        "EPFNOSUPPORT" => 96,
        "EAFNOSUPPORT" => 97,
        "EADDRINUSE" => 98,
        "EADDRNOTAVAIL" => 99,
        "ENETDOWN" => 100,
        "ENETUNREACH" => 101,
        "ENETRESET" => 102,
        "ECONNABORTED" => 103,
        "ECONNRESET" => 104,
        "ENOBUFS" => 105,
        "EISCONN" => 106,
        "ENOTCONN" => 107,
        "ESHUTDOWN" => 108,
        "ETOOMANYREFS" => 109,
        "ETIMEDOUT" => 110,
        "ECONNREFUSED" => 111,
        "EHOSTDOWN" => 112,
        "EHOSTUNREACH" => 113,
        "EALREADY" => 114,
        "EINPROGRESS" => 115,
        "ESTALE" => 116,
        "EUCLEAN" => 117,
        "ENOTNAM" => 118,
        "ENAVAIL" => 119,
        "EISNAM" => 120,
        "EREMOTEIO" => 121,
        "EDQUOT" => 122,
        "ENOMEDIUM" => 123,
        "EMEDIUMTYPE" => 124,
        "ECANCELED" => 125,
        "ENOKEY" => 126,
        "EKEYEXPIRED" => 127,
        "EKEYREVOKED" => 128,
        "EKEYREJECTED" => 129,
        "EOWNERDEAD" => 130,
        "ENOTRECOVERABLE" => 131,
        "ERFKILL" => 132,
        "EHWPOISON" => 133,
        _ => return None,
    })
}

fn call_fn(name: &str, args: &[Value], scope: &Scope) -> Value {
    let s = |i: usize| match args.get(i) {
        Some(v) => match v {
            Value::Str(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
        },
        None => String::new(),
    };

    match name {
        "regex" => {
            let value = s(0);
            let pattern = s(1);
            match crate::runtime::regex::Regex::new(&pattern) {
                Ok(re) => Value::Bool(re.is_match(&value)),
                Err(_) => Value::Bool(false),
            }
        }
        "sed" => Value::Str(sed(&s(0), &s(1))),
        "append" => Value::Str(format!("{}{}", s(0), s(1))),
        "map_path" => {
            let root = s(0);
            let path = s(1);
            let root = root.trim_end_matches('/');
            // idempotent: a path already anchored on the rootfs passes through.
            // without this, `path = map_path(root, path)` on an already-mapped
            // path would double-prefix and land outside the sandbox tree.
            if path == root || path.starts_with(&format!("{root}/")) {
                return Value::Str(path);
            }
            // relative paths resolve against the tracee's virtual cwd first,
            // turning them into guest-absolute paths
            let guest = if path.starts_with('/') {
                path
            } else if scope.cwd == "/" {
                format!("/{path}")
            } else {
                format!("{}/{path}", scope.cwd)
            };
            // binds win: if the guest path sits under a bound source prefix,
            // translate to the bind destination (the "handler" model).
            for (src, dst) in scope.binds {
                let rest = if guest == *src {
                    Some("")
                } else if let Some(r) = guest.strip_prefix(src).and_then(|r| r.strip_prefix('/'))
                {
                    Some(r)
                } else {
                    None
                };
                if let Some(rest) = rest {
                    if rest.is_empty() {
                        return Value::Str(dst.clone());
                    }
                    return Value::Str(format!("{dst}/{rest}"));
                }
            }
            // otherwise slam the paths together: guest path onto root
            if guest.starts_with('/') {
                Value::Str(format!("{root}{guest}"))
            } else {
                Value::Str(format!("{root}/{guest}"))
            }
        }
        "bind" => Value::Str(format!("{} -> {}", s(0), s(1))),
        "get_arg" => {
            if let Some(v) = scope.args.get(&s(0)) {
                Value::Str(v.clone())
            } else {
                Value::Str(String::new())
            }
        }
        _ => Value::Str(String::new()),
    }
}

fn sed(value: &str, expr: &str) -> String {
    let rest = expr.strip_prefix("s/").unwrap_or(expr);
    let mut it = rest.splitn(2, '/');
    let pattern = it.next().unwrap_or("");
    let replacement = it.next().unwrap_or("").trim_end_matches('/');

    match crate::runtime::regex::Regex::new(pattern) {
        Ok(re) => re.replace(value, replacement),
        Err(_) => value.to_string(),
    }
}
