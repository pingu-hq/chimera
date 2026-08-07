use super::chmp::*;
use std::collections::HashMap;

pub fn validate(policy: &mut Policy) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();

    if !policy.meta.present {
        return Err(
            "policy has no metadata section (-t> ... -t>); add name/version/xattr/arch".into(),
        );
    }

    // api version gate: v2 is the current floor. `version` names the policy
    // format, not the policy's own revision.
    let api = policy
        .meta
        .version
        .as_deref()
        .ok_or_else(|| "metadata: 'version' is required (api v2)".to_string())?;
    let api: u32 = api.parse().map_err(|_| {
        format!("metadata: api version '{api}' is not a number (v2 is the minimum)")
    })?;
    if api < 2 {
        return Err(format!(
            "metadata: api version {api} is not supported; v2 is the minimum"
        ));
    }

    for (k, v) in &policy.meta.raw {
        match k.as_str() {
            "name" | "version" | "arch" => {}
            "xattr" => {
                let ok = matches!(
                    v.to_ascii_lowercase().as_str(),
                    "yes" | "true" | "1" | "on" | "no" | "false" | "0" | "off"
                );
                if !ok {
                    warnings.push(format!("metadata: xattr = {v:?} is not a yes/no value"));
                }
            }
            _ => warnings.push(format!("metadata: unknown key '{k}'")),
        }
    }

    let mut index: HashMap<String, usize> = HashMap::new();
    for (i, g) in policy.groups.iter().enumerate() {
        if index.insert(g.name.clone(), i).is_some() {
            return Err(format!("duplicate group '{}'", g.name));
        }
    }

    for i in 0..policy.groups.len() {
        let name = policy.groups[i].name.clone();
        let mut stack = vec![name.clone()];
        let mut flat = Vec::new();
        let includes = std::mem::take(&mut policy.groups[i].includes);
        for inc in &includes {
            expand(&policy.groups, &index, inc, &mut stack, &mut flat)?;
        }
        policy.groups[i].syscalls.append(&mut flat);
    }

    for h in &policy.handles {
        if !index.contains_key(&h.group) {
            warnings.push(format!(
                "handle '{}' references undefined group '{}'",
                h.group, h.group
            ));
        }
    }

    check_body(&policy.on_startup, &mut warnings, "on_startup");
    check_body(&policy.on_exit, &mut warnings, "on_exit");
    for h in &policy.handles {
        check_body(&h.body, &mut warnings, &format!("handle '{}'", h.group));
    }
    for o in &policy.overrides {
        check_body(&o.body, &mut warnings, &format!("syscall '{}'", o.name));
    }

    Ok(warnings)
}

fn expand(
    groups: &[Group],
    index: &HashMap<String, usize>,
    name: &str,
    stack: &mut Vec<String>,
    out: &mut Vec<String>,
) -> Result<(), String> {
    let idx = *index
        .get(name)
        .ok_or_else(|| format!("group '{}' referenced but not defined", name))?;

    if stack.contains(&name.to_string()) {
        let mut cycle = stack.clone();
        cycle.push(name.to_string());
        return Err(format!(
            "circular group nesting: {}",
            cycle.join(" -> ")
        ));
    }

    stack.push(name.to_string());
    let g = &groups[idx];
    for s in &g.syscalls {
        out.push(s.clone());
    }
    for inc in &g.includes {
        expand(groups, index, inc, stack, out)?;
    }
    stack.pop();

    Ok(())
}

fn check_body(stmts: &[Statement], warnings: &mut Vec<String>, what: &str) {
    for s in stmts {
        match s {
            Statement::Assign(name, expr) => {
                if name == GLOBAL_ROOT || name == GLOBAL_CWD {
                    warnings.push(format!(
                        "{what}: assignment to read-only '{name}' ignored"
                    ));
                }
                check_expr(expr, warnings, what);
            }
            Statement::Conditional(c) => {
                check_expr(&c.expr, warnings, what);
                check_body(&c.then, warnings, what);
                if let Some(o) = &c.otherwise {
                    check_body(o, warnings, what);
                }
            }
            Statement::Respond(expr) => {
                check_expr(expr, warnings, what);
            }
            Statement::Deny(Some(expr)) => {
                check_expr(expr, warnings, what);
            }
            _ => {}
        }
    }
}

fn check_expr(expr: &Expr, warnings: &mut Vec<String>, what: &str) {
    match expr {
        Expr::Call(name, args) => {
            if name == "get_arg" {
                warnings.push(format!(
                    "{what}: get_arg() is deprecated; syscall args are available directly"
                ));
            }
            for a in args {
                check_expr(a, warnings, what);
            }
        }
        Expr::BinOp(l, _, r) => {
            check_expr(l, warnings, what);
            check_expr(r, warnings, what);
        }
        _ => {}
    }
}
