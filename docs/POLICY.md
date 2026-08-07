# chimera policy - `.chmp` reference

a chimera policy (`.chmp`) is a small declarative language that describes how to
rewrite and answer a guest's syscalls. current format is **API v2**.

## file structure

```
-t>
name = example
version = 2
xattr = yes
arch = x86_64
-t>

on_startup { ... }
on_exit { ... }

group NAME { syscall @group ... }
handle NAME { statements }
syscall NAME { statements }     # per-syscall override
```

Comments start with `#` and run to the end of the line. Identifiers may contain
letters, digits, and `_`. Strings use double quotes.

## metadata section

The optional-but-required `-t> ... -t>` block at the top holds policy metadata as
`key = value` lines:

| key       | meaning                                            |
|-----------|----------------------------------------------------|
| `name`    | policy name (free text)                            |
| `version` | API version; must be a number >= `2`               |
| `xattr`   | `yes`/`no` - enable `user.chimera.meta` permission checks |
| `arch`    | target architecture string (e.g. `x86_64`)         |

A policy without a metadata section fails to load. Unknown keys produce a
warning and are preserved.

```text
-t>
name = example
version = 2
xattr = yes
arch = x86_64
-t>
```

## blocks

### on_startup

runs once when the sandbox boots. Its `bind` statements set up path binds that
`map_path` consults (binds win over root mapping):

```
on_startup {
    bind("/proc", "/proc")
    bind("/dev", "/dev")
    bind("/etc/resolv.conf", "/etc/resolv.conf")
}
```

a bind maps a *guest* path (first arg) to a *host* path (second arg). the
example above keeps `/proc`, `/dev`, and DNS reachable from their real host
locations while everything else falls through to the rootfs.

### on_exit

parsed and validated like any block, reserved for future use. it is not executed
at runtime yet.

### group

collects syscalls by name and by inclusion of other groups:

```
group filesystem {
    open
    openat
    stat
    access
    readlink
    getdents64
}

group everything {
    @filesystem
    @process
    @identity
}
```

* syscalls are named as in the arch table (see `data/syscalls.chmd`)
* `@group` includes expand transitively; circular nesting and duplicate group
  names are errors
* syscalls in a group with a `handle` get trapped; a handle-less group that
  doesn't need emulation is never trapped

### handle

attaches a body to a *group name*. the body runs for every syscall in the group:

```
handle filesystem {
    path = map_path(root, path)
    allow
}
```

`map_path(root, path)` resolves the guest path onto the rootfs (`/etc/passwd` →
`<rootfs>/etc/passwd`), or through a bind if the path sits under a bound prefix.

### syscall (override)

attaches a body to a *single syscall*. overrides run **before** group handles, so
they can special-case one syscall without splitting the group:

```
syscall openat {
    path = map_path(root, path)
    allow
}
```

## statements

| statement                | meaning                                                       |
|--------------------------|---------------------------------------------------------------|
| `allow`                  | let the syscall through untouched (kernel runs it)            |
| `deny`                   | block it with `EPERM`                                         |
| `deny -ENOENT`           | block it with the given errno                                 |
| `respond <expr>`         | answer with a raw value; the kernel never runs the syscall    |
| `echo("...")`            | print a message to the supervisor's stdout                    |
| `echo_args`              | print the syscall's argument map (sorted)                     |
| `if <expr> { } else { }` | conditional body                                              |
| `bind("a", "b")`         | in `on_startup`: register a path bind; elsewhere: prints `a -> b` |
| `name = <expr>`          | assign: rewrite a syscall arg, or set a local variable        |

### allow / deny / respond

`allow` `CONTINUE`s the syscall into the kernel with its (possibly rewritten)
arguments. `deny` answers with an errno instead of running anything. `respond`
answers with a literal value - `respond 0` fakes success without the kernel
being involved (the classic fakeroot trick):

```
handle identity {
    respond 0
}

handle metadata {
    # fakeroot behavior: pretend chown/chmod succeeded
    respond 0
}
```

only the **first** decision in a body counts (`outcome.decision` is set once).

### assignment

an assignment targets a syscall argument by name if the syscall has one;
otherwise it creates a *local* variable. assigning to `root` or `cwd` is
read-only and warned about.

```
path = map_path(root, path)     # rewrites the open()'s path
flags = "0"                     # rewrites the flags argument
myvar = append(prefix, path)    # local variable
```

rewriting an argument marks the syscall as **modified**, which makes the
supervisor *emulate* it: it runs the syscall itself on the resolved values and
writes the result back into the guest's buffers. `echo_args` is handy for
discovering what arguments a syscall exposes.

### conditionals

```
handle filesystem {
    if regex(path, "^/proc/") {
        allow
    } else {
        path = map_path(root, path)
        allow
    }
}
```

## expressions

| form        | meaning                                             |
|-------------|-----------------------------------------------------|
| `"string"`  | string literal                                      |
| `123`       | number literal (treated as a string)                |
| `ident`     | variable: syscall arg, `root`, `cwd`, errno, local  |
| `fn(a, b)`  | function call                                       |
| `-expr`     | numeric negation (used for errnos: `-ENOENT`)       |
| `a | b`     | logical **or** (truthy)                             |
| `a == b`    | equality (string comparison)                        |

truthiness: a boolean, any non-empty string, or a string that isn't `"0"`.
numbers are handled as strings; `respond` and `deny` parse them as integers
(unparseable → `0`, booleans → `1`/`0`).

## built-in variables

* **`root`** - the rootfs path (host side)
* **`cwd`** - the guest's virtual current working directory
* **syscall arguments** - named per the arch table, e.g. `path`, `dirfd`,
  `flags`, `mode`, `oldpath`, `newpath`, `target`, `linkpath`, `buffer`, `fd`,
  `length`, `domain`, `type`, `protocol`, ...
* **errno constants** - every Linux x86_64 errno name resolves to its number,
  e.g. `EPERM` (1), `ENOENT` (2), `EACCES` (13), `EINVAL` (22). The full table
  lives in `src/runtime/exec.rs`.

## built-in functions

| function                  | result                                                       |
|---------------------------|--------------------------------------------------------------|
| `map_path(root, path)`    | resolve a guest path: binds win, then rootfs prefixing; already-mapped paths pass through idempotently; relative paths resolve against `cwd` first |
| `regex(value, pattern)`   | `true` if `value` matches the regex                          |
| `sed(value, "s/a/b/")`    | regex replace (first match), `sed`-style                     |
| `append(a, b)`            | `a` concatenated with `b`                                    |
| `get_arg(name)`           | fetch a syscall arg by name (deprecated - args are direct)   |
| `bind(a, b)`              | expression form returns the string `a -> b`                  |

## syscall arguments (common)

```
open:     path, flags, mode
openat:   dirfd, path, flags, mode
creat:    path, mode
stat:     path, stat
lstat:    path, stat
newfstatat: dirfd, path, stat, flags
statx:    dirfd, path, flags, mask, stat
access:   path, mode
faccessat: dirfd, path, mode, flags
readlink: path, buffer, bufsiz
readlinkat: dirfd, path, buffer, bufsiz
getdents64: fd, dirp, count
chdir:    path
getcwd:   buffer, length
mkdir:    path, mode
mkdirat:  dirfd, path, mode
rmdir:    path
unlink:   path
unlinkat: dirfd, path, flags
rename:   oldpath, newpath
renameat: olddirfd, oldpath, newdirfd, newpath
symlink:  target, linkpath
symlinkat: target, newdirfd, linkpath
chmod:    path, mode
chown:    path, owner, group
truncate: path, length
execve:   path, argv, envp
clone:    fn, stack, flags, arg, parent_tid, tls, child_tid
getrandom: buffer, length, flags
socket:   domain, type, protocol
connect:  fd, buffer, address_length
bind:     fd, buffer, address_length
```

## full example

```text
# ==========================================
# example.chmp - chimera policy (api v2)
# ==========================================

-t>
name = example
version = 2
xattr = yes
arch = x86_64
-t>

on_startup {
    bind("/proc", "/proc")
    bind("/sys", "/sys")
    bind("/dev", "/dev")
    bind("/etc/resolv.conf", "/etc/resolv.conf")
}

group filesystem {
    open openat stat access readlink getdents64
}

group directories {
    chdir getcwd mkdir rmdir unlink rename symlink
}

group process {
    clone fork execve exit exit_group wait4
}

group identity {
    getuid geteuid getgid getegid setuid setgid
}

group everything {
    @filesystem
    @directories
    @process
    @identity
}

handle filesystem {
    path = map_path(root, path)
    allow
}

handle directories {
    allow
}

handle process {
    allow
}

handle identity {
    respond 0
}

syscall openat {
    if regex(path, "^/etc/shadow") {
        deny -EACCES
    }
    path = map_path(root, path)
    allow
}
```

see the repo root for `example.chmp` (a proot-style identity policy).

## validation & warnings

`chimera embroider` (and `conjure`, before running) reports:

* **errors** - missing metadata section, `version` below 2, duplicate groups,
  undefined `@include`, circular group nesting, bad syntax
* **warnings** - unknown metadata keys, handles referencing undefined groups,
  assignment to read-only `root`/`cwd`, deprecated `get_arg`, syscalls modified
  by the policy but not emulated
