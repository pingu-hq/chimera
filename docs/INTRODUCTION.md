# chimera - introduction

**chimera** is a declarative syscall policy engine for Linux. instead of
sandboxing a program with `chroot`, namespaces, or a seccomp allow-list written
in raw BPF, you describe the environment in a small policy file (`.chmp`), and
chimera translates it into a seccomp filter, which a supervisor uses to rewrite and
answer syscalls for the guest, usually by fake returns or emulation.

## what chimera does

* **traps syscalls** - a tiny `no_std` trampoline (`chi`) installs a classic-BPF
  seccomp filter, chdirs into the rootfs, and passes the notification listener
  back to the supervisor.
* **runs your policy** - for each trapped syscall, the supervisor evaluates the
  matching `handle`/`syscall` bodies and either `allow`s, `deny`s with an errno,
  `respond`s with a fake return value, or rewrites syscall arguments.
* **emulates rewritten syscalls** - a syscall whose arguments the policy changed
  is executed by the supervisor itself (against the mapped host path) and the
  real result is written back into the guest's buffers. See
  [emulation](./USAGE.md#how-syscalls-are-handled).
* **fakes identity** - boots as uid/gid 0 and serves `getuid`/`geteuid`/... from
  per-process sandbox state, so `setuid`/`setgid` calls don't leak between
  processes (an apt child can drop to `_apt` while the shell stays root).
* **enforces per-file permissions** - optional `user.chimera.meta` xattrs on the
  rootfs drive access checks (see [`setup_perms`](./USAGE.md#setup_perms)).

## exemplary policy

```text
-t>
name = example
version = 2
xattr = yes
arch = x86_64
-t>

on_startup {
    bind("/proc", "/proc")
    bind("/dev", "/dev")
}

group filesystem {
    open openat stat access readlink getdents64
}

handle filesystem {
    path = map_path(root, path)
    allow
}

group identity {
    getuid geteuid getgid getegid
}

handle identity {
    respond 0
}
```

every `open` the guest makes hits the `filesystem` handle: its `path` argument
is rewritten with `map_path(root, path)`, guest `/etc/passwd` becomes
`<rootfs>/etc/passwd`, and the syscall is then allowed. identity syscalls are
answered directly (`respond 0`) instead of reaching the kernel at all.

see [POLICY.md](./POLICY.md) for the full language reference.

## what chimera is not

* **not a security boundary.** seccomp user notifications are a transformation
  layer, not a verifier. The kernel documents the TOCTOU race between a syscall
  being trapped and the supervisor answering it; chimera is a path/policy
  rewriter, not a sandbox that contains malicious code.
* **not a container runtime.** No namespaces, no cgroups, no mounts. The guest
  shares the host kernel and (for native, un-modified syscalls) the host's view
  of the system.
* **not a full virtualization layer.** Guest binaries run under the host
  dynamic linker unless the rootfs ships a compatible loader (see the known
  limitation in [USAGE.md](./USAGE.md#known-limitations)).

## the pieces

| piece       | where                              | what it is                                    |
|-------------|------------------------------------|-----------------------------------------------|
| `chimera`   | repo root crate (`src/`)           | CLI + supervisor + policy engine + emulation  |
| `chi`       | `chi/` crate                       | `no_std` seccomp trampoline (static, musl)    |
| `.chmp`     | root of the repo                   | policy files (example, hello, test, root0)    |
| `.chmd`     | `data/`                            | syscall metadata tables                       |

## next steps

* [INSTALL.md](./INSTALL.md) - install the latest release
* [USAGE.md](./USAGE.md) - the `chimera` command line
* [POLICY.md](./POLICY.md) - the `.chmp` policy language
