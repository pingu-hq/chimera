# chimera - usage

## command overview

```
chimera conjure <policy.chmp> <rootfs> <command> [args...]
chimera embroider <policy.chmp>
chimera setup_perms [--uid U] [--gid G] <rootfs>
chimera help
```

Run `chimera help` for the built-in help page.

## conjure - run a sandbox

```
chimera conjure <policy.chmp> <rootfs> <command relative to rootfs> [args...]
```

loads the policy, forks `chi`, installs the seccomp filter, and runs `<command>`
inside the rootfs under the policy's rules. The command is *relative to the
rootfs* (e.g. `/bin/sh`, not `/srv/rootfs/bin/sh`).

example:
```bash
chimera conjure example.chmp /srv/rootfs /bin/sh
chimera conjure root0.chmp /srv/rootfs /bin/apt-get update
```

## embroider - inspect a policy

```
chimera embroider <policy.chmp>
```

compiles the policy and prints the compiler's plan plus the parsed AST without
running anything. Useful for debugging a policy before conjuring it.

```text
[chimera] trap 28 syscalls: access bind chmod clone ... 
[chimera] emulated 4 syscalls: getuid geteuid getgid getegid
[chimera] policy-modified 1 syscalls (run as supervisor): open
```

* **trap** - syscalls the seccomp filter redirects to the supervisor
* **emulated** - syscalls whose body assigns an argument and that chimera can
  emulate itself
* **policy-modified** - syscalls whose values the policy rewrites (run as the
  supervisor); warn-once at runtime if a modified syscall has no emulation
* **unknown** - policy names that aren't in the arch's syscall table

## setup_perms - seed permission metadata

```
chimera setup_perms [--uid U] [--gid G] <rootfs>
```

walks a rootfs and writes a `user.chimera.meta` xattr onto every file and
directory (default owner root:root `0:0`, host modes kept). this is the only
place chimera sets the meta xattr; at runtime it only ever reads it. the
`user.chimera.meta` payload is a tiny JSON blob:

```json
{"version":1,"uid":0,"gid":0,"mode":493}
```

with this in place, a policy with `xattr = yes` gets real per-file permission
checks: opening/reading/writing/executing is compared against the sandbox's
current identity and the file's stored uid/gid/mode.

```bash
chimera setup_perms /srv/rootfs
chimera setup_perms --uid 1000 --gid 1000 /srv/rootfs
```

## how syscalls are handled

for every trapped syscall the supervisor runs the matching policy bodies:

| policy decision | effect                                                          |
|-----------------|-----------------------------------------------------------------|
| `allow`         | syscall is `CONTINUE`'d to the kernel, untouched                 |
| `deny`          | answered with an errno (`EPERM` by default, or `deny -ENOENT`)   |
| `respond N`     | answered with a raw value, kernel never runs (`respond 0` = fake success) |
| arg assignment  | the syscall is **emulated**: run by the supervisor against the mapped path, real result written into the guest's buffers |

emulation is what makes path rewriting work. `path = map_path(root, path)` turns
guest `/etc/passwd` into `<rootfs>/etc/passwd`; the supervisor then performs the
`open` on the real host path and injects the resulting fd into the guest via
`SECCOMP_IOCTL_NOTIF_ADDFD`. everything the policy doesn't touch runs natively
with zero round trips.

the full emulated syscall set lives under `src/emulation/` and covers filesystem,
directories, metadata, fd, statfs, identity, capabilities, sysidentity, time,
procinfo, processes, xattr, memory, networking, random, and signals.

## environment

the guest never sees host environment leaks. `chimera` strips `LD_*`, language
path variables (`PYTHONPATH`, `GEM_HOME`, ...), `XDG_*`, `SSH_AUTH_SOCK`, `PWD`,
and friends from the environment before exec'ing `chi`, then re-adds a fixed
`PATH` and `HOME` for the guest. the `CHIMERA_CTRL_FD`/`CHIMERA_SYSCALLS` handshake
variables are consumed by `chi` and never reach the guest.

## known limitations

* **host dynamic linker.** the kernel loads `PT_INTERP` invisibly, so guest
  binaries run under the *host* ld.so unless the rootfs ships its own loader
  (a `chi` execve shim handles the guest-loader case). the rootfs's libc must be
  compatible with the host's glibc.
* **shebang scripts** are rewritten in place to the sandbox interpreter path so
  `$0` stays correct (needed by `basename $0` dispatchers like `adduser`).
* **not a security boundary** - see [INTRODUCTION.md](./INTRODUCTION.md).

## troubleshooting

* **`chi binary not found`** - run the install script, or point `CHIMERA_CHI` at
  a chi binary.
* **`xattr perms but rootfs does not support user.* xattrs`** - your filesystem
  (or mount) doesn't support user xattrs; run on ext4/btrfs/tmpfs, or drop
  `xattr` from the policy metadata.
* **policy modified a syscall with no emulation** - the policy rewrote an
  argument but that syscall has no emulator; it runs with the original
  arguments and a warning is printed once.
