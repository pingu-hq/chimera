# chimera

**declarative syscall policy engine for Linux**

chimera is a proot-like sandbox built on seccomp user notifications. you write a
small `.chmp` policy describing how syscalls should be rewritten and answered;
chimera traps the syscalls, runs your policy on each one, and emulates the ones
you modify. no `chroot`, mounts, or namespaces are required.

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

## quick start

```bash
# install the latest GitHub release
curl -fsSL https://raw.githubusercontent.com/pingu-hq/chimera/main/install.sh | bash

# inspect a policy
chimera embroider example.chmp

# run a shell in a rootfs under the policy
chimera conjure example.chmp /srv/rootfs /bin/sh
```

## docs

* [introduction](./docs/INTRODUCTION.md) - what chimera is and how it works
* [install](./docs/INSTALL.md) - install the latest release
* [usage](./docs/USAGE.md) - the `chimera` command line
* [policy](./docs/POLICY.md) - the `.chmp` policy language reference

## layout

| path          | what                                                |
|---------------|-----------------------------------------------------|
| `src/`        | the `chimera` supervisor: policy engine + emulation |
| `chi/`        | the `no_std` seccomp trampoline (static, musl)      |
| `data/`       | syscall metadata tables (`.chmd`)                   |
| `*.chmp`      | example policies                                    |
| `docs/`       | documentation                                       |
