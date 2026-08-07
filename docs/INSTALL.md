# chimera install

## requirements

| requirement | notes |
|-------------|-------|
| Linux (x86_64) | chimera uses seccomp user notifications and currently supports x86_64 hosts |
| `curl` | used by the installer to fetch the release assets |
| a rootfs | a Linux filesystem tree for the guest, such as a Debian bootstrap or container export |
| `user.*` xattr support | required only by policies with `xattr = yes` |

`chi` installs its seccomp filter with `PR_SET_NO_NEW_PRIVS`, so neither root
nor `chroot` is required. Run `chimera` as the same user as the guest command,
because the supervisor reads guest memory with `process_vm_readv`.

## install

the installer downloads the latest GitHub release, installs `chimera-x86_64` as
`chimera`, and installs `chi-x86_64` as `chi`, and by default both go to
`/usr/local/bin`.

```bash
curl -fsSL https://raw.githubusercontent.com/pingu-hq/chimera/main/install.sh | bash
```

choose another prefix by passing it as the first argument:

```bash
curl -fsSL https://raw.githubusercontent.com/pingu-hq/chimera/main/install.sh | PREFIX="$HOME/.local" bash
```

ensure the chosen `bin` directory is on your `PATH`.

at runtime, `chimera` looks for `chi` next to its own executable. You can
override that location with `CHIMERA_CHI`.

## verify

```bash
chimera help
chimera embroider example.chmp
```

## build from source

release binaries are the supported installation path. for development builds,
the repository selects nightly Rust, the musl target, and `rust-src`. the root
workspace includes both `chimera` and `chi`, so one command builds both:

```bash
cargo +nightly build \
    -Z build-std=std,panic_abort \
    --target x86_64-unknown-linux-musl \
    --release
```

the target and `build-std` settings are also in `.cargo/config.toml`, so the
short equivalent is `cargo +nightly build --release`.

plain `cargo +nightly build` also builds both binaries for the musl target. Its
development profile uses `panic = "abort"` so the `no_std` `chi` binary builds
without unwinding support.

## get a rootfs

chimera does not create a rootfs. a Debian or Ubuntu tree works well:

```bash
debootstrap stable /srv/rootfs
```

or export and unpack a container image:

```bash
docker export "$(docker create debian:stable)" -o rootfs.tar
mkdir -p /srv/rootfs
tar -xf rootfs.tar -C /srv/rootfs
```

for policies with `xattr = yes`, seed the per-file permission metadata:

```bash
chimera setup_perms /srv/rootfs
```

see [usage](./USAGE.md#setup_perms) for details.
