# Owner policy (`/etc/central-agent/policy.toml`)

The owner policy lets whoever controls a server (local root) limit what Central may do on
it. Central **cannot** read-modify-write this file: the agent's file operations refuse to touch
it, and the privileged helper only re-reads it on a local reload. The agent reports the
effective policy to Central, which shows it read-only and disables actions it does not allow.
**Enforcement happens on the host, in the privileged helper**, never only in Central.

This document is the normative specification: the agent must implement it exactly, and
Central's UI relies on the capability model below.

## File location, ownership and loading

- Path: `/etc/central-agent/policy.toml` (TOML 1.0). Optional drop-ins:
  `/etc/central-agent/policy.d/*.toml`, applied in lexical order, later keys win, lists replace.
- The helper refuses to start (and keeps the previous policy on reload) if the file or any
  parent directory is writable by anyone other than root, or not owned by root (sshd
  `StrictModes` semantics).
- Missing file ⇒ built-in default (`profile = "administer"` with the defaults below). The
  package ships a commented example at `/usr/share/central-agent/policy.example.toml`.
- Reload: `sudo central-agent policy reload` or `sudo systemctl reload central-agent-helper`.
  The helper also watches the file (inotify) and reloads automatically after it changes, then
  sends `AgentEvent.TYPE_POLICY_CHANGED` and a `PolicyReport`.
- Invalid file ⇒ the helper keeps the last good policy (or, at startup, falls back to
  `observe`) and reports the parse error in `EffectivePolicy.warnings`.
- `sudo central-agent policy check [file]` validates a file without applying it.
  `central-agent policy show` prints the effective policy.
- `digest` = lowercase hex SHA-256 over the concatenated bytes of the main file and drop-ins
  (in load order, each prefixed by its path and a NUL byte).

## Schema

```toml
# /etc/central-agent/policy.toml — owned by root:root, mode 0644.
# Only the machine owner can change this file. Central can never modify it.
version = 1

# observe | operate | administer | full        (install default: administer)
profile = "administer"

# Owner kill switch: refuse every remote operation (same as `central-agent pause`).
paused = false
# Keep sending metrics/inventory while paused.
telemetry_while_paused = true

[capabilities]
# Add or remove individual capabilities relative to the profile (names from the table below,
# lowercase with dots, e.g. "files.write", "terminal").
allow = []
deny = []

[files]
# Doublestar globs matched against the fully resolved path.
read_allow = ["/**"]
write_allow = ["/srv/**", "/var/www/**", "/home/*/**"]
# Added to the built-in deny lists below. Deny always wins.
deny = []
# Permit chmod with setuid/setgid bits.
allow_setuid = false

[packages]
# Globs on package names that may be installed. Upgrades of installed packages are not
# restricted by this list.
install_allow = ["*"]
# Never install or remove these (the agent's own package is always included).
deny = []

[users]
# Never modified (root, the central-agent user and every member of a privileged group are
# always protected unless allow_privileged_groups = true).
protected_users = []
# Allow adding users to / modifying members of: sudo, admin, wheel, adm, root, disk, shadow,
# docker, lxd, incus-admin, libvirt, kvm.
allow_privileged_groups = false

[services]
# Units that cannot be stopped, disabled or masked (globs). The agent's units, and
# debug-shell.service / emergency.service / rescue.service, are always protected.
protected_units = ["ssh.service", "sshd.service"]

[run_as]
# Linux users that terminals and exec may run as (requires the terminal/exec capability).
allowed_users = []
default_user = ""
allow_root = false

[network]
# Smallest confirm window Central may request for network/firewall changes (seconds).
min_confirm_timeout_seconds = 60

[agent]
# Allow Central to uninstall the agent (AgentUninstall).
allow_remote_uninstall = false
```

Unknown keys produce a warning (not an error) so newer policies degrade gracefully on older
agents; unknown capability names in `allow` are ignored with a warning.

## Profiles and capabilities

| Capability (`name` in TOML) | observe | operate | administer | full |
| --------------------------- | :-----: | :-----: | :--------: | :--: |
| `telemetry`                 | ✓ | ✓ | ✓ | ✓ |
| `packages.read`             | ✓ | ✓ | ✓ | ✓ |
| `packages.upgrade`          |   | ✓ | ✓ | ✓ |
| `packages.install`          |   |   | ✓ | ✓ |
| `packages.remove`           |   |   | ✓ | ✓ |
| `services.read`             | ✓ | ✓ | ✓ | ✓ |
| `services.manage`           |   | ✓ | ✓ | ✓ |
| `logs.read`                 | ✓ | ✓ | ✓ | ✓ |
| `processes.read`            | ✓ | ✓ | ✓ | ✓ |
| `processes.signal`          |   | ✓ | ✓ | ✓ |
| `power`                     |   | ✓ | ✓ | ✓ |
| `network.read`              | ✓ | ✓ | ✓ | ✓ |
| `network.manage`            |   |   | ✓ | ✓ |
| `firewall.manage`           |   |   | ✓ | ✓ |
| `files.read`                |   |   | ✓ | ✓ |
| `files.write`               |   |   | ✓ | ✓ |
| `files.permissions`         |   |   | ✓ | ✓ |
| `users.read`                | ✓ | ✓ | ✓ | ✓ |
| `users.manage`              |   |   | ✓ | ✓ |
| `storage.read`              | ✓ | ✓ | ✓ | ✓ |
| `agent.upgrade`             |   | ✓ | ✓ | ✓ |
| `agent.uninstall`           |   |   |   | (✓ if `allow_remote_uninstall`) |
| `exec`                      |   |   |   | ✓ |
| `terminal`                  |   |   |   | ✓ |

These map 1:1 to `central.agent.v1.Capability`. Every `Operation` maps to exactly one
capability (documented on each message in `proto/central/agent/v1/*.proto`).

`full` also changes defaults: `files.read_allow`/`write_allow` = `["/**"]`, the escalation
deny lists are not applied (only the hardcoded protections), `run_as.allow_root = true` and
`allowed_users = ["root"]` unless configured, and `allow_privileged_groups = true`.

## Hardcoded protections (every profile, cannot be disabled)

Typed operations always refuse to:

- write, delete, rename, chmod or chown anything under `/etc/central-agent/`,
  `/var/lib/central-agent/`, `/var/lib/central-agent-helper/`, `/usr/lib/central-agent/`,
  `/usr/bin/central-agent*`, or any `central-agent*` systemd unit file or drop-in;
- read the agent's private key or the helper's state;
- stop, disable, mask or signal the agent's own services and processes;
- remove, hold or downgrade the `central-agent` package (only `AgentUpgrade` /
  `AgentUninstall` touch it);
- modify `root` or the `central-agent` user/group;
- signal PID 1 or kernel threads.

## Escalation deny lists (profiles below `full`)

Writing any of these paths would let Central obtain root (or rewrite the policy) indirectly,
so `files.write` / `files.permissions` refuse them even if `write_allow` matches:

```
/etc/sudoers  /etc/sudoers.d/**          /etc/crontab  /etc/cron*/**  /var/spool/cron/**
/etc/systemd/**  /lib/systemd/**  /usr/lib/systemd/**  /run/systemd/**
/etc/init.d/**  /etc/rc*.d/**  /etc/rc.local
/etc/apt/**  /usr/share/keyrings/**  /var/lib/dpkg/**  /var/lib/apt/**
/etc/passwd  /etc/shadow  /etc/group  /etc/gshadow  /etc/subuid  /etc/subgid
/etc/pam.d/**  /etc/security/**  /etc/ssh/**  /etc/polkit-1/**  /etc/dbus-1/**
/etc/ld.so.preload  /etc/ld.so.conf  /etc/ld.so.conf.d/**
/etc/profile  /etc/profile.d/**  /etc/bash.bashrc  /etc/environment  /etc/default/**
/etc/logrotate.conf  /etc/logrotate.d/**  /etc/update-motd.d/**
/etc/udev/**  /etc/modprobe.d/**  /etc/modules-load.d/**  /etc/sysctl.conf  /etc/sysctl.d/**
/etc/network/**  /etc/netplan/**  /etc/NetworkManager/**  /etc/networkd-dispatcher/**
/etc/dhcp/**  /etc/ufw/**  /etc/xinetd.d/**  /etc/inetd.conf
/etc/supervisor/**  /etc/docker/**  /etc/containerd/**
/root/**  /home/*/.*  /home/*/.*/**
/boot/**  /usr/**  /bin/**  /sbin/**  /lib/**  /lib32/**  /lib64/**  /libx32/**
/proc/**  /sys/**  /dev/**  /run/**  /var/run/**
```

(Network and firewall files are changed only through `NetworkApply` / `FirewallApply`, which
validate content; user files only through the users operations; `authorized_keys` only through
`AuthorizedKeysSet`.)

Reads are refused for secrets even if `read_allow` matches:

```
/etc/shadow  /etc/gshadow  /etc/ssh/ssh_host_*_key  /root/.ssh/**  /home/*/.ssh/id_*
/var/lib/central-agent/**  /var/lib/central-agent-helper/**
/proc/*/environ  /proc/*/mem  /proc/kcore  /dev/**
```

## What the policy can and cannot guarantee

Be honest with owners about this — the UI and docs repeat it:

- **`observe` and `operate` are strongly enforceable.** They grant no file writes, no package
  installs, no user management, no exec and no terminal. A compromised Central can at worst
  restart services, upgrade already-installed packages from configured repositories, signal
  processes and reboot.
- **`administer` is enforceable against the known generic escalation paths above**, but not
  absolutely: any writable location that a root process consumes as configuration or code can
  potentially be turned into root. Keep `files.write_allow` narrow (data directories, not the
  configuration of daemons that run as root — e.g. avoid `/etc/nginx/**` if nginx's master runs
  as root and loads modules), and review which packages you allow.
  - `users.manage` refuses to change members of privileged groups (or users matched by
    sudoers rules) unless `allow_privileged_groups = true`, because setting such a user's
    password or SSH keys is root-equivalent.
  - `network.manage` validates configuration: ifupdown `up`/`down`/`pre-up`/`post-down`/
    `source` directives and netplan keys outside a known-safe allow list are rejected, because
    they run commands as root.
  - Enabling `terminal` or `exec` under `administer` requires a non-root `run_as` user; if
    that user can sudo, it is root-equivalent.
- **`full` is root-equivalent.** A root terminal can rewrite this file, so the policy is
  advisory under `full`. Choose `full` only for servers where you trust Central (and whoever
  operates it) with root.
- Phase 2 will add **owner-signed commands**: the policy can require that high-risk operations
  carry a signature from a key the owner holds (e.g. a hardware security key), which a
  compromised Central cannot forge.

## Owner tooling

| Command | Effect |
| ------- | ------ |
| `sudo central-agent pause [--reason TEXT]` | Sets the paused flag in `/var/lib/central-agent-helper/paused` (root-only). Every command is rejected with `PAUSED`; Central is notified. |
| `sudo central-agent resume` | Clears the paused flag. |
| `central-agent policy show` | Prints the effective policy and digest. |
| `sudo central-agent policy check [FILE]` | Validates a policy file. |
| `sudo central-agent policy reload` | Reloads the policy now. |
| `sudo central-agent audit [--since …]` | Shows the helper's local audit log. |

### Local audit log

The helper appends one JSON line per command decision (accepted/rejected, capability,
command ID, issuer, result, duration) to `/var/log/central-agent/audit.log` (root:adm 0640) and
to journald (`SYSLOG_IDENTIFIER=central-agent-helper`). Central cannot delete or rewrite it.
Secrets (passwords, file contents) are never logged — only their presence and size.
