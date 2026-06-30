# earth Rust MVP

This is a prototype local-first folder sharing CLI. It supports password-backed local accounts, one daemon per account, LAN mDNS discovery, snapshot sync, and simplified line-based CRDT merging for text/code files.

## Current account/daemon model

The program now uses **Option 1: one daemon per logged-in user/account**.

Each account is isolated under:

```text
~/.earth/accounts/<account_id>/
  config.tsv
  account.lock
  shares.tsv
  shares/
  crdts/
  blobs/
  logs/
```

Global metadata lives under:

```text
~/.earth/global/
  active_account.tsv
  port_allocations.tsv
```

The first account gets port `7878`, the next gets `7879`, then `7880`, etc. You can override this during login with `--port`.

## Login starts the daemon by default

```bash
earth login fran --password 'test-password-123'
```

This now does all of the following:

1. Creates or unlocks the password-backed local account.
2. Sets it as the active account.
3. Starts the account-specific daemon by default.
4. Advertises the daemon over mDNS as `_earth._tcp.local`.
5. Discovers same-account peers on the LAN.
6. Prints available remote shares.

Use `--no-start` if you want login without a background daemon:

```bash
earth login fran --password 'test-password-123' --no-start
```

Use `--no-discover` if you want to skip the post-login peer scan:

```bash
earth login fran --password 'test-password-123' --no-discover
```

## Basic usage

Device 1:

```bash
earth login fran --password 'test-password-123'
mkdir -p ./example_dir
echo 'hello from device 1' > ./example_dir/notes.txt
earth init ./example_dir
```

Device 2, same LAN:

```bash
earth login fran --password 'test-password-123'
earth list --discover
earth clone example_dir ./example_dir --discover
```

After that, both account daemons should discover each other and sync common shares automatically.

## Multiple accounts on one machine

```bash
earth login fran --password 'test-password-123'
earth login alex --password 'other-password-123'
```

This creates two isolated account directories and two daemon instances on different ports.

Commands resolve the account in this order:

1. `--account <user-or-account-id>`
2. `EARTH_ACCOUNT`
3. active account from the latest login/use command

Examples:

```bash
earth init ./fran_project --account fran
earth init ./alex_project --account alex
earth use fran
earth list
```

## Lifecycle commands

Show all accounts and whether their daemons are reachable:

```bash
earth status
```

Show one account:

```bash
earth status --account fran
```

Stop one account daemon:

```bash
earth stop --account fran
```

Stop all account daemons:

```bash
earth stop --all
```

## Manual daemon command

Normally you do not need this because login starts the daemon by default.

```bash
earth daemon --account fran
```

The daemon:

- acquires `account.lock` for that account,
- binds the account's assigned port,
- advertises the account over mDNS,
- listens for incoming sync/control requests,
- scans local shares,
- discovers same-account peers,
- syncs snapshots with compatible peers.

## Notes and limitations

This is still an MVP, not production-ready software.

Current limitations:

- text CRDT is a simplified line-based CRDT, not full Automerge yet;
- sync protocol exchanges snapshots, not incremental operations;
- authentication is account-ID based, not full signed device auth yet;
- blob files are copied by hash but conflict handling is still basic;
- lock handling removes stale locks only during auto-start if no daemon responds.

Good next upgrades:

- real device keypairs and signed peer handshakes;
- encrypted share keys;
- Automerge or Yjs document backend;
- file watcher events plus periodic scan;
- chunked blob transfer;
- systemd user service integration.

## Build

```bash
cargo build
```

## Test with isolated local homes

Terminal 1:

```bash
rm -rf /tmp/lsdev1 /tmp/lsdev2 /tmp/a /tmp/b
mkdir -p /tmp/a/example_dir
printf 'int main() {\n    return 0;\n}\n' > /tmp/a/example_dir/main.c
PROGRAM_HOME=/tmp/lsdev1 cargo run -- login fran --password 'test-password-123' --port 9001
PROGRAM_HOME=/tmp/lsdev1 cargo run -- init /tmp/a/example_dir
```

Terminal 2:

```bash
PROGRAM_HOME=/tmp/lsdev2 cargo run -- login fran --password 'test-password-123' --port 9002
PROGRAM_HOME=/tmp/lsdev2 cargo run -- list --discover
PROGRAM_HOME=/tmp/lsdev2 cargo run -- clone example_dir /tmp/b/example_dir --discover
```

Then edit both `main.c` files and allow the daemons to sync.

## Editor temporary files

The scanner ignores common editor-generated temporary files so they do not become shared files. This includes Vim swap/backup files such as:

```text
.test.txt.swp
.test.txt.swo
test.txt~
test.txu~
test.txv~
```

It also ignores a few common transient files such as `.DS_Store`, `Thumbs.db`, `4913`, `#file#`, `.#file`, `*.tmp`, `*.part`, and `*.crdownload`.

If an older daemon already synced these files, delete them once locally. After every device is running this version, the next scan prunes ignored paths from the manifest so they stop propagating.

## Editor-safe daemon rendering

This version avoids the Vim `E949: File changed while writing` race by changing daemon behavior:

- Local scan no longer immediately renders files back into the same folder.
- Visible file writes are hash-guarded; unchanged files are not rewritten.
- Vim/Emacs active editor markers defer visible renders:
  - `.file.swp`, `.file.swo`, `.file.swn`, etc.
  - `.#file`
- Recently modified files are not imported until they have been quiet for about 1.2 seconds.
- Incoming remote updates are still merged, but the final write to the visible file is deferred while an editor has the file open.

With Vim, the expected behavior is:

```bash
vim test.txt
# edit and save normally
```

The daemon should import the saved change after the file becomes stable, sync it to peers, and avoid rewriting `test.txt` while Vim's swap file exists.
