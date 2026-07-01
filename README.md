# Earth

Earth is a prototype **local-first folder sharing CLI** for Ubuntu/Linux. It is designed for people who want to share a normal folder between their own devices, keep working offline, and have changes automatically sync when devices meet again on the same network.

The goal is a workflow like this:

```bash
earth login alice
earth init ./example_dir
```

Then, on another device:

```bash
earth login alice
earth list
earth clone example_dir ./example_dir
```

After that, both devices keep `example_dir` synchronized automatically through an account-specific background daemon.

> Status: **MVP / experimental prototype.** Earth is useful for testing the architecture, but it is not production-ready yet.

---

## What Earth does

Earth turns a regular folder into a local-first share:

```text
example_dir/
  notes.txt
  main.c
  image.png
  subfolder/
    test.h
```

Each device keeps its own local copy. You can edit files while offline. When two devices using the same account come back onto the same LAN, Earth discovers the peer and syncs common shares.

Earth currently supports:

- password-backed local accounts;
- one isolated daemon per logged-in account;
- automatic daemon startup on login;
- mDNS LAN discovery using `_earth._tcp.local`;
- account-scoped peer filtering;
- share creation from an existing folder;
- remote share listing and cloning;
- text/code file merging using a simplified line-based CRDT-like merge;
- blob syncing for non-text files;
- editor-temp-file ignoring for Vim, Emacs, OS junk, and common temp downloads;
- editor-safe rendering to avoid fighting Vim while a file is open.

---

## Why Earth is different

Earth sits between tools like Syncthing, Git, and CRDT document editors.

### Compared with Syncthing

Syncthing is excellent for peer-to-peer folder sync. Earth is trying to add a CRDT-aware text/code layer on top of that style of workflow.

```text
Syncthing:
  great folder sync
  great LAN/offline sync
  conflict files for simultaneous edits

Earth:
  folder sync style UX
  automatic LAN/offline sync
  tries to merge text/code files automatically
```

### Compared with Git

Git is great for source code history and manual merges, but it is not a continuous background folder sync daemon.

```text
Git:
  explicit commit/push/pull workflow
  great history
  manual conflict workflow

Earth:
  daemon-based sync
  normal folder workflow
  intended for automatic merge/sync between your devices
```

### Compared with Dropbox/Drive

Cloud drives usually require a cloud service as the center of truth. Earth is designed around local-first peer sync.

```text
Cloud drive:
  cloud is central
  devices sync through provider

Earth:
  devices keep local state
  LAN peers sync directly
  offline-first by design
```

### Compared with CRDT editors

CRDT editors merge document changes well, but usually operate inside a specific app. Earth exposes the shared state as normal files and folders so you can keep using Vim, GCC, VS Code, scripts, and normal shell tools.

---

## Mental model

Earth should not be thought of as simply copying files from one machine to another.

The intended architecture is:

```text
local folder changes
  -> internal share state
  -> text/code merge state
  -> peer sync
  -> merged state
  -> visible folder output
```

The visible folder is the user interface. The daemon keeps account state, share metadata, text merge state, and blob data under `~/.earth/`.

---

## Account and daemon model

Earth uses **one daemon per logged-in user/account**.

That means:

```text
alice account -> alice daemon -> alice shares only
alex account -> alex daemon -> alex shares only
```

Accounts are isolated under:

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

The first account usually gets port `7878`, the next gets `7879`, then `7880`, etc. You can override this during login with `--port`.

---

## Install on Ubuntu

### 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl
```

### 2. Install Rust if needed

```bash
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
```

### 3. Build Earth

From the repo directory:

```bash
cargo build --release
```

### 4. Install the binary

System-wide install:

```bash
sudo install -m 755 target/release/earth /usr/local/bin/earth
```

User-only install:

```bash
mkdir -p ~/.local/bin
cp target/release/earth ~/.local/bin/earth
chmod +x ~/.local/bin/earth
```

Make sure `~/.local/bin` is in your PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Verify:

```bash
earth --help
earth status
```

---

## Quick start

### Device 1

```bash
earth login alice --password 'test-password-123'
mkdir -p ./example_dir
echo 'hello from device 1' > ./example_dir/notes.txt
earth init ./example_dir
```

`earth login` starts the daemon by default. The daemon advertises this account on the LAN, scans local shares, discovers same-account peers, and syncs common shares.

### Device 2 on the same LAN

```bash
earth login alice --password 'test-password-123'
earth list
earth clone example_dir ./example_dir
```

After cloning, both devices should keep the share synchronized while their daemons are running.

---

## Login behavior

By default:

```bash
earth login alice --password 'test-password-123'
```

Does all of this:

1. creates or unlocks the password-backed local account;
2. sets it as the active account;
3. starts the account-specific daemon;
4. advertises the daemon over mDNS as `_earth._tcp.local`;
5. discovers same-account peers on the LAN;
6. prints available remote shares.

Skip daemon startup:

```bash
earth login alice --password 'test-password-123' --no-start
```

Skip post-login peer discovery:

```bash
earth login alice --password 'test-password-123' --no-discover
```

Use a specific daemon port:

```bash
earth login alice --password 'test-password-123' --port 9001
```

For scripts/tests, you can also use:

```bash
EARTH_PASSWORD='test-password-123' earth login alice
```

---

## Common commands

Create a share from an existing folder:

```bash
earth init ./example_dir
```

List available shares from discovered peers:

```bash
earth list
```

Clone a remote share into a local folder:

```bash
earth clone example_dir ./example_dir
```

Show discovered peers manually:

```bash
earth peers --timeout 10
```

Run a one-shot sync:

```bash
earth sync
```

Show daemon/account status:

```bash
earth status
```

Stop one account daemon:

```bash
earth stop --account alice
```

Stop all Earth daemons:

```bash
earth stop --all
```

Switch the active account:

```bash
earth use alice
```

Show the active account:

```bash
earth whoami
```

---

## Multiple accounts on one machine

Earth supports multiple accounts by running one daemon per account.

```bash
earth login alice --password 'test-password-123'
earth login alex --password 'other-password-123'
```

This creates two isolated account directories and two daemon instances on different ports.

Commands resolve the account in this order:

1. `--account <user-or-account-id>`
2. `EARTH_ACCOUNT`
3. active account from the latest `login` or `use` command

Examples:

```bash
earth init ./alice_project --account alice
earth init ./alex_project --account alex
earth use alice
earth list
```

---

## Manual daemon command

Normally you do not need this because `earth login` starts the daemon by default.

```bash
earth daemon --account alice
```

The daemon:

- acquires `account.lock` for that account;
- binds the account's assigned port;
- advertises over mDNS;
- listens for incoming sync/control requests;
- scans local shares;
- discovers same-account peers;
- syncs snapshots with compatible peers;
- avoids rendering over files currently being edited.

---

## Editor temporary files

Earth ignores common editor-generated temporary files so they do not become shared files.

Ignored examples include:

```text
.test.txt.swp
.test.txt.swo
.test.txt.swn
test.txt~
test.txu~
test.txv~
4913
#file#
.#file
```

It also ignores common transient files such as:

```text
.DS_Store
Thumbs.db
desktop.ini
*.tmp
*.temp
*.part
*.crdownload
.git/
.hg/
.svn/
```

If an older daemon already synced these files, delete them once locally. After every device is running this version, the next scan prunes ignored paths from the manifest so they stop propagating.

---

## Editor-safe rendering

Earth avoids the Vim `E949: File changed while writing` race by making daemon writes more conservative.

Current behavior:

- local scan does not immediately render files back into the same folder;
- visible file writes are hash-guarded, so unchanged files are not rewritten;
- Vim/Emacs active editor markers defer visible renders;
- recently modified files are not imported until they have been quiet for about 1.2 seconds;
- incoming remote updates are merged, but final writes are deferred while an editor has the file open.

With Vim, the expected behavior is:

```bash
vim test.txt
# edit and save normally
```

The daemon should import the saved change after the file becomes stable, sync it to peers, and avoid rewriting `test.txt` while Vim's swap file exists.

---

## Test with isolated local homes

You can simulate two devices on one machine by using different `PROGRAM_HOME` values.

Terminal 1:

```bash
rm -rf /tmp/lsdev1 /tmp/lsdev2 /tmp/a /tmp/b
mkdir -p /tmp/a/example_dir
printf 'int main() {\n    return 0;\n}\n' > /tmp/a/example_dir/main.c
PROGRAM_HOME=/tmp/lsdev1 cargo run -- login alice --password 'test-password-123' --port 9001
PROGRAM_HOME=/tmp/lsdev1 cargo run -- init /tmp/a/example_dir
```

Terminal 2:

```bash
PROGRAM_HOME=/tmp/lsdev2 cargo run -- login alice --password 'test-password-123' --port 9002
PROGRAM_HOME=/tmp/lsdev2 cargo run -- list --discover
PROGRAM_HOME=/tmp/lsdev2 cargo run -- clone example_dir /tmp/b/example_dir --discover
```

Then edit both `main.c` files and allow the daemons to sync.

---

## VM testing

The repo includes a `vmtest/` folder with a Vagrant-based test scaffold.

```bash
cd vmtest
vagrant up
cd ..
./vmtest/run_vm_test.sh
```

This is intended to validate two-device behavior on separate virtual machines. Depending on your host, you may need VirtualBox, libvirt, or another Vagrant provider installed.

---

## Current limitations

Earth is still an MVP. Important limitations:

- The text merge layer is a simplified line-based CRDT-like merge, not full Automerge/Yjs yet.
- The sync protocol exchanges snapshots, not incremental operations.
- Authentication is still account-ID based; full signed device authentication is not implemented yet.
- Share contents are not end-to-end encrypted yet.
- Blob conflict handling is basic.
- Rename/delete conflict semantics are still early.
- There is no polished systemd installer yet.
- There is no `.deb` package yet.
- mDNS discovery may depend on LAN/firewall/router behavior.
- Large folders are inefficient because snapshot sync is not chunked/incremental yet.
- This has not been hardened against malicious peers.

Do not use this yet as the only copy of important data.

---

## Work in progress / roadmap

Planned next steps:

1. Replace line-based merge with a real text CRDT backend, such as Automerge or Yjs.
2. Add signed device identities and authenticated peer handshakes.
3. Add encrypted share keys and encrypted blob storage.
4. Replace snapshot sync with incremental CRDT ops and chunked blob transfer.
5. Add filesystem event watching with periodic scan as a fallback.
6. Add better conflict handling for rename/delete/binary edits.
7. Add a real `.earthignore` file per share.
8. Add systemd user service installation:

   ```bash
   earth service install
   earth service enable alice
   ```

9. Add `.deb` packaging for Ubuntu:

   ```bash
   sudo apt install ./earth_*.deb
   ```

10. Add a more complete VM/integration test suite.

---

## Development build

```bash
cargo build
cargo run -- --help
cargo run -- login alice --password 'test-password-123'
```

Release build:

```bash
cargo build --release
```

Install locally:

```bash
sudo install -m 755 target/release/earth /usr/local/bin/earth
```

---

## Safety note

Earth is experimental sync software. Keep backups. Test it with disposable folders first. The long-term goal is a local-first, peer-to-peer, CRDT-aware folder sharing tool, but the current implementation is still a prototype.
