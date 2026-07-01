#!/usr/bin/env bash
set -euo pipefail

# Run from repo root after `vagrant up`.
# This checks that login starts account-specific daemons by default and that device 2 can discover/list/clone from device 1.

PASS='test-password-123'

vagrant ssh node1 -c "set -e; cd /vagrant; cargo build; rm -rf /tmp/lsdev1 /tmp/a; mkdir -p /tmp/a/example_dir; printf 'int main() {\\n    return 0;\\n}\\n' > /tmp/a/example_dir/main.c; PROGRAM_HOME=/tmp/lsdev1 ./target/debug/earth login alice --password '$PASS' --port 9001 --no-discover; PROGRAM_HOME=/tmp/lsdev1 ./target/debug/earth init /tmp/a/example_dir; PROGRAM_HOME=/tmp/lsdev1 ./target/debug/earth status --account alice"

vagrant ssh node2 -c "set -e; cd /vagrant; cargo build; rm -rf /tmp/lsdev2 /tmp/b; PROGRAM_HOME=/tmp/lsdev2 ./target/debug/earth login alice --password '$PASS' --port 9002 --discover-timeout 10; PROGRAM_HOME=/tmp/lsdev2 ./target/debug/earth list --discover; PROGRAM_HOME=/tmp/lsdev2 ./target/debug/earth clone example_dir /tmp/b/example_dir --discover; test -f /tmp/b/example_dir/main.c; grep -q 'return 0' /tmp/b/example_dir/main.c; PROGRAM_HOME=/tmp/lsdev2 ./target/debug/earth status --account alice"

vagrant ssh node1 -c "PROGRAM_HOME=/tmp/lsdev1 /vagrant/target/debug/earth stop --all || true"
vagrant ssh node2 -c "PROGRAM_HOME=/tmp/lsdev2 /vagrant/target/debug/earth stop --all || true"

echo 'VM test completed.'
