#!/usr/bin/env bash
#
# Live test of a keepassxc-fork .deb, fully inside a throwaway Ubuntu 26.04 container:
# installs the .deb with apt (checks its Depends), starts KeePassXC on a private D-Bus session
# and Xvfb display with a throwaway database, and counts Access Request prompts while
# glab-like clients run. Nothing touches the host's session bus, keyring or config.
#
# Usage: utils/fork-live-test/run.sh build-deb/keepassxc-fork_*.deb

set -euo pipefail
DEB=$(realpath "${1:?path to keepassxc-fork .deb}")
HERE=$(dirname "$(realpath "$0")")
IMAGE=keepassxc-fork-live:26.04

docker build -q -t "$IMAGE" - >/dev/null <<'DOCKERFILE'
FROM ubuntu:26.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        dbus xvfb xauth xdotool libsecret-tools python3-secretstorage procps
DOCKERFILE

# host cgroup namespace: processes get real cgroup paths, which decide what "Remember while" offers
docker run --rm --cgroupns=host -v "$DEB:/tmp/keepassxc-fork.deb:ro" -v "$HERE:/test:ro" "$IMAGE" bash -euo pipefail -c '
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /tmp/keepassxc-fork.deb >/tmp/apt.log 2>&1 || { tail -20 /tmp/apt.log; exit 1; }
echo "installed: $(dpkg-query -W keepassxc-fork)"
runuser -u ubuntu -- env LANG=C.UTF-8 dbus-run-session -- xvfb-run -a -s "-screen 0 1280x800x24" bash /test/inner.sh 2>&1 \
    | grep -v "^Enter password\|^Repeat password"'
