#!/usr/bin/env bash
#
# Build this fork from git HEAD as a .deb that installs to /opt/keepassxc-fork,
# inside an Ubuntu 26.04 Docker container, so no build dependencies land on the host.
#
# Usage: utils/build-fork-deb.sh [output-dir]      (default: <repo>/build-deb)
#   RUN_TESTS=0  skip the test suite
#
# The package only adds /opt/keepassxc-fork and the polkit policy for Quick Unlock,
# so it can be installed next to Ubuntu's keepassxc / keepassxc-full.

set -euo pipefail

REPO=$(git rev-parse --show-toplevel)
OUT=$(realpath -m "${1:-$REPO/build-deb}")
cd "$REPO"
RUN_TESTS=${RUN_TESTS:-1}
IMAGE=keepassxc-fork-build:26.04
PREFIX=/opt/keepassxc-fork

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "WARNING: uncommitted changes are NOT part of the build (it uses git HEAD)" >&2
fi

# 2.8.0-beta1 + 3 commits -> KeePassXC version 2.8.0-beta1-3-gabc1234, deb version 2.8.0~beta1+fork3.gabc1234
TAG=$(git describe --tags --abbrev=0 --match '[0-9]*')
COMMITS=$(git rev-list --count "$TAG..HEAD")
SHA=$(git rev-parse --short=7 HEAD)
VERSION="$TAG-$COMMITS-g$SHA"
DEB_VERSION="${TAG/-/\~}+fork$COMMITS.g$SHA"
MAINTAINER="$(git config user.name) <$(git config user.email)>"

docker build -t "$IMAGE" - <<'EOF'
FROM ubuntu:26.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config dpkg-dev file \
        qt6-base-dev qt6-svg-dev qt6-tools-dev qt6-tools-dev-tools qt6-l10n-tools \
        qt6-qpa-plugins qt6-svg-plugins \
        libbotan-3-dev zlib1g-dev libminizip-dev libpcsclite-dev libusb-1.0-0-dev libkeyutils-dev \
        libzxcvbn-dev libqrencode-dev libreadline-dev libxkbcommon-dev libx11-dev libxi-dev libxtst-dev \
        asciidoctor dbus xvfb xauth xclip locales \
    && rm -rf /var/lib/apt/lists/* && locale-gen en_US.UTF-8
EOF

mkdir -p "$OUT"
git archive --format=tar HEAD | docker run --rm -i \
    -v "$OUT:/out" \
    -e VERSION="$VERSION" -e SHA="$SHA" -e DEB_VERSION="$DEB_VERSION" -e MAINTAINER="$MAINTAINER" \
    -e PREFIX="$PREFIX" -e RUN_TESTS="$RUN_TESTS" -e HOST_IDS="$(id -u):$(id -g)" \
    "$IMAGE" bash -euo pipefail -c '
mkdir /src && tar -x -C /src

# Features as in Ubuntu keepassxc-full. KeeShare, YubiKey and auto-type are always built in 2.8.
cmake -S /src -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DGIT_HEAD_OVERRIDE="$SHA" -DOVERRIDE_VERSION="$VERSION" \
    -DKPXC_FEATURE_BROWSER=ON -DKPXC_FEATURE_SSHAGENT=ON -DKPXC_FEATURE_FDOSECRETS=ON \
    -DKPXC_FEATURE_NETWORK=ON -DKPXC_FEATURE_UPDATES=OFF -DKPXC_FEATURE_DOCS=ON \
    -DWITH_TESTS=ON -DWITH_GUI_TESTS=ON
cmake --build /build

if [[ $RUN_TESTS == 1 ]]; then
    # as a normal user (root can read write-only files), with a UTF-8 locale, on a private
    # session bus and X server; GUI tests one at a time as they fight over the window focus
    chown -R ubuntu: /build /src
    runuser -u ubuntu -- env LANG=C.UTF-8 HOME=/tmp dbus-run-session -- xvfb-run -a bash -euo pipefail -c "
        cd /build
        ctest --output-on-failure -j$(nproc) -E ^testgui
        ctest --output-on-failure -R ^testgui" 2>&1 | tee /out/ctest.log
fi

DESTDIR=/pkg cmake --install /build --strip
mkdir -p /pkg/usr/share/polkit-1/actions /pkg/DEBIAN
mv /pkg$PREFIX/share/polkit-1/actions/*.policy /pkg/usr/share/polkit-1/actions/
rmdir -p --ignore-fail-on-non-empty /pkg$PREFIX/share/polkit-1/actions

# shared library Depends, so apt pulls the Qt 6 runtime; plugins are not linked, so list them by hand
mkdir -p /tmp/shlibs/debian && touch /tmp/shlibs/debian/control
ELF=$(find /pkg$PREFIX -type f -print0 | xargs -0 file | grep ": *ELF" | cut -d: -f1)
DEPENDS=$(cd /tmp/shlibs && dpkg-shlibdeps -O $ELF | sed -n "s/^shlibs:Depends=//p")
cat > /pkg/DEBIAN/control <<CONTROL
Package: keepassxc-fork
Version: $DEB_VERSION
Architecture: $(dpkg --print-architecture)
Maintainer: $MAINTAINER
Section: utils
Priority: optional
Installed-Size: $(du -sk /pkg --exclude=DEBIAN | cut -f1)
Depends: $DEPENDS, qt6-qpa-plugins, qt6-wayland, qt6-svg-plugins
Description: KeePassXC $VERSION (fork) in $PREFIX
 Secret Service "Remember" decisions also cover later runs of the same
 program started by the same parent process. Installs next to Ubuntu keepassxc.
CONTROL
DEB=/out/keepassxc-fork_${DEB_VERSION}_$(dpkg --print-architecture).deb
dpkg-deb --build --root-owner-group /pkg "$DEB"
chown "$HOST_IDS" /out "$DEB" /out/ctest.log 2>/dev/null || true
echo "Built $DEB"
'
