#!/usr/bin/env bash
#
# Switch this user's Secret Service provider and autostart between Ubuntu's KeePassXC
# (/usr/bin/keepassxc) and this fork (/opt/keepassxc-fork/bin/keepassxc).
# Needs no sudo. Does not start or quit KeePassXC, and never reads secrets.
#
#   utils/fork-switch.sh to-fork <database.kdbx>...   back up, then point activation + autostart at the fork
#   utils/fork-switch.sh rollback                     put back the files saved by to-fork
#
# Install the package first:  sudo apt install ./build-deb/keepassxc-fork_*.deb

set -euo pipefail

FORK=/opt/keepassxc-fork/bin/keepassxc
SERVICE=$HOME/.local/share/dbus-1/services/org.freedesktop.secrets.service
AUTOSTART=$HOME/.config/autostart/org.keepassxc.KeePassXC.desktop
BACKUP=$HOME/.local/share/keepassxc-fork-backup
STAMP=$(date +%Y%m%d-%H%M%S)
# keepassxc-browser native messaging manifests; the running KeePassXC rewrites the proxy path in them
MANIFESTS=("$HOME"/.config/*/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json
           "$HOME"/.mozilla/native-messaging-hosts/org.keepassxc.keepassxc_browser.json)

if [[ ${1:-} == @(to-fork|rollback) ]] && pgrep -x keepassxc >/dev/null; then
    echo "KeePassXC is running (pid $(pgrep -x keepassxc | tr '\n' ' ')). Quit it first (tray icon -> Quit)." >&2
    exit 1
fi

case ${1:-} in
to-fork)
    shift
    (($#)) || { echo "Pass your database file(s), e.g. $0 to-fork ~/Passwords.kdbx" >&2; exit 1; }
    [[ -x $FORK ]] || { echo "$FORK not found. Install the .deb first." >&2; exit 1; }
    [[ -f $SERVICE ]] || { echo "$SERVICE not found, so nothing starts KeePassXC on demand." >&2; exit 1; }
    for db in "$@"; do [[ -f $db ]] || { echo "$db not found." >&2; exit 1; }; done
    [[ ! -e $BACKUP ]] || { echo "$BACKUP exists, so you already switched. Run rollback first." >&2; exit 1; }

    # fill the backup next to its place and move it there only once complete
    tmp=$(mktemp -d "$BACKUP.XXXXXX")
    mkdir "$tmp/manifests"
    cp -a "$SERVICE" "$tmp/"
    [[ -f $AUTOSTART ]] && cp -a "$AUTOSTART" "$tmp/"
    [[ -d $HOME/.config/keepassxc ]] && cp -a "$HOME/.config/keepassxc" "$tmp/config"
    [[ -d $HOME/.cache/keepassxc ]] && cp -a "$HOME/.cache/keepassxc" "$tmp/cache"
    i=0
    for db in "$@"; do i=$((i + 1)); cp -a "$db" "$tmp/db$i-$(basename "$db").$STAMP"; done
    for m in "${MANIFESTS[@]}"; do
        [[ -f $m ]] && mkdir -p "$tmp/manifests$(dirname "$m")" && cp -a "$m" "$tmp/manifests$m"
    done
    mv "$tmp" "$BACKUP"

    sed -i "s|^Exec=.*|Exec=$FORK|" "$SERVICE"
    [[ -f $AUTOSTART ]] && sed -i -e "s|^Exec=.*|Exec=$FORK|" -e "s|^TryExec=.*|TryExec=$FORK|" "$AUTOSTART"
    echo "Backup in $BACKUP. Activation and autostart now run $FORK."
    echo "Start it now with:  $FORK &"
    ;;
rollback)
    [[ -d $BACKUP ]] || { echo "No backup in $BACKUP, nothing to roll back." >&2; exit 1; }
    cp -a "$BACKUP/$(basename "$SERVICE")" "$SERVICE"
    [[ -f $BACKUP/$(basename "$AUTOSTART") ]] && cp -a "$BACKUP/$(basename "$AUTOSTART")" "$AUTOSTART"
    # keep the fork's settings next to the backup, then restore the 2.7.10 ones
    if [[ -d $BACKUP/config ]]; then
        [[ -d $HOME/.config/keepassxc ]] && mv "$HOME/.config/keepassxc" "$BACKUP/config.fork-$STAMP"
        cp -a "$BACKUP/config" "$HOME/.config/keepassxc"
    fi
    if [[ -d $BACKUP/cache ]]; then
        [[ -d $HOME/.cache/keepassxc ]] && mv "$HOME/.cache/keepassxc" "$BACKUP/cache.fork-$STAMP"
        cp -a "$BACKUP/cache" "$HOME/.cache/keepassxc"
    fi
    # 2.8 moved the cache file here; without it, a later 2.8 picks up the restored one again
    [[ -d $HOME/.local/state/keepassxc ]] && mv "$HOME/.local/state/keepassxc" "$BACKUP/state.fork-$STAMP"
    (cd "$BACKUP/manifests" && find . -type f -print0) | while IFS= read -r -d '' m; do
        cp -a "$BACKUP/manifests/$m" "/${m#./}"
    done
    mv "$BACKUP" "$BACKUP.rolled-back-$STAMP"
    echo "Restored. Activation and autostart run /usr/bin/keepassxc again. Database copies are in $BACKUP.rolled-back-$STAMP."
    echo "Start it now with:  /usr/bin/keepassxc &      Optional: sudo apt remove keepassxc-fork"
    ;;
*)
    sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
