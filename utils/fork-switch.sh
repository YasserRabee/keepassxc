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
    [[ ! -e $BACKUP ]] || { echo "$BACKUP exists, so you already switched. Run rollback first." >&2; exit 1; }

    mkdir -p "$BACKUP/manifests" && chmod 700 "$BACKUP"
    cp -a "$SERVICE" "$AUTOSTART" "$BACKUP/"
    cp -a "$HOME/.config/keepassxc" "$BACKUP/config"
    [[ -d $HOME/.cache/keepassxc ]] && cp -a "$HOME/.cache/keepassxc" "$BACKUP/cache"
    for db in "$@"; do cp -a "$db" "$BACKUP/$(basename "$db").$STAMP"; done
    for m in "${MANIFESTS[@]}"; do
        [[ -f $m ]] && mkdir -p "$BACKUP/manifests$(dirname "$m")" && cp -a "$m" "$BACKUP/manifests$m"
    done

    sed -i "s|^Exec=.*|Exec=$FORK|" "$SERVICE"
    sed -i -e "s|^Exec=.*|Exec=$FORK|" -e "s|^TryExec=.*|TryExec=$FORK|" "$AUTOSTART"
    echo "Backup in $BACKUP. Activation and autostart now run $FORK."
    echo "Start it now with:  $FORK &"
    ;;
rollback)
    [[ -d $BACKUP ]] || { echo "No backup in $BACKUP, nothing to roll back." >&2; exit 1; }
    cp -a "$BACKUP/$(basename "$SERVICE")" "$SERVICE"
    cp -a "$BACKUP/$(basename "$AUTOSTART")" "$AUTOSTART"
    # keep the fork's settings next to the backup, then restore the 2.7.10 ones
    mv "$HOME/.config/keepassxc" "$BACKUP/config.fork-$STAMP"
    cp -a "$BACKUP/config" "$HOME/.config/keepassxc"
    if [[ -d $BACKUP/cache ]]; then
        [[ -d $HOME/.cache/keepassxc ]] && mv "$HOME/.cache/keepassxc" "$BACKUP/cache.fork-$STAMP"
        cp -a "$BACKUP/cache" "$HOME/.cache/keepassxc"
    fi
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
