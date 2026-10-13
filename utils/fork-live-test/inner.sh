#!/bin/bash
# Runs inside the container started by run.sh, under its own D-Bus session and Xvfb display,
# with a throwaway .kdbx and config. Access Request dialogs are counted and answered by xdotool.
set -uo pipefail
W=/tmp/live; mkdir -p "$W/home" "$W/run"; chmod 700 "$W/run"
export HOME=$W/home XDG_RUNTIME_DIR=$W/run
BIN=/opt/keepassxc-fork/bin
mkdir -p "$W/bin"; cp /usr/bin/secret-tool "$W/bin/secret-tool-copy"; export PATH=$W/bin:$PATH  # "another program"

printf 'pw\npw\n' | $BIN/keepassxc-cli import -q -p /test/db.xml "$W/db.kdbx" || exit 1
cat > "$W/keepassxc.ini" <<INI
[General]
UpdateCheckMessageShown=true
[FdoSecrets]
Enabled=true
ConfirmAccessItem=true
ConfirmDeleteItem=false
ShowNotification=false
INI
printf '[Security]\nQuickUnlock=false\n' > "$W/local.ini"

echo pw | $BIN/keepassxc --config "$W/keepassxc.ini" --localconfig "$W/local.ini" --pw-stdin "$W/db.kdbx" >"$W/kpxc.log" 2>&1 &
for _ in $(seq 150); do
    dbus-send --session --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.GetNameOwner \
        string:org.freedesktop.secrets >/dev/null 2>&1 && break
    sleep 0.2
done
echo "secret service owner pid: $(dbus-send --session --print-reply --dest=org.freedesktop.DBus / \
    org.freedesktop.DBus.GetConnectionUnixProcessID string:org.freedesktop.secrets | awk '/uint32/{print $2}')" \
    "(keepassxc pid $(pgrep -f "$BIN/keepassxc --config"))"

# the service is on the bus before the database has finished unlocking
for _ in $(seq 150); do
    dbus-send --session --print-reply --dest=org.freedesktop.secrets /org/freedesktop/secrets/aliases/default \
        org.freedesktop.DBus.Properties.Get string:org.freedesktop.Secret.Collection string:Locked 2>/dev/null \
        | grep -q 'boolean false' && break
    sleep 0.2
done
echo "default collection unlocked: $(dbus-send --session --print-reply --dest=org.freedesktop.secrets \
    /org/freedesktop/secrets/aliases/default org.freedesktop.DBus.Properties.Get \
    string:org.freedesktop.Secret.Collection string:Locked | grep -q 'boolean false' && echo yes || echo NO)"

# --- dialog answering: counts every Access Request window and answers per $W/action
: >"$W/prompts"
answer() { echo "$1" >"$W/action"; }
(
    while :; do
        for wid in $(xdotool search --onlyvisible --name 'Access Request' 2>/dev/null); do
            act=$(cat "$W/action")
            echo "$act" >>"$W/prompts"
            sleep 0.3
            xdotool windowfocus --sync "$wid" 2>/dev/null
            case $act in
                allow) xdotool key Return ;;                  # Allow Selected, Remember is ticked by default
                allowall) xdotool key alt+f ;;                # Allow All & Future
                allow-up) xdotool key --delay 150 alt+w Down Return ;;  # Allow Selected, remembered for the grandparent
                deny) # Deny All & Future has no shortcut: click it, 26px above the bottom edge
                    eval "$(xdotool getwindowgeometry --shell "$wid")"
                    xdotool mousemove --window "$wid" 471 $((HEIGHT - 26)) click 1 ;;
            esac
            while xdotool search --onlyvisible --name 'Access Request' 2>/dev/null | grep -qx "$wid"; do sleep 0.1; done
        done
        sleep 0.1
    done
) &
trap 'kill $!' EXIT

PASS=0 FAIL=0
run_case() { # name expected_prompts action script
    local name=$1 want=$2 before after
    answer "$3"
    before=$(wc -l <"$W/prompts")
    echo "== $name"
    timeout 60 bash -c "$4" 2>&1
    sleep 0.5
    after=$(wc -l <"$W/prompts")
    if (( after - before == want )); then echo "   prompts: $((after - before)) (expected $want) PASS"; ((PASS++));
    else echo "   prompts: $((after - before)) (expected $want) FAIL"; ((FAIL++)); fi
}
look='secret-tool lookup service glab >/dev/null && echo "  secret-tool: got secret" || echo "  secret-tool: NO SECRET"'
copy='secret-tool-copy lookup service glab >/dev/null && echo "  secret-tool-copy: got secret" || echo "  secret-tool-copy: NO SECRET"'
py='python3 -I /test/gokeyring_like.py'

# The trailing ':' stops bash from exec-ing the last command in place of itself.
run_case "1. one script, 3 runs of the same program -> one prompt" 1 allow "$look; $look; $look; :"
run_case "1b. go-keyring style: one process, 3 connections -> one prompt" 1 allow "$py lookups 3; :"
# bash runs these directly, so their parent is the script itself
forms='x=$(secret-tool lookup service glab) && echo "  \$(secret-tool): got secret" || echo "  \$(secret-tool): NO SECRET"
secret-tool lookup service glab | grep -q . && echo "  secret-tool | grep: got secret" || echo "  secret-tool | grep: NO SECRET"
( cd /tmp; secret-tool lookup service glab ) >/dev/null && echo "  ( cd; secret-tool ): got secret" || echo "  ( cd; secret-tool ): NO SECRET"'
run_case "1c. \$(cmd), pipelines and ( cd x; cmd ) in the script are covered" 1 allow "$look; $forms; :"
run_case "1d. started by another program under the script (like an npm install script) asks again" 2 allow "$look; sh -c '$look'; :"
run_case "2. another program under the same parent still prompts" 2 allow "$look; $look; $copy; $copy; :"
run_case "3a. script run #1" 1 allow "$look; $look; :"
run_case "3b. script run #2 (new parent; run #1 has exited) prompts again" 1 allow "$look; $look; :"
run_case "4. Deny All & Future is inherited" 1 deny "$look; $look; $look; :"
run_case "5. glab probe item: Allow All & Future covers the next run's new probe" 1 allowall "$py probe; $py probe; $py probe; :"
run_case "6. Allow Selected (one entry) does not cover the next run's new probe item" 2 allow "$py probe; $py probe; :"
# A long-running process that starts a new shell for every command, like a coding agent.
# "Remember while this runs" = that process: later commands are not asked, other ways are.
cmd="bash -c '$look; :'"
run_case "7. session process chosen once: its later commands (new shell each) are not asked" 1 allow-up \
    "$cmd; $cmd; $cmd; :"
run_case "8. but glab started another way under it is: by another program (like an MCP server), or deeper" 3 allow-up \
    "$cmd; $py spawn; bash -c '$py spawn; :'; :"

echo
echo "RESULT: $PASS passed, $FAIL failed"
((FAIL == 0))
