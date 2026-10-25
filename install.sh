#!/usr/bin/env bash
#
# install.sh — put the Sentinel agent on this server and let one phone in.
#
#   sudo bash install.sh --key <the key the app shows>
#
# Options:
#   --key <key>            the app's public key (as the app copies it: one base64
#                          word, or the plain "ssh-ed25519 AAAA… comment" line)
#   --user <name>          the account the phone logs in as (default: sentinel,
#                          created for it, with no password and no other use)
#   --allow-control        let the app start/stop/restart what the config lists
#                          under "control" (the default is read-only)
#   --read-only            take that away again
#   --detect               look for services, containers and hardware again,
#                          adding what is new (nothing is ever removed)
#   --check <what>         watch a website or port: a URL, host:port,
#                          minecraft:host:port or a2s:host:port (repeatable)
#   --remove-key <which>   revoke a phone: its SHA256:… fingerprint or comment
#   --uninstall            remove the agent, its rules, its keys and its account
#
# Re-running is safe: the agent and the sudo rules are replaced, the config is
# merged (never clobbered), and a key that is already there is not added twice.
# What every rule allows, and why, is in the README of
# https://github.com/K0tatkoo/sentinel-agent.

set -euo pipefail

AGENT_VERSION="@VERSION@"
AGENT_SHA256="@SHA256@"
AGENT_DST=/usr/local/bin/sentinel-agent
CONF=/etc/sentinel-agent.conf
SUDOERS=/etc/sudoers.d/sentinel-agent
DEDICATED_HOME=/var/lib/sentinel
MARKER=.sentinel-account          # in the home of an account this script created

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n  \033[31m✗\033[0m %s\n\n' "$*" >&2; exit 1; }

KEY=""; TARGET_USER="sentinel"; USER_GIVEN=0
CONTROL_FLAG=""; DETECT=0; CHECKS=(); REMOVE_KEY=""; UNINSTALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)           KEY="${2:-}"; shift 2 ;;
    --user)          TARGET_USER="${2:?--user needs a name}"; USER_GIVEN=1; shift 2 ;;
    --allow-control) CONTROL_FLAG="--allow-control"; shift ;;
    --read-only)     CONTROL_FLAG="--read-only"; shift ;;
    --detect)        DETECT=1; shift ;;
    --check)         CHECKS+=(--check "${2:?--check needs a target}"); shift 2 ;;
    --remove-key)    REMOVE_KEY="${2:?--remove-key needs a fingerprint or comment}"; shift 2 ;;
    --uninstall)     UNINSTALL=1; shift ;;
    -h|--help)       sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)               die "unknown option: $1 (see --help)" ;;
  esac
done

[[ $(id -u) -eq 0 ]] || die "run it as root: sudo bash $0 …"
[[ -f $0 ]] || die "save this script to a file and run that file (it carries the agent inside it)"
[[ ${BASH_VERSINFO[0]} -ge 4 ]] || die "bash 4 or newer is needed"
[[ $TARGET_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "not a usable account name: $TARGET_USER"

home_of() { getent passwd "$1" | cut -d: -f6; }
is_dedicated() {        # an account this script made for the phone and nothing else
  local h; h="$(home_of "$1")"
  [[ -n $h && -f $h/$MARKER ]]
}

# The authorized_keys lines that are ours: they force this agent.
OUR_LINE_RE='command="/usr/local/bin/sentinel-agent"'

remove_lines() {        # remove_lines <authorized_keys> <predicate-awk-var> — keeps everything else
  local ak=$1 pattern=$2
  [[ -f $ak ]] || return 0
  local tmp; tmp="$(mktemp)"
  local removed=0
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == *"$OUR_LINE_RE"* ]] && { [[ -z $pattern ]] || line_matches "$line" "$pattern"; }; then
      removed=$((removed + 1)); continue
    fi
    printf '%s\n' "$line" >> "$tmp"
  done < "$ak"
  cat "$tmp" > "$ak"; rm -f "$tmp"
  echo "$removed"
}

line_matches() {        # line_matches <authorized_keys line> <SHA256:fp | comment>
  local line=$1 want=$2 key comment fp
  key="$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) {print $i" "$(i+1); exit}}' <<<"$line")"
  comment="$(awk '{print $NF}' <<<"$line")"
  [[ $comment == "$want" ]] && return 0
  fp="$(ssh-keygen -lf - <<<"$key" 2>/dev/null | awk '{print $2}')"
  [[ -n $fp && $fp == "$want" ]]
}

key_files() {           # every authorized_keys an install of ours may have written to
  local u h
  for u in "$TARGET_USER" sentinel; do
    h="$(home_of "$u")" || continue
    [[ -n $h && -f $h/.ssh/authorized_keys ]] && echo "$h/.ssh/authorized_keys"
  done | sort -u
}

# --------------------------------------------------------------------------- #
if [[ -n $REMOVE_KEY ]]; then
  total=0
  while IFS= read -r ak; do
    n="$(remove_lines "$ak" "$REMOVE_KEY")"; total=$((total + n))
    [[ $n -gt 0 ]] && ok "removed $n key(s) from $ak"
  done < <(key_files)
  [[ $total -gt 0 ]] || die "no Sentinel key matches $REMOVE_KEY"
  ok "that phone can no longer connect"
  exit 0
fi

if [[ $UNINSTALL -eq 1 ]]; then
  while IFS= read -r ak; do
    n="$(remove_lines "$ak" "")"
    [[ $n -gt 0 ]] && ok "removed $n Sentinel key(s) from $ak"
  done < <(key_files)
  rm -f "$SUDOERS" && ok "removed $SUDOERS"
  rm -f "$AGENT_DST" && ok "removed $AGENT_DST"
  [[ -f $CONF ]] && rm -f "$CONF" && ok "removed $CONF"
  for u in "$TARGET_USER" sentinel; do
    if id "$u" >/dev/null 2>&1; then
      if is_dedicated "$u"; then
        userdel -r "$u" 2>/dev/null || userdel "$u"
        ok "removed the account $u"
      else
        h="$(home_of "$u")"; [[ -n $h ]] && rm -rf "$h/.cache/sentinel-agent"
      fi
    fi
  done
  ok "Sentinel is gone from this server"
  exit 0
fi

# --------------------------------------------------------------------------- #
say "Sentinel agent $AGENT_VERSION"
[[ -d /run/systemd/system ]] || die "this server does not run systemd, which Sentinel needs"
command -v python3 >/dev/null || die "python3 is needed (apt install python3 / dnf install python3)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "python3 3.8 or newer is needed"
command -v sudo >/dev/null && command -v visudo >/dev/null || die "sudo is needed (apt install sudo / dnf install sudo)"
grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers\.d' /etc/sudoers \
  || die "/etc/sudoers does not read /etc/sudoers.d, where Sentinel's rules go"
command -v ssh-keygen >/dev/null || die "ssh-keygen (OpenSSH) is needed"

# The agent travels inside this file, after the __AGENT__ line, and is checked
# before anything is put in place: a cut-off download must not half-install.
TMP_AGENT="$(mktemp)"; TMP_SUDO="$(mktemp)"
trap 'rm -f "$TMP_AGENT" "$TMP_SUDO"' EXIT
sed -n '/^__AGENT__$/,$p' "$0" | tail -n +2 | base64 -d > "$TMP_AGENT" 2>/dev/null \
  || die "this installer is damaged (the agent inside it does not decode) — download it again"
got="$(sha256sum "$TMP_AGENT" | awk '{print $1}')"
[[ $got == "$AGENT_SHA256" ]] || die "this installer is damaged (checksum mismatch) — download it again"
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$TMP_AGENT" || die "the agent does not parse"
install -o root -g root -m 0755 "$TMP_AGENT" "$AGENT_DST"
ok "agent installed at $AGENT_DST"

# --------------------------------------------------------------------------- #
# The account. A dedicated one holds the phone's key and nothing else: it gets a
# real shell (sshd runs the forced command through it), the password field "*"
# (no password works, but the account is not "locked" — sshd refuses locked
# accounts when PAM is off), and a root-owned ~/.ssh so it cannot rewrite its
# own restrictions.
if ! id "$TARGET_USER" >/dev/null 2>&1; then
  [[ $USER_GIVEN -eq 0 ]] || die "no such account: $TARGET_USER"
  useradd --system --create-home --home-dir "$DEDICATED_HOME" --shell /bin/sh \
          --comment "Sentinel agent" "$TARGET_USER"
  usermod -p '*' "$TARGET_USER"
  touch "$DEDICATED_HOME/$MARKER"; chown root:root "$DEDICATED_HOME/$MARKER"
  ok "created the account $TARGET_USER (no password, used only by the agent)"
fi
HOME_DIR="$(home_of "$TARGET_USER")"
[[ -n $HOME_DIR && -d $HOME_DIR ]] || die "the account $TARGET_USER has no home directory"
DEDICATED=0; is_dedicated "$TARGET_USER" && DEDICATED=1

# --------------------------------------------------------------------------- #
fresh=1; [[ -f $CONF ]] && fresh=0
[[ $fresh -eq 1 ]] && say "looking at what this server runs…"
args=(--write-config --conf "$CONF")
[[ $DETECT -eq 1 ]] && args+=(--detect)
[[ -n $CONTROL_FLAG ]] && args+=("$CONTROL_FLAG")
args+=("${CHECKS[@]}")
SUMMARY="$("$AGENT_DST" "${args[@]}")" || die "could not write $CONF"
python3 - "$SUMMARY" <<'PY'
import json, sys
s = json.loads(sys.argv[1])
def show(title, items):
    print(f"  ✓ {title}: " + (", ".join(items) if items else "none"))
show("watching services", [u[:-8] if u.endswith(".service") else u for u in s["units"]])
show("watching containers", s["containers"])
hw = s["hardware"]
found = [n for n, on in (("sensors", hw.get("sensors")), ("BMC", hw.get("ipmi")), ("GPU", hw.get("gpu"))) if on]
if hw.get("smart"):
    found.append(f"SMART on {len(hw['smart'])} drive(s)")
show("hardware", found)
print(f"  ✓ checks: {s['checks']}")
for n in s.get("notes", []):
    print(f"  ! {n}")
print("  ✓ control: " + ("allowed for what the config lists under \"control\"" if s["allow_control"] else "off (read-only)"))
PY

# --------------------------------------------------------------------------- #
# The sudo rules come from the agent itself, from the very argv it runs, and are
# validated before they go anywhere: a bad drop-in can break sudo for everyone.
"$AGENT_DST" --sudoers --user "$TARGET_USER" --conf "$CONF" > "$TMP_SUDO"
if ! visudo -cqf "$TMP_SUDO" >/dev/null 2>&1; then
  # An older sudo without per-command log settings: the same rules, logged.
  "$AGENT_DST" --sudoers --user "$TARGET_USER" --conf "$CONF" --no-quiet > "$TMP_SUDO"
  visudo -cqf "$TMP_SUDO" >/dev/null 2>&1 || { visudo -cf "$TMP_SUDO" || true; die "the generated sudo rules did not validate — nothing was changed"; }
fi
install -o root -g root -m 0440 "$TMP_SUDO" "$SUDOERS"
ok "sudo rules written to $SUDOERS ($(grep -c '' "$SUDOERS") lines, every one an exact command)"

# --------------------------------------------------------------------------- #
if [[ -n $KEY ]]; then
  case "$KEY" in
    ssh-*|ecdsa-*|sk-*) LINE_KEY="$KEY" ;;
    *) LINE_KEY="$(printf '%s' "$KEY" | base64 -d 2>/dev/null)" || die "--key is neither a public key nor base64 of one" ;;
  esac
  LINE_KEY="$(printf '%s' "$LINE_KEY" | tr -d '\r\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  read -r KTYPE KBODY KCOMMENT <<<"$LINE_KEY"
  [[ $KTYPE =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$ ]] \
    || die "that is not an OpenSSH public key (it should start with ssh-ed25519)"
  [[ $KBODY =~ ^[A-Za-z0-9+/=]{40,}$ ]] || die "the key's body is not base64"
  ssh-keygen -lf - <<<"$KTYPE $KBODY" >/dev/null 2>&1 || die "ssh-keygen does not accept that key"
  KCOMMENT="${KCOMMENT:-sentinel}"; KCOMMENT="${KCOMMENT//[^A-Za-z0-9@._-]/}"

  SSH_DIR="$HOME_DIR/.ssh"; AK="$SSH_DIR/authorized_keys"
  if [[ $DEDICATED -eq 1 ]]; then
    install -d -o root -g root -m 0755 "$SSH_DIR"
    touch "$AK"; chown root:root "$AK"; chmod 0644 "$AK"
  else
    install -d -o "$TARGET_USER" -g "$(id -gn "$TARGET_USER")" -m 0700 "$SSH_DIR"
    touch "$AK"; chown "$TARGET_USER:$(id -gn "$TARGET_USER")" "$AK"; chmod 0600 "$AK"
  fi
  if grep -qF "$KBODY" "$AK"; then
    grep -vF "$KBODY" "$AK" > "$AK.new" || true
    cat "$AK.new" > "$AK"; rm -f "$AK.new"
    say "that key was already there — its line is replaced"
  fi
  # restrict = no forwarding of any kind, no pty; command= = nothing but the agent.
  echo "restrict,command=\"$AGENT_DST\" $KTYPE $KBODY $KCOMMENT" >> "$AK"
  ok "the phone's key is authorised for $TARGET_USER (it can run the agent and nothing else)"
else
  say "no --key given: run this again with the key the app shows to let a phone in"
fi

# --------------------------------------------------------------------------- #
# Will sshd actually let this account in?
if command -v sshd >/dev/null && SSHD="$(sshd -T 2>/dev/null)"; then
  allow_users="$(awk '$1=="allowusers"{$1=""; print}' <<<"$SSHD")"
  allow_groups="$(awk '$1=="allowgroups"{$1=""; print}' <<<"$SSHD")"
  if [[ -n $allow_users && " $allow_users " != *" $TARGET_USER "* ]]; then
    warn "sshd only lets in AllowUsers ($allow_users): add $TARGET_USER there and reload sshd"
  fi
  if [[ -n $allow_groups ]]; then
    in_group=0
    for g in $(id -Gn "$TARGET_USER"); do [[ " $allow_groups " == *" $g "* ]] && in_group=1; done
    [[ $in_group -eq 1 ]] || warn "sshd only lets in AllowGroups ($allow_groups): add $TARGET_USER to one of them"
  fi
  if awk '$1=="pubkeyauthentication" && $2=="no"' <<<"$SSHD" | grep -q .; then
    warn "sshd has PubkeyAuthentication off: the phone's key cannot work until it is on"
  fi
fi

# --------------------------------------------------------------------------- #
# Prove it the way the phone will run it: as the account, through the agent.
PING="$(sudo -H -u "$TARGET_USER" env SSH_ORIGINAL_COMMAND=ping "$AGENT_DST" 2>/dev/null || true)"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d.get("ok")' "$PING" 2>/dev/null \
  && ok "the agent answers as $TARGET_USER" || warn "the agent did not answer cleanly as $TARGET_USER: $PING"
SNAP="$(sudo -H -u "$TARGET_USER" env SSH_ORIGINAL_COMMAND=snapshot "$AGENT_DST" 2>/dev/null || true)"
python3 - "$SNAP" <<'PY' || true
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print("  ! the first snapshot did not come back as JSON"); sys.exit(0)
problems = []
if (d.get("docker") or {}).get("error"):
    problems.append("containers: " + d["docker"]["error"])
for name, err in ((d.get("hardware") or {}).get("sources") or {}).items():
    if err:
        problems.append(f"{name}: {err}")
for p in problems:
    print("  ! " + p)
if not problems:
    print("  \033[32m✓\033[0m the first snapshot came back clean")
PY

echo
ok "done. The server's identity, to compare with what the app shows:"
for f in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub; do
  [[ -f $f ]] && ssh-keygen -lf "$f" | awk '{print "      " $2 "  (" $NF ")"}'
done
echo
exit 0
__AGENT__
