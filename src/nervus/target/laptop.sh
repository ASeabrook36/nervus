nervus_laptop() {
umask 022
# printf, never echo: the echo of dash, and of a Mac's sh, turns the \n of a printed command into a line break.
line() { printf '%s\n' "$*"; }
fail() { printf 'nervus: %s\n' "$*" >&2; exit 1; }
say() { printf 'nervus: %s\n' "$*"; }
nl='
'
tmp=
trap 'rm -f "$tmp"' EXIT

[ "$(id -u)" != 0 ] || fail "run this as yourself, not as root: it sets up your own account, where your client runs. Nothing here was changed."
case $(uname -s) in
  Darwin) os=mac ;;
  Linux) os=linux ;;
  *) fail "this computer is neither a Mac nor Linux. On Windows, run the PowerShell line from nervus's Clients page. Nothing here was changed." ;;
esac
command -v curl >/dev/null 2>&1 || fail "curl is not installed. Nothing here was changed."
dir=${XDG_CONFIG_HOME:-$HOME/.config}/nervus
# The helper's path goes into each client's settings as part of a command line.
case $dir in
  *[!A-Za-z0-9._/-]*) fail "the folder nervus's files go in, $dir, has a character a client's command line would split: set XDG_CONFIG_HOME to a folder whose path has only letters, digits, ., _, - and /. Nothing here was changed." ;;
esac
# The clients' own settings folders go into the printed commands, in single quotes.
claude_config=${CLAUDE_CONFIG_DIR:-$HOME/.claude}
codex_home=${CODEX_HOME:-$HOME/.codex}
case $claude_config$codex_home in
  *"'"*) fail "CLAUDE_CONFIG_DIR or CODEX_HOME holds a quote, which the commands this prints cannot carry. Nothing here was changed." ;;
esac
item=nervus-$name
# Absolute, so a folder earlier on PATH cannot stand in for it; another only for nervus's own tests, as
# tools/nervus-headers allows.
security=${NERVUS_SECURITY_BIN:-/usr/bin/security}
if [ "$os" = mac ]; then
  if "$security" find-generic-password -a nervus -s "$item" >/dev/null 2>&1; then
    fail "your keychain already holds an item $item, from a token of the same id before. Remove it first, in Keychain Access or with: security delete-generic-password -a nervus -s $item, then run this line again; it works for 15 minutes from when it was made. Nothing here was changed."
  fi
  # A locked keychain, as over SSH, would take the token and keep nothing: found first, while the code still works.
  keychain=$("$security" default-keychain 2>/dev/null | sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//')
  [ -n "$keychain" ] && "$security" show-keychain-info "$keychain" >/dev/null 2>&1 \
    || fail "your login keychain is locked, or there is none, so the token could not be kept in it: run this line in a terminal on the Mac itself, logged in, while it works for 15 minutes from when it was made. Nothing here was changed."
fi

# 1. Is this line's code still good? One run again, or too late, stops here, before anything changes.
first=$(curl -sSk --pinnedpubkey "$pin" -o /dev/null -w '%{http_code}' "$url") \
  || fail "could not reach nervus at $origin. Nothing here was changed."
[ "$first" = 200 ] || fail "this line's code is used or expired (nervus answered $first): on nervus's Clients page, give the token a new line, or issue another. Nothing here was changed."

# 2. nervus's root, carried above, checked before it is saved: nervus must answer at $host as the root vouches,
#    since that is how each client will check it.
tmp=$(mktemp) || fail "cannot make a temporary file. Nothing here was changed."
printf '%s\n' "$root_pem" > "$tmp" || fail "cannot write a temporary file. Nothing here was changed."
if ! err=$(curl -sS -o /dev/null --max-time 10 --cacert "$tmp" "$origin/" 2>&1); then
  err=${err%%"$nl"*}
  fail "nervus does not check out against its own root as $host (${err#curl: }): is $host one of the names its certificate is for? Nothing here was changed."
fi
mkdir -p "$dir" || fail "cannot make $dir. Nothing here was changed."
# Yours alone: another account that could write in it could take the token, swap the helper, which runs as you,
# or add a root your clients would then trust.
for d in "$dir" "${dir%/*}"; do
  { [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ]; } \
    || fail "$d is not a folder of yours (a link, or another account's), so nothing of nervus's is kept in it. Nothing else was changed."
  [ -z "$(find "$d" -maxdepth 0 \( -perm -020 -o -perm -002 \) -print 2>/dev/null)" ] \
    || fail "another account can write in $d, so nothing of nervus's is kept in it: chmod go-w '$d', then run this line again. Nothing else was changed."
done
rootfile=$dir/root-$safe.pem
if [ -f "$rootfile" ] && cmp -s "$tmp" "$rootfile"; then
  say "nervus's root for $host is saved already, at $rootfile"
else
  was=
  [ -f "$rootfile" ] && was=" in place of the one saved there before, another nervus's at that name"
  { cp "$tmp" "$rootfile.new" && chmod 0644 "$rootfile.new" && mv -f "$rootfile.new" "$rootfile"; } \
    || fail "cannot write $rootfile"
  say "saved nervus's root at $rootfile$was"
fi
# Every nervus root saved here, in the one file each client is told, made again each time: certificates alone get in.
bundle=$dir/roots.pem
: > "$bundle.new" || fail "cannot write $bundle"
for f in "$dir"/root-*.pem; do
  awk '/-----BEGIN CERTIFICATE-----/ { on = 1 } on { print } /-----END CERTIFICATE-----/ { on = 0 }' "$f" >> "$bundle.new"
done
{ chmod 0644 "$bundle.new" && mv -f "$bundle.new" "$bundle"; } || fail "cannot write $bundle"
say "$bundle holds every nervus root saved here: $(grep -c 'BEGIN CERTIFICATE' "$bundle")"

# 3. The helper, which gives a client the token's header when it connects.
cat > "$dir/nervus-headers.new" <<'NERVUS_HELPER' || fail "cannot write $dir/nervus-headers"
@@HELPER@@NERVUS_HELPER
{ chmod 0755 "$dir/nervus-headers.new" && mv -f "$dir/nervus-headers.new" "$dir/nervus-headers"; } \
  || fail "cannot write $dir/nervus-headers"
helper="$dir/nervus-headers $name"
say "put the helper at $dir/nervus-headers"

# 4. The token: handed over once, for this line's code, and kept, never shown. It is in no command's arguments:
#    the shell holds it, and the keychain is given it on its standard input.
got=$(curl -sSk --pinnedpubkey "$pin" -X POST -w '\n%{http_code}' "$url") \
  || fail "could not reach nervus to fetch the token. nervus's root and the helper are saved; run this line again while it works, or make a new one on nervus's Clients page."
status=${got##*"$nl"}
value=${got%"$nl"*}
value=${value%"$nl"}  # nervus ends what it says with a line break
if [ "$status" != 200 ]; then
  value=${value#nervus: }
  fail "nervus did not hand over the token: $value"
fi
case $value in *[!A-Za-z0-9_-]*|'') fail "what nervus sent is not a token. nervus's root and the helper are saved; the token is not." ;; esac
[ ${#value} -ge 32 ] || fail "what nervus sent is not a token. nervus's root and the helper are saved; the token is not."
lost="nervus handed the token over, and it could not be kept here, so it is lost: revoke $token on nervus's Clients page and issue another"
if [ "$os" = mac ]; then
  # -T "": no application may read it without asking, so macOS asks before every read.
  printf 'add-generic-password -a nervus -s "%s" -l "%s" -T "" -w "%s"\n' "$item" "nervus token $token at $host" "$value" \
    | "$security" -i >/dev/null 2>&1
  value=
  "$security" find-generic-password -a nervus -s "$item" >/dev/null 2>&1 || fail "$lost"
  where="your login keychain, as the item $item, which asks you before each read"
else
  { (umask 077 && printf '%s\n' "$value" > "$dir/token-$name.new") && chmod 0600 "$dir/token-$name.new" \
    && mv -f "$dir/token-$name.new" "$dir/token-$name"; } || { value=; rm -f "$dir/token-$name.new"; fail "$lost"; }
  value=
  where="$dir/token-$name, which only you can read"
fi
say "kept the token $token in $where"

# 5. What the client needs, printed, never run: each change to this computer is one you make (question 6).
line
case $client in
  claude-code)
    config=$claude_config
    settings=$config/settings.json
    line "To use nervus from Claude Code, run these, then start a new session:"
    line
    line "  claude mcp add-json --scope user nervus '{\"type\":\"http\",\"url\":\"$mcp\",\"headersHelper\":\"$helper\"}'"
    # Its trust in nervus's root: one file, which ~/.claude/settings.json names, and which wins over the environment.
    named=
    [ -f "$settings" ] && named=$(sed -n 's/.*"NODE_EXTRA_CA_CERTS"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$settings" | head -n 1)
    if [ "$named" = "$bundle" ]; then
      :
    elif [ -n "$named" ]; then
      line
      line "  Claude Code's settings ($settings) name $named as the file of roots it trusts, and it reads that"
      line "  one alone. To reach nervus, name $bundle there instead, or, if that file holds a root you need"
      line "  besides nervus's (a company's, say), add nervus's to it: cat '$bundle' >> '$named'"
    elif [ "$os" = mac ]; then
      # macOS's own JavaScript, which every Mac has: plutil reads a file of just {} as an older kind of list,
      # and cannot write it back.
      # Through a link to the file it names, and that file's mode kept, as a dotfiles folder has it.
      jxa='ObjC.import("Foundation"); function run(a) { var p = $(a[0]).stringByResolvingSymlinksInPath.js, fm = $.NSFileManager.defaultManager; var was = fm.attributesOfItemAtPathError(p, null); var t = $.NSString.stringWithContentsOfFileEncodingError(p, 4, null); var s = t.isNil() ? {} : JSON.parse(t.js); s.env = s.env || {}; s.env.NODE_EXTRA_CA_CERTS = a[1]; if (!$(JSON.stringify(s, null, 2) + "\n").writeToFileAtomicallyEncodingError(p, true, 4, null)) throw new Error("cannot write " + p); if (!was.isNil()) fm.setAttributesOfItemAtPathError($({NSFilePosixPermissions: was.objectForKey("NSFilePosixPermissions")}), p, null); }'
      line "  mkdir -p '$config' && osascript -l JavaScript -e '$jxa' '$settings' '$bundle'"
    elif command -v python3 >/dev/null 2>&1; then
      [ -f "$settings" ] || line "  mkdir -p '$config' && echo '{}' > '$settings'"
      line "  python3 -c 'import json, sys; p = sys.argv[1]; s = json.load(open(p)); s.setdefault(\"env\", {})[\"NODE_EXTRA_CA_CERTS\"] = sys.argv[2]; json.dump(s, open(p, \"w\"), indent=2)' '$settings' '$bundle'"
    else
      line "  and in $settings, under \"env\", set \"NODE_EXTRA_CA_CERTS\": \"$bundle\""
    fi
    line
    line "If Claude Code has a server named nervus already, run claude mcp remove --scope user nervus first."
    if [ "$os" = mac ]; then
      line "When it connects, macOS asks whether security may use $item: Allow, never Always Allow."
    fi
    ;;
  codex)
    home=$codex_home
    line "To use nervus from Codex, run these, then start a new session:"
    line
    # codex mcp add has no flag for the helper, and puts its table among the others, so the server is added whole.
    # A server named nervus already, in any of the forms TOML allows, would make the file one Codex refuses.
    if grep -Eq '^[[:space:]]*(\[mcp_servers\.("nervus"|nervus)\]|mcp_servers\.("nervus"|nervus)[[:space:].=]|nervus[[:space:]]*=)' "$home/config.toml" 2>/dev/null; then
      line "  codex mcp remove nervus"
    fi
    line "  mkdir -p '$home' && printf '\\n[mcp_servers.nervus]\\nurl = \"%s\"\\nhttp_headers_helper = \"%s\"\\n' '$mcp' '$helper' >> '$home/config.toml'"
    # The login file the person's shell reads: zsh reads none of bash's, and bash skips ~/.profile beside its own.
    case ${SHELL:-} in
      */zsh) profile='~/.zprofile' ;;
      */bash) profile='~/.profile'
              if [ -f "$HOME/.bash_profile" ]; then profile='~/.bash_profile'; elif [ -f "$HOME/.bash_login" ]; then profile='~/.bash_login'; fi ;;
      *) if [ "$os" = mac ]; then profile='~/.zprofile'; else profile='~/.profile'; fi ;;
    esac
    if [ "${CODEX_CA_CERTIFICATE:-}" != "$bundle" ]; then
      if [ "$os" = mac ]; then
        line "  echo \"export CODEX_CA_CERTIFICATE='$bundle'\" >> $profile"
        line
        line "Then open a new terminal for Codex's command line. For the ChatGPT app, where Codex also runs, and"
        line "which sees no terminal's settings, also run this, then quit the app (Command-Q) and open it again;"
        line "it lasts until you log out:"
        line
        line "  launchctl setenv CODEX_CA_CERTIFICATE '$bundle'"
      else
        line "  echo \"export CODEX_CA_CERTIFICATE='$bundle'\" >> $profile"
        line
        line "Then log in again, so Codex is started with it."
      fi
      line
      line "CODEX_CA_CERTIFICATE adds nervus's roots to those Codex trusts. Not SSL_CERT_FILE, which replaces them."
    fi
    line "If codex mcp get nervus shows a server already, run codex mcp remove nervus before the rest."
    if [ "$os" = mac ]; then
      line "When it connects, macOS asks whether security may use $item: Allow, never Always Allow."
    fi
    ;;
  *)
    line "For your client: nervus's MCP address is $mcp. For a client that can run a command for its headers,"
    line "$helper prints them, {\"Authorization\": \"Bearer ...\"}. The roots it should trust are in $bundle."
    ;;
esac
}

# Only now, with every line of it here, does anything run; with nothing on its standard input, which a pipe
# would otherwise be.
nervus_laptop </dev/null
}
