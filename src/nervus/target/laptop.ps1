function Invoke-NervusLaptop {
    # Windows PowerShell 5.1 and PowerShell 7 alike. Each failure throws, and the call below says why: never
    # `exit`, which would close the window this was pasted into.
    $ErrorActionPreference = 'Stop'
    function Say([string]$Text) { Write-Host "nervus: $Text" }
    function Fail([string]$Text) { throw "nervus: $Text" }
    # A string as Windows reads one argument of a command line: in double quotes, a quote, and the
    # backslashes before it, escaped.
    function Quote-Arg([string]$Text) {
        '"' + (($Text -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
    }

    $unchanged = 'Nothing here was changed.'
    # Where there is no Windows identity to ask, as in PowerShell on another system, it is no administrator's.
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $admin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        $admin = $false
    }
    if ($admin) {
        Fail "run this in a PowerShell window that is not an administrator's: it sets up your own account, where your client runs. $unchanged"
    }
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        Fail "curl.exe is not here; Windows 10 and 11 carry it. $unchanged"
    }
    $dir = Join-Path $HOME '.config\nervus'
    # The helper's path goes into each client's settings, inside quotes PowerShell would expand.
    if ($dir -match '[`$"'']') {
        Fail "the folder nervus's files go in, $dir, holds a character a client's settings would expand. $unchanged"
    }
    $fwd = $dir -replace '\\', '/'

    # 1. Is this line's code still good? One run again, or too late, stops here, before anything changes.
    $first = & curl.exe -sSk --pinnedpubkey $nervusPin -o NUL -w '%{http_code}' $nervusUrl
    if ($LASTEXITCODE -ne 0) { Fail "could not reach nervus at $nervusOrigin. $unchanged" }
    if ("$first" -ne '200') {
        Fail "this line's code is used or expired (nervus answered $first): on nervus's Clients page, give the token a new line, or issue another. $unchanged"
    }

    # 2. nervus's root, carried above, checked before it is saved: nervus must answer at its host as the root
    #    vouches, since that is how each client will check it. --ssl-no-revoke: nervus's own authority publishes no
    #    revocation list for Windows to ask.
    $tmp = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($tmp, $nervusRoot + "`n")
        # Its error output gathered, not stopped at: Windows PowerShell 5.1 turns a native program's first
        # line of it into an error that stops the script, where errors are set to stop.
        $ErrorActionPreference = 'Continue'
        $err = (& curl.exe -sS -o NUL --max-time 10 --ssl-no-revoke --cacert $tmp "$nervusOrigin/" 2>&1 | Out-String).Trim()
        $ErrorActionPreference = 'Stop'
        if ($LASTEXITCODE -ne 0) {
            Fail "nervus does not check out against its own root as $nervusHost ($err): is $nervusHost one of the names its certificate is for? $unchanged"
        }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $rootFile = Join-Path $dir "root-$nervusSafe.pem"
        if ((Test-Path $rootFile) -and ([IO.File]::ReadAllText($rootFile) -eq [IO.File]::ReadAllText($tmp))) {
            Say "nervus's root for $nervusHost is saved already, at $rootFile"
        } else {
            $was = ''
            if (Test-Path $rootFile) { $was = ", in place of the one saved there before, another nervus's at that name" }
            [IO.File]::WriteAllText($rootFile, [IO.File]::ReadAllText($tmp))
            Say "saved nervus's root at $rootFile$was"
        }
    } finally {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
    }
    # Every nervus root saved here, in the one file each client is told, made again each time: certificates alone get in.
    $bundle = Join-Path $dir 'roots.pem'
    $certs = foreach ($f in Get-ChildItem -Path $dir -Filter 'root-*.pem') {
        [regex]::Matches([IO.File]::ReadAllText($f.FullName),
            '-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----') | ForEach-Object { $_.Value }
    }
    [IO.File]::WriteAllText($bundle, (($certs | ForEach-Object { $_ -replace "`r", '' }) -join "`n") + "`n")
    Say "$bundle holds every nervus root saved here: $(@($certs).Count)"
    $bundleFwd = $bundle -replace '\\', '/'

    # 3. The helper, which gives a client the token's header when it connects.
    $helperFile = Join-Path $dir 'nervus-headers.ps1'
    [IO.File]::WriteAllText($helperFile, $nervusHelper + "`n")
    $helper = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$fwd/nervus-headers.ps1`" $nervusName"
    Say "put the helper at $helperFile"

    # 4. The token: handed over once, for this line's code, and kept, never shown. It is in no command's
    #    arguments: PowerShell holds it, and Windows encrypts it for this account alone.
    $got = @(& curl.exe -sSk --pinnedpubkey $nervusPin -X POST -w '\n%{http_code}' $nervusUrl)
    if ($LASTEXITCODE -ne 0) {
        Fail "could not reach nervus to fetch the token. nervus's root and the helper are saved; run this line again while it works, or make a new one on nervus's Clients page."
    }
    $status = $got[-1]
    $value = (@($got | Select-Object -SkipLast 1) -join "`n").Trim()
    if ("$status" -ne '200') { Fail ("nervus did not hand over the token: " + ($value -replace '^nervus: ', '')) }
    if ($value -notmatch '^[A-Za-z0-9_-]{32,}$') {
        Fail "what nervus sent is not a token. nervus's root and the helper are saved; the token is not."
    }
    $tokenFile = Join-Path $dir "token-$nervusName"
    try {
        $secure = ConvertTo-SecureString -String $value -AsPlainText -Force
        $value = $null
        [IO.File]::WriteAllText($tokenFile, (ConvertFrom-SecureString -SecureString $secure))
    } catch {
        $value = $null
        Fail "nervus handed the token over, and it could not be kept here, so it is lost: revoke $nervusToken on nervus's Clients page and issue another"
    }
    Say "kept the token $nervusToken in $tokenFile, which only your Windows account can read"

    # 5. What the client needs, printed, never run: each change to this computer is one you make (question 6).
    Write-Host ''
    switch ($nervusClient) {
        'claude-code' {
            $config = $env:CLAUDE_CONFIG_DIR
            if (-not $config) { $config = Join-Path $HOME '.claude' }
            $settings = Join-Path $config 'settings.json'
            $json = '{"type":"http","url":"' + $nervusMcp + '","headersHelper":"' + ($helper -replace '"', '\"') + '"}'
            Write-Host 'To use nervus from Claude Code, run these, then start a new session:'
            Write-Host ''
            # --%: PowerShell passes the rest to the program exactly as written, so the quotes in the JSON reach it.
            # Called as the program it is, claude.exe, never a script PowerShell would find first under that name.
            Write-Host "  & (Get-Command claude -CommandType Application)[0].Source --% mcp add-json --scope user nervus $(Quote-Arg $json)"
            $named = $null
            if (Test-Path $settings) {
                # As UTF-8, which Claude Code writes: Windows PowerShell 5.1 reads a file without a BOM in the ANSI code page.
                try { $named = ([IO.File]::ReadAllText($settings) | ConvertFrom-Json).env.NODE_EXTRA_CA_CERTS } catch { }
            }
            if ($named -eq $bundleFwd) {
            } elseif ($named) {
                Write-Host ''
                Write-Host "  Claude Code's settings ($settings) name $named as the file of roots it trusts, and it reads that"
                Write-Host "  one alone. To reach nervus, name $bundleFwd there instead, or, if that file holds a root you"
                Write-Host "  need besides nervus's, add nervus's to it: Get-Content '$bundle' | Add-Content '$named'"
            } else {
                Write-Host "  `$p = '$settings'; New-Item -ItemType Directory -Force (Split-Path `$p) | Out-Null; `$s = if (Test-Path `$p) { [IO.File]::ReadAllText(`$p) | ConvertFrom-Json } else { New-Object PSObject }; if (-not `$s.env) { `$s | Add-Member -NotePropertyName env -NotePropertyValue (New-Object PSObject) }; `$s.env | Add-Member -NotePropertyName NODE_EXTRA_CA_CERTS -NotePropertyValue '$bundleFwd' -Force; [IO.File]::WriteAllText(`$p, (`$s | ConvertTo-Json -Depth 32))"
            }
            Write-Host ''
            Write-Host 'If Claude Code has a server named nervus already, run claude mcp remove --scope user nervus first.'
        }
        'codex' {
            $codexHome = $env:CODEX_HOME
            if (-not $codexHome) { $codexHome = Join-Path $HOME '.codex' }
            $config = Join-Path $codexHome 'config.toml'
            Write-Host 'To use nervus from Codex, run these, then start a new session:'
            Write-Host ''
            $named = '^\s*(\[mcp_servers\.("nervus"|nervus)\]|mcp_servers\.("nervus"|nervus)[\s.=]|nervus\s*=)'
            if ((Test-Path $config) -and (Select-String -Path $config -Pattern $named -Quiet)) {
                Write-Host '  codex mcp remove nervus'
            }
            # codex mcp add has no flag for the helper, and puts its table among the others, so the server is added whole.
            $toml = "`r`n[mcp_servers.nervus]`r`nurl = '$nervusMcp'`r`nhttp_headers_helper = '$helper'`r`n"
            $text = $toml -replace '"', '""' -replace "`r", '`r' -replace "`n", '`n'
            Write-Host "  New-Item -ItemType Directory -Force '$codexHome' | Out-Null; [IO.File]::AppendAllText('$config', `"$text`")"
            if ($env:CODEX_CA_CERTIFICATE -ne $bundle) {
                Write-Host "  [Environment]::SetEnvironmentVariable('CODEX_CA_CERTIFICATE', '$bundle', 'User')"
                Write-Host ''
                Write-Host 'Then open a new window for Codex, or restart the app it runs in, so it is started with it.'
                Write-Host 'CODEX_CA_CERTIFICATE adds nervus''s roots to those Codex trusts. Not SSL_CERT_FILE, which replaces them.'
            }
            Write-Host 'If codex mcp get nervus shows a server already, run codex mcp remove nervus before the rest.'
        }
        default {
            Write-Host "For your client: nervus's MCP address is $nervusMcp. For a client that can run a command for its"
            Write-Host "headers, $helper prints them, {`"Authorization`": `"Bearer ...`"}. The roots it should trust are in $bundle."
        }
    }
}

# Only now, with every line of it here, does anything run.
try { Invoke-NervusLaptop } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
}
