# nervus-headers.ps1 -- the header that carries one nervus token, for a client to send when it
# connects (ADR-0032 question 11). nervus's laptop line put this here.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File nervus-headers.ps1 <name>
#
# Claude Code's headersHelper and Codex's http_headers_helper run it when they connect to nervus,
# and send what it prints as the request's headers: {"Authorization": "Bearer <token>"}, and
# nothing else. The token is never written to a file, the error output or an environment variable.
#
# The token is kept in the file token-<name> beside this helper, encrypted by Windows for your
# Windows account alone (DPAPI): another account on this computer, or a copy of the file taken
# elsewhere, cannot read it.
param([string]$Name)
$ErrorActionPreference = 'Stop'
if (-not $Name -or $Name -notmatch '^[A-Za-z0-9._-]+$') {
    [Console]::Error.WriteLine('usage: nervus-headers.ps1 <name>')
    exit 2
}
$file = Join-Path $PSScriptRoot "token-$Name"
try {
    $secure = ConvertTo-SecureString -String ([IO.File]::ReadAllText($file).Trim())
    $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
} catch {
    [Console]::Error.WriteLine("nervus-headers: cannot read the token in $file")
    exit 1
}
# A token is URL-safe base64. Checked, so a wrong file is refused rather than sent, and the value goes
# into JSON as it is.
if ($token -notmatch '^[A-Za-z0-9_-]{32,}$') {
    [Console]::Error.WriteLine("nervus-headers: what is kept in $file is not a nervus token")
    exit 1
}
[Console]::Out.WriteLine('{"Authorization": "Bearer ' + $token + '"}')
