<#
siem-ctf - helper launcher (Windows PowerShell 5.1+ / PowerShell 7 on any OS).
Linux/macOS can also use ./run.sh

Usage:
  .\run.ps1 setup               one-time: create .venv and install requirements
  .\run.ps1 server [port]       start the WebSocket server (auto-picks a free port)
  .\run.ps1 monitor             start the host SIEM monitor CLI (127.0.0.1)
  .\run.ps1 attack [nick] [url] start an attacker CLI (students: pass the host URL)
  .\run.ps1 grade [--csv f.csv] print the per-attacker results table (grading)
  .\run.ps1 ip                  print the URL classmates should connect to
  .\run.ps1 reset               empty the event + defense logs
  .\run.ps1 showcase [--quiet]  end-to-end demo + smoke test (isolated temp logs)

Students on another PC:
  .\run.ps1 attack alice ws://192.168.1.42:8000/ws

If Windows says "running scripts is disabled on this system", run instead:
  powershell -ExecutionPolicy Bypass -File .\run.ps1 setup
#>
param(
    [Parameter(Position = 0)][string]$Command = "help",
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)][string[]]$Rest = @()
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

# Python child processes: UTF-8 output even on cp1252 consoles.
$env:PYTHONUTF8 = "1"

$Venv = Join-Path $PSScriptRoot ".venv"
$VenvPyWin = Join-Path $Venv "Scripts\python.exe"
$VenvPyNix = Join-Path $Venv "bin/python"
$DataDir = Join-Path $PSScriptRoot "data"

function Get-VenvPython {
    if (Test-Path -LiteralPath $VenvPyWin) { return $VenvPyWin }
    if (Test-Path -LiteralPath $VenvPyNix) { return $VenvPyNix }
    return $null
}

function Need-Venv {
    $py = Get-VenvPython
    if (-not $py) {
        Write-Host "[!] no venv found. Run:  .\run.ps1 setup" -ForegroundColor Red
        exit 1
    }
    return $py
}

# Returns @(exe, extra-args...) for a system Python >= 3.10, or $null.
# Tries the Windows "py" launcher first; skips the Microsoft Store stub.
function Find-SystemPython {
    # (strings, not nested arrays: PowerShell would flatten @(@(..), @(..)))
    foreach ($spec in @("py -3", "python", "python3")) {
        $c = @($spec -split " ")
        if (-not (Get-Command $c[0] -ErrorAction SilentlyContinue)) { continue }
        $extra = @()
        if ($c.Count -gt 1) { $extra = $c[1..($c.Count - 1)] }
        try {
            & $c[0] @extra -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) { return , $c }
        } catch { }
    }
    return $null
}

function Resolve-Port {
    if ($env:PORT) { return $env:PORT }
    $rp = Join-Path $DataDir ".runtime_port"
    # -Force: on macOS/Linux PowerShell treats dot-files as hidden.
    if (Test-Path -LiteralPath $rp) {
        $v = Get-Content -LiteralPath $rp -Raw -Force -ErrorAction SilentlyContinue
        if ($v -and $v.Trim()) { return $v.Trim() }
    }
    return "8000"
}

function Invoke-Py {
    param([string]$Py, [string[]]$PyArgs)
    & $Py @PyArgs
    exit $LASTEXITCODE
}

switch ($Command.ToLower()) {

    "setup" {
        $sys = Find-SystemPython
        if (-not $sys) {
            Write-Host "[!] Python 3.10+ not found." -ForegroundColor Red
            Write-Host "    Windows: winget install Python.Python.3.12"
            Write-Host "             or https://www.python.org/downloads/ (tick 'Add python.exe to PATH')"
            Write-Host "    macOS:   brew install python"
            exit 1
        }
        $exe = $sys[0]
        $extra = @()
        if ($sys.Count -gt 1) { $extra = $sys[1..($sys.Count - 1)] }
        $ver = & $exe @extra --version
        Write-Host "[*] using $ver ($($sys -join ' '))"
        Write-Host "[*] creating venv in .venv ..."
        & $exe @extra -m venv $Venv
        if ($LASTEXITCODE -ne 0) { Write-Host "[!] venv creation failed" -ForegroundColor Red; exit 1 }
        $py = Get-VenvPython
        & $py -m pip install --upgrade pip
        & $py -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) { Write-Host "[!] pip install failed" -ForegroundColor Red; exit 1 }
        Write-Host "[*] done. Host:  .\run.ps1 server     Student:  .\run.ps1 attack <nick> ws://<host-ip>:<port>/ws" -ForegroundColor Green
    }

    "server" {
        $py = Need-Venv
        if ($Rest.Count -ge 1 -and $Rest[0]) { $env:PORT = $Rest[0] }
        $port = Resolve-Port
        Write-Host "[i] Windows Firewall may ask to allow Python: choose 'Private networks'." -ForegroundColor DarkGray
        Write-Host "    No prompt but students can't connect? (admin PowerShell):" -ForegroundColor DarkGray
        Write-Host "    New-NetFirewallRule -DisplayName siem-ctf -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Private" -ForegroundColor DarkGray
        Invoke-Py $py @("-m", "server")
    }

    "monitor" {
        $py = Need-Venv
        $port = Resolve-Port
        Invoke-Py $py @("clients/monitor.py", "--url", "ws://127.0.0.1:$port/ws")
    }

    "attack" {
        $py = Need-Venv
        $nick = "attacker"
        if ($Rest.Count -ge 1 -and $Rest[0]) { $nick = $Rest[0] }
        $port = Resolve-Port
        $url = "ws://127.0.0.1:$port/ws"
        if ($env:URL) { $url = $env:URL }
        if ($Rest.Count -ge 2 -and $Rest[1]) { $url = $Rest[1] }
        Invoke-Py $py @("clients/attacker.py", "--url", $url, "--nick", $nick)
    }

    "grade" {
        $py = Need-Venv
        Invoke-Py $py (@("clients/grade.py") + $Rest)
    }

    "ip" {
        $port = Resolve-Port
        $ip = $null
        $py = Get-VenvPython
        if ($py) {
            try { $ip = (& $py -c "from server import config; print(config.lan_ip())" 2>$null) } catch { }
        }
        if ($ip -and $ip -ne "127.0.0.1") {
            Write-Host "ws://$($ip.Trim()):$port/ws"
        } else {
            Write-Host "ws://<your-ip>:$port/ws   (could not auto-detect; try: ipconfig)"
        }
    }

    "showcase" {
        $py = Need-Venv
        Invoke-Py $py (@("clients/showcase.py") + $Rest)
    }

    "reset" {
        if (-not (Test-Path -LiteralPath $DataDir)) { New-Item -ItemType Directory -Path $DataDir | Out-Null }
        foreach ($f in @("events.jsonl", "defense.jsonl")) {
            [System.IO.File]::WriteAllText((Join-Path $DataDir $f), "")
        }
        Write-Host "[*] logs reset (data/events.jsonl, data/defense.jsonl)"
    }

    default {
        # Print the usage block at the top of this file.
        $lines = Get-Content -LiteralPath $PSCommandPath
        $end = [Array]::IndexOf($lines, "#>")
        $lines[1..($end - 1)] | ForEach-Object { Write-Host $_ }
    }
}
