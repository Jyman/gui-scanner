#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hidden process & registry startup scanner
.DESCRIPTION
    1) Enumerate running processes, detect H/S attribute on executable files
    2) Scan registry Run/RunOnce entries, flag H/S attributed targets
#>

# ------------------------------------------------------------
# 1. Scan running processes for Hidden/System file attributes
# ------------------------------------------------------------
Write-Host "`n========== [1] Hidden Attribute Process Scan ==========" -ForegroundColor Cyan

$processes = Get-Process -ErrorAction SilentlyContinue
$hiddenProcessFiles = @()
$seenPaths = @{}

foreach ($proc in $processes) {
    try {
        $path = $proc.Path
        if (-not $path) { continue }
        if ($seenPaths[$path]) { continue }
        $seenPaths[$path] = $true

        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $attrs = $item.Attributes

        $isHidden = $attrs -band [System.IO.FileAttributes]::Hidden
        $isSystem = $attrs -band [System.IO.FileAttributes]::System

        if ($isHidden -or $isSystem) {
            $flagList = @()
            if ($isHidden)  { $flagList += "H" }
            if ($isSystem)  { $flagList += "S" }

            $hiddenProcessFiles += [PSCustomObject]@{
                PID        = $proc.Id
                Process    = $proc.ProcessName
                Path       = $path
                Attributes = $attrs.ToString()
                Flags      = $flagList -join "/"
            }
        }
    } catch {
        # skip inaccessible processes
    }
}

if ($hiddenProcessFiles.Count -gt 0) {
    Write-Host "[!] Found $($hiddenProcessFiles.Count) hidden/system process file(s):" -ForegroundColor Red
    $hiddenProcessFiles | Format-Table -AutoSize -Wrap | Out-Host
} else {
    Write-Host "[OK] No Hidden/System attribute on any process file." -ForegroundColor Green
}

# ------------------------------------------------------------
# 2. Scan registry startup entries for H/S attributes
# ------------------------------------------------------------
Write-Host "`n========== [2] Registry Startup H/S Scan ==========" -ForegroundColor Cyan

$regPaths = @(
    @{ Hive = "HKLM"; Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"       ; Label = "HKLM Run"       },
    @{ Hive = "HKLM"; Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"   ; Label = "HKLM RunOnce"   },
    @{ Hive = "HKCU"; Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"       ; Label = "HKCU Run"       },
    @{ Hive = "HKCU"; Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"   ; Label = "HKCU RunOnce"   },
    @{ Hive = "HKLM"; Key = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Label = "HKLM Run (WOW64)" },
    @{ Hive = "HKLM"; Key = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"; Label = "HKLM RunOnce (WOW64)" }
)

$suspiciousEntries = @()
$allEntries = @()

function Resolve-TargetPath {
    param([string]$RawValue)

    $val = $RawValue.Trim()

    # Quoted path: "C:\path\app.exe" --arg
    if ($val -match '^"([^"]+)"') { return $matches[1] }

    # Skip @-prefixed DLL resource strings
    if ($val -match '^@\S+') { return $null }

    # Bare path with possible trailing args
    if ($val -match '^[a-zA-Z]:\\[^\s]+\.[a-zA-Z]{1,4}') {
        $candidate = $matches[0]
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    # Expand environment variables then retry
    $expanded = [System.Environment]::ExpandEnvironmentVariables($val)
    if ($expanded -match '^"([^"]+)"') { return $matches[1] }
    if ($expanded -match '^[a-zA-Z]:\\[^\s]+\.[a-zA-Z]{1,4}') {
        $candidate = $matches[0]
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    # Bare exe name - search in PATH
    if ($val -match '^[\w\-\.]+\.exe') {
        $exeName = $matches[0]
        $found = Get-Command $exeName -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }

    return $null
}

foreach ($rp in $regPaths) {
    $hive  = $rp.Hive
    $key   = $rp.Key
    $label = $rp.Label

    try {
        if ($hive -eq "HKLM") {
            $regKey = "Registry::HKEY_LOCAL_MACHINE\$key"
        } else {
            $regKey = "Registry::HKEY_CURRENT_USER\$key"
        }

        $subKey = Get-Item -LiteralPath $regKey -ErrorAction Stop
        $values = $subKey.GetValueNames()

        foreach ($vname in $values) {
            $rawVal  = $subKey.GetValue($vname)
            $rawStr  = if ($rawVal -is [byte[]]) { "[REG_BINARY]" } else { $rawVal.ToString() }

            $targetPath = Resolve-TargetPath -RawValue $rawStr

            $isHidden  = $false
            $isSystem  = $false
            $fileAttrs = ""

            if ($targetPath -and (Test-Path -LiteralPath $targetPath)) {
                $item = Get-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
                if ($item) {
                    $attrs     = $item.Attributes
                    $isHidden  = ($attrs -band [System.IO.FileAttributes]::Hidden) -ne 0
                    $isSystem  = ($attrs -band [System.IO.FileAttributes]::System) -ne 0
                    $fileAttrs = $attrs.ToString()
                }
            }

            $flagList = @()
            if ($isHidden)  { $flagList += "H" }
            if ($isSystem)  { $flagList += "S" }

            $resolvedDisplay = if ($targetPath) { $targetPath } else { "(unresolved)" }

            $entry = [PSCustomObject]@{
                Source       = $label
                Name         = $vname
                RawValue     = $rawStr
                ResolvedPath = $resolvedDisplay
                FileAttrs    = $fileAttrs
                Flags        = $flagList -join "/"
            }

            $allEntries += $entry

            if ($isHidden -or $isSystem) {
                $suspiciousEntries += $entry
            }
        }
    } catch {
        # Key does not exist or inaccessible - skip
    }
}

# Output all startup entries
Write-Host "`n[All Startup Entries] ($($allEntries.Count) items)" -ForegroundColor Yellow
if ($allEntries.Count -gt 0) {
    $allEntries | Format-Table -AutoSize -Wrap -Property Source, Name, Flags, ResolvedPath, FileAttrs | Out-Host
}

# Output suspicious entries
if ($suspiciousEntries.Count -gt 0) {
    Write-Host "`n[!] Found $($suspiciousEntries.Count) H/S flagged startup item(s):" -ForegroundColor Red
    $suspiciousEntries | Format-Table -AutoSize -Wrap -Property Source, Name, Flags, ResolvedPath, FileAttrs | Out-Host
} else {
    Write-Host "`n[OK] No Hidden/System attribute on any startup entry target." -ForegroundColor Green
}

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------
Write-Host "`n========== Summary ==========" -ForegroundColor Cyan
Write-Host "  Hidden process files    : $($hiddenProcessFiles.Count)"
Write-Host "  Total startup entries   : $($allEntries.Count)"
Write-Host "  H/S flagged entries     : $($suspiciousEntries.Count)"
Write-Host ""
