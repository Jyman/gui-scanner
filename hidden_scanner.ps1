#Requires -RunAsAdministrator
<#
.SYNOPSIS
    隐藏进程与注册表启动项扫描器
.DESCRIPTION
    1) 枚举所有运行进程，检查其主程序文件是否具有 Hidden 或 System 属性
    2) 扫描注册表启动项（HKLM/HKCU Run/RunOnce），标记具有 Hidden/System 属性的启动项指向的文件
#>

# ------------------------------------------------------------
# 1. 扫描隐藏属性的进程文件
# ------------------------------------------------------------
Write-Host "`n========== [1] 隐藏属性进程扫描 ==========" -ForegroundColor Cyan

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
        # 跳过无法访问的进程（系统级保护等）
    }
}

if ($hiddenProcessFiles.Count -gt 0) {
    Write-Host "[!] 发现 $($hiddenProcessFiles.Count) 个隐藏/系统属性进程文件：" -ForegroundColor Red
    $hiddenProcessFiles | Format-Table -AutoSize -Wrap | Out-Host
} else {
    Write-Host "[OK] 所有进程文件均无 Hidden/System 属性。" -ForegroundColor Green
}

# ------------------------------------------------------------
# 2. 扫描注册表启动项，检测 H/S 属性
# ------------------------------------------------------------
Write-Host "`n========== [2] 注册表启动项 H/S 属性扫描 ==========" -ForegroundColor Cyan

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
    <#
    从注册表值中提取实际文件路径。
    典型格式：
      "C:\Program Files\App\app.exe" --arg
      "C:\Program Files\App\app.exe"
      C:\Program Files\App\app.exe -flag
      svchost.exe -k netsvcs   （仅文件名，需在 PATH 中查找）
    #>
    $val = $RawValue.Trim()

    # 去掉引号包裹
    if ($val -match '^"([^"]+)"') { return $matches[1] }

    # 去掉开头 @ 或环境变量展开后的路径段
    if ($val -match '^@\S+') { return $null }

    # 常见模式：路径开头，空格或参数分隔
    if ($val -match '^([a-zA-Z]:\\[^\s]+(?:\.[a-zA-Z]{1,4}))\b') {
        $candidate = $matches[1]
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    # 处理 SystemRoot / ProgramFiles 等环境变量
    $expanded = [System.Environment]::ExpandEnvironmentVariables($val)
    if ($expanded -match '^"([^"]+)"') { return $matches[1] }
    if ($expanded -match '^([a-zA-Z]:\\[^\s]+(?:\.[a-zA-Z]{1,4}))\b') {
        $candidate = $matches[1]
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    # 仅文件名的情况：在 PATH 中搜索
    if ($val -match '^([\w\-\.]+\.exe)\b') {
        $found = Get-Command $matches[1] -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }

    return $null
}

foreach ($rp in $regPaths) {
    $hive = $rp.Hive
    $key  = $rp.Key
    $label = $rp.Label

    try {
        $regKey = switch ($hive) {
            "HKLM" { Registry::HKEY_LOCAL_MACHINE\$key }
            "HKCU" { Registry::HKEY_CURRENT_USER\$key }
        }
        $subKey = Get-Item -LiteralPath $regKey -ErrorAction Stop
        $values = $subKey.GetValueNames()

        foreach ($vname in $values) {
            $rawVal  = $subKey.GetValue($vname)
            $rawStr  = if ($rawVal -is [byte[]]) { "[REG_BINARY]" } else { $rawVal.ToString() }

            $targetPath = Resolve-TargetPath -RawValue $rawStr

            $isHidden = $false
            $isSystem = $false
            $fileAttrs = ""

            if ($targetPath -and (Test-Path -LiteralPath $targetPath)) {
                $item = Get-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
                if ($item) {
                    $attrs = $item.Attributes
                    $isHidden = ($attrs -band [System.IO.FileAttributes]::Hidden) -ne 0
                    $isSystem = ($attrs -band [System.IO.FileAttributes]::System) -ne 0
                    $fileAttrs = $attrs.ToString()
                }
            }

            $flagList = @()
            if ($isHidden)  { $flagList += "H" }
            if ($isSystem)  { $flagList += "S" }

            $entry = [PSCustomObject]@{
                Source       = $label
                Name         = $vname
                RawValue     = $rawStr
                ResolvedPath = if ($targetPath) { $targetPath } else { "(未解析)" }
                FileAttrs    = $fileAttrs
                Flags        = $flagList -join "/"
            }

            $allEntries += $entry

            if ($isHidden -or $isSystem) {
                $suspiciousEntries += $entry
            }
        }
    } catch {
        # 注册表项不存在或无法访问，跳过
    }
}

# 输出所有启动项
Write-Host "`n[全部启动项] ($($allEntries.Count) 条)" -ForegroundColor Yellow
if ($allEntries.Count -gt 0) {
    $allEntries | Format-Table -AutoSize -Wrap -Property Source, Name, Flags, ResolvedPath, FileAttrs | Out-Host
}

# 输出可疑项
if ($suspiciousEntries.Count -gt 0) {
    Write-Host "`n[!] 发现 $($suspiciousEntries.Count) 条 H/S 属性启动项：" -ForegroundColor Red
    $suspiciousEntries | Format-Table -AutoSize -Wrap -Property Source, Name, Flags, ResolvedPath, FileAttrs | Out-Host
} else {
    Write-Host "`n[OK] 所有启动项指向文件均无 Hidden/System 属性。" -ForegroundColor Green
}

# ------------------------------------------------------------
# 汇总
# ------------------------------------------------------------
Write-Host "`n========== 汇总 ==========" -ForegroundColor Cyan
Write-Host "  隐藏属性进程文件 : $($hiddenProcessFiles.Count)"
Write-Host "  注册表启动项总数 : $($allEntries.Count)"
Write-Host "  H/S 属性启动项   : $($suspiciousEntries.Count)"
Write-Host ""
