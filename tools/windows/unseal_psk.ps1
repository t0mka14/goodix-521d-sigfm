<#
  Unseal the Goodix 27c6:521d TLS PSK that Windows stored (DPAPI-sealed) in the sensor.

  Run from an Administrator PowerShell:
      cd C:\goodix-psk
      powershell -ExecutionPolicy Bypass -File .\unseal_psk.ps1

  It tries the unseal as LOCAL SERVICE (the account the UMDF driver host normally
  uses), then as SYSTEM, each in a temporary scheduled task that is removed again.
  Every attempt writes child_<TAG>.log. The key is saved to goodix.psk only when
  SHA-256(key) equals the hash the sensor reports (mcu_hash.txt).
#>
param(
    [switch]$Child,
    [string]$Tag = ""
)

$Dir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$BlobPath = Join-Path $Dir "dpapi_blob.bin"
$HashPath = Join-Path $Dir "mcu_hash.txt"
$OutPath  = Join-Path $Dir "goodix.psk"

if ($Child) {
    try {
        Write-Output "account: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        Add-Type -AssemblyName System.Security
        $blob  = [System.IO.File]::ReadAllBytes($BlobPath)
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
                     $blob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $sha   = [System.Security.Cryptography.SHA256]::Create()
        $got   = ([System.BitConverter]::ToString($sha.ComputeHash($plain))).Replace("-", "").ToLower()
        $want  = (Get-Content $HashPath -Raw).Trim().ToLower()
        Write-Output "unsealed $($plain.Length) bytes, sha256 $got"
        Write-Output "sensor hash          $want"
        if ($got -eq $want) {
            $hex = ([System.BitConverter]::ToString($plain)).Replace("-", "").ToLower()
            [System.IO.File]::WriteAllText($OutPath, $hex + "`n")
            Write-Output "RESULT: OK, hash matches, saved goodix.psk"
        } else {
            [System.IO.File]::WriteAllBytes((Join-Path $Dir "candidate_$Tag.bin"), $plain)
            Write-Output "RESULT: unsealed but hash does NOT match (saved candidate_$Tag.bin for analysis)"
        }
    } catch {
        Write-Output "RESULT: FAILED: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
        if ($_.Exception.InnerException) { Write-Output "inner: $($_.Exception.InnerException.Message)" }
    } finally {
        Write-Output "DONE"
    }
    exit 0
}

# ---- Administrator part ----
$me = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this from an Administrator PowerShell." -ForegroundColor Red
    exit 1
}
foreach ($f in @($BlobPath, $HashPath)) {
    if (-not (Test-Path $f)) { Write-Host "Missing $f" -ForegroundColor Red; exit 1 }
}
Remove-Item (Join-Path $Dir "child_*.log"), $OutPath -ErrorAction SilentlyContinue

# Let the service accounts write their log/result into this folder.
icacls $Dir /grant "*S-1-5-19:(OI)(CI)M" "*S-1-5-18:(OI)(CI)M" | Out-Null

$wrapper = Join-Path $Dir "run_child.cmd"
$attempts = @(
    @{ Tag = "LOCALSERVICE"; Sid = "S-1-5-19" },
    @{ Tag = "SYSTEM";       Sid = "S-1-5-18" }
)

foreach ($a in $attempts) {
    $tag  = $a.Tag
    $acct = (New-Object System.Security.Principal.SecurityIdentifier($a.Sid)).Translate(
                [System.Security.Principal.NTAccount]).Value
    $log  = Join-Path $Dir "child_$tag.log"
    $task = "GoodixPskUnseal_$tag"
    Write-Host "[*] Trying as $acct ..."

    $action    = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$wrapper`" $tag"
    $principal = New-ScheduledTaskPrincipal -UserId $acct -LogonType ServiceAccount -RunLevel Highest
    try {
        Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $task
        $deadline = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
            if ((Test-Path $log) -and ((Get-Content $log -Raw) -match "DONE")) { break }
        }
    } catch {
        Write-Host "    could not run task: $($_.Exception.Message)" -ForegroundColor Yellow
    } finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    }

    if (Test-Path $log) {
        Get-Content $log | ForEach-Object { Write-Host "    $_" }
    } else {
        Write-Host "    (no log written: the task did not run)" -ForegroundColor Yellow
    }
    if (Test-Path $OutPath) {
        Write-Host ""
        Write-Host "[+] SUCCESS: C:\goodix-psk\goodix.psk written (verified against the sensor hash)." -ForegroundColor Green
        exit 0
    }
}

Write-Host ""
Write-Host "[-] No attempt produced a verified key. The child_*.log files in C:\goodix-psk say why." -ForegroundColor Red
exit 1
