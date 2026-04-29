# MiniSOC - Automated Task Scheduler Setup
# Run this script as Administrator to enable automated detection

Write-Host "=== MiniSOC Task Scheduler Setup ===" -ForegroundColor Cyan
Write-Host ""

# Check for admin privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $IsAdmin) {
    Write-Host "[!] ERROR: This script requires Administrator privileges" -ForegroundColor Red
    Write-Host "[!] Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit
}

# Configuration
$ScriptPath = "$PSScriptRoot\MiniSOC-Detection.ps1"
$TaskName = "MiniSOC-Detection"
$IntervalMinutes = 5

Write-Host "[*] Setting up automated detection..." -ForegroundColor Yellow
Write-Host "    Script: $ScriptPath" -ForegroundColor Gray
Write-Host "    Interval: Every $IntervalMinutes minutes" -ForegroundColor Gray
Write-Host ""

# Check if script exists
if (-not (Test-Path $ScriptPath)) {
    Write-Host "[!] ERROR: MiniSOC-Detection.ps1 not found" -ForegroundColor Red
    Write-Host "[!] Please ensure it's in the same folder as this script" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit
}

# Remove existing task if it exists
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
    Write-Host "[*] Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Create scheduled task
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration ([TimeSpan]::MaxValue)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings | Out-Null

Write-Host ""
Write-Host "[+] SUCCESS: Automated detection enabled!" -ForegroundColor Green
Write-Host ""
Write-Host "=== Task Details ===" -ForegroundColor Cyan
Write-Host "  Task Name: $TaskName" -ForegroundColor White
Write-Host "  Runs every: $IntervalMinutes minutes" -ForegroundColor White
Write-Host "  Runs as: SYSTEM (highest privileges)" -ForegroundColor White
Write-Host "  Status: Running" -ForegroundColor Green
Write-Host ""

Write-Host "=== Management Commands ===" -ForegroundColor Cyan
Write-Host "  View task:" -ForegroundColor White
Write-Host "    Get-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Gray
Write-Host ""
Write-Host "  Disable task:" -ForegroundColor White
Write-Host "    Disable-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Gray
Write-Host ""
Write-Host "  Remove task:" -ForegroundColor White
Write-Host "    Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false" -ForegroundColor Gray
Write-Host ""

Write-Host "[+] Your SOC is now operational and monitoring automatically!" -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to exit"
