# MiniSOC Advanced Detection Engine
# Multiple detection capabilities: Brute Force, Credential Stuffing, Privilege Escalation, Policy Changes

# Configuration
$FindingsFile = "findings.json"
$TimeWindow = 240  # minutes
$FailureThreshold = 3

Write-Host "=== MiniSOC Advanced Detection Engine ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')" -ForegroundColor Gray
Write-Host "Detection Window: $TimeWindow minutes" -ForegroundColor Gray
Write-Host ""

$StartTime = (Get-Date).AddMinutes(-$TimeWindow)
$Detections = @()

# ==========================================
# DETECTION 1: Brute Force (Failed Logins)
# ==========================================
Write-Host "[*] Running Detection: Brute Force Attacks..." -ForegroundColor Yellow

try {
    $FailedLogins = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    if ($FailedLogins) {
        $GroupedFailures = $FailedLogins | Group-Object -Property {
            $_.Properties[5].Value  # TargetUserName
        }

        foreach ($Group in $GroupedFailures) {
            if ($Group.Count -ge $FailureThreshold) {
                $Username = $Group.Name
                $Count = $Group.Count
                
                $Severity = switch ($Count) {
                    {$_ -ge 10} { "High" }
                    {$_ -ge 5} { "Medium" }
                    default { "Low" }
                }

                $Detection = [PSCustomObject]@{
                    Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
                    Severity = $Severity
                    Type = "Brute Force"
                    EventID = 4625
                    Count = $Count
                    Message = "Detected $Count failed login attempts for user '$Username' within $TimeWindow minutes."
                }

                $Detections += $Detection
                Write-Host "  [!] ALERT: Brute Force - $Count attempts on '$Username'" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "  [!] Could not access Event ID 4625" -ForegroundColor DarkYellow
}

# ==========================================
# DETECTION 2: Credential Stuffing
# ==========================================
Write-Host "[*] Running Detection: Credential Stuffing..." -ForegroundColor Yellow

try {
    # Get both failed and successful logins
    $FailedLogins = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    $SuccessfulLogins = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4624
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    if ($FailedLogins -and $SuccessfulLogins) {
        # Group failures by username
        $FailedByUser = @{}
        foreach ($Event in $FailedLogins) {
            $Username = $Event.Properties[5].Value
            if (-not $FailedByUser.ContainsKey($Username)) {
                $FailedByUser[$Username] = @()
            }
            $FailedByUser[$Username] += $Event
        }

        # Check for successful logins after failures
        foreach ($SuccessEvent in $SuccessfulLogins) {
            $Username = $SuccessEvent.Properties[5].Value
            
            # Skip system accounts
            if ($Username -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-)') {
                continue
            }

            if ($FailedByUser.ContainsKey($Username)) {
                $FailureCount = $FailedByUser[$Username].Count
                
                # Check if success came after failures
                $LastFailure = ($FailedByUser[$Username] | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                
                if ($SuccessEvent.TimeCreated -gt $LastFailure -and $FailureCount -ge 2) {
                    $Detection = [PSCustomObject]@{
                        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
                        Severity = "High"
                        Type = "Credential Stuffing"
                        EventID = 4624
                        Count = $FailureCount + 1
                        Message = "Successful login for '$Username' after $FailureCount failed attempts - possible credential stuffing attack."
                    }

                    $Detections += $Detection
                    Write-Host "  [!] ALERT: Credential Stuffing - '$Username' logged in after $FailureCount failures" -ForegroundColor Red
                }
            }
        }
    }
} catch {
    Write-Host "  [!] Could not correlate login events" -ForegroundColor DarkYellow
}

# ==========================================
# DETECTION 3: Privilege Escalation
# ==========================================
Write-Host "[*] Running Detection: Privilege Escalation..." -ForegroundColor Yellow

try {
    $PrivEscalation = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4672  # Special privileges assigned to new logon
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    if ($PrivEscalation) {
        # Count privilege assignments
        if ($PrivEscalation.Count -ge 5) {
            $Detection = [PSCustomObject]@{
                Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
                Severity = "Medium"
                Type = "Privilege Escalation"
                EventID = 4672
                Count = $PrivEscalation.Count
                Message = "Detected $($PrivEscalation.Count) privilege escalation events within $TimeWindow minutes."
            }

            $Detections += $Detection
            Write-Host "  [!] ALERT: Multiple privilege escalations detected" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "  [!] Could not access Event ID 4672" -ForegroundColor DarkYellow
}

# ==========================================
# DETECTION 4: Security Policy Changes
# ==========================================
Write-Host "[*] Running Detection: Policy Modifications..." -ForegroundColor Yellow

try {
    $PolicyChanges = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4719  # System audit policy was changed
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    if ($PolicyChanges) {
        foreach ($Event in $PolicyChanges) {
            $Detection = [PSCustomObject]@{
                Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
                Severity = "Medium"
                Type = "Policy Violation"
                EventID = 4719
                Count = 1
                Message = "System audit policy was modified - potential security control bypass attempt."
            }

            $Detections += $Detection
            Write-Host "  [!] ALERT: Security policy modification detected" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "  [!] Could not access Event ID 4719" -ForegroundColor DarkYellow
}

# ==========================================
# SAVE FINDINGS
# ==========================================
Write-Host ""
if ($Detections.Count -gt 0) {
    # Load existing findings
    $ExistingFindings = @()
    if (Test-Path $FindingsFile) {
        try {
            $ExistingFindings = Get-Content $FindingsFile -Raw | ConvertFrom-Json
            if ($ExistingFindings -isnot [Array]) {
                $ExistingFindings = @($ExistingFindings)
            }
            Write-Host "[+] Loaded $($ExistingFindings.Count) existing findings" -ForegroundColor Green
        } catch {
            Write-Host "[!] Could not parse existing findings, starting fresh" -ForegroundColor Yellow
            $ExistingFindings = @()
        }
    }

    # Append new detections
    $AllFindings = @($ExistingFindings) + @($Detections)
    
    # Save to JSON
    $AllFindings | ConvertTo-Json -Depth 3 | Out-File $FindingsFile -Encoding UTF8
    
    Write-Host "[+] Saved $($Detections.Count) new findings (Total: $($AllFindings.Count))" -ForegroundColor Green
    Write-Host "[+] Findings written to: $FindingsFile" -ForegroundColor Cyan
} else {
    Write-Host "[i] No threats detected in this scan" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Detection Complete ===" -ForegroundColor Cyan
Write-Host "Summary: $($Detections.Count) new threats detected" -ForegroundColor White
