# MiniSOC Detection Engine - Production Grade
# Detects failed login attempts and maintains historical findings

# Configuration
$FindingsFile = "findings.json"
$TimeWindow = 240  # minutes
$FailureThreshold = 3

Write-Host "=== MiniSOC Detection Engine ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# Get failed login events (Event ID 4625) from the last time window
$StartTime = (Get-Date).AddMinutes(-$TimeWindow)

try {
    $FailedLogins = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue

    if ($FailedLogins) {
        Write-Host "[+] Found $($FailedLogins.Count) failed login events" -ForegroundColor Yellow
        
        # Group by target account
        $GroupedFailures = $FailedLogins | Group-Object -Property {
            $_.Properties[5].Value  # TargetUserName
        }

        # Detect repeated failures
        $Detections = @()
        foreach ($Group in $GroupedFailures) {
            if ($Group.Count -ge $FailureThreshold) {
                $Username = $Group.Name
                $Count = $Group.Count
                
                # Determine severity based on attempt count
                $Severity = switch ($Count) {
                    {$_ -ge 10} { "High" }
                    {$_ -ge 5} { "Medium" }
                    default { "Low" }
                }

                $Detection = [PSCustomObject]@{
                    Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")  # ISO 8601 with timezone
                    Severity = $Severity
                    Type = "Brute Force"
                    EventID = 4625
                    Count = $Count
                    Message = "Detected $Count failed login attempts for user '$Username' within $TimeWindow minutes."
                }

                $Detections += $Detection
                Write-Host "[!] ALERT: $($Detection.Message)" -ForegroundColor Red
            }
        }

        if ($Detections.Count -gt 0) {
            # Load existing findings
            $ExistingFindings = @()
            if (Test-Path $FindingsFile) {
                try {
                    $ExistingFindings = Get-Content $FindingsFile -Raw | ConvertFrom-Json
                    # Ensure it's always an array
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
    } else {
        Write-Host "[i] No failed login events found in the last $TimeWindow minutes" -ForegroundColor Gray
    }

} catch {
    Write-Host "[!] Error accessing Security logs: $_" -ForegroundColor Red
    Write-Host "[!] Ensure you're running as Administrator" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Detection Complete ===" -ForegroundColor Cyan