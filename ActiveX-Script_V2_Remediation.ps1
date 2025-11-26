#String / REG ID / Expected Value
$zoneSettings = @{
    "Local Intranet Zone" = @{
        "- Download signed activex controls" = @{ "ID" = "1001"; "Expected" = "Enable" };
        "- Download unsigned activex controls" = @{ "ID" = "1004"; "Expected" = "Enable" };
        "- Run activex controls and plugins" = @{ "ID" = "1200"; "Expected" = "Enable" };
        "- Initialize and script activex controls not marked as safe for scripting" = @{ "ID" = "1201"; "Expected" = "Enable" };
        "- Allow previously unused activex controls to run without prompt" = @{ "ID" = "1208"; "Expected" = "Enable" };
        "- Allow scriptlets" = @{ "ID" = "1209"; "Expected" = "Enable" };
        "- Script activex controls marked safe for scripting" = @{ "ID" = "1405"; "Expected" = "Enable" };
        "- Binary and script behaviors" = @{ "ID" = "2000"; "Expected" = "Enable" };
        "- Automatic prompting for activex controls" = @{ "ID" = "2201"; "Expected" = "Enable" };
        "- Allow activex filtering" = @{ "ID" = "2702"; "Expected" = "Enable" };
        "- Display video animation on a webpage that does not use external media player" = @{ "ID" = "120A"; "Expected" = "Enable" };
        "- Only allow approved domains to use activex without prompt" = @{ "ID" = "120B"; "Expected" = "Enable" };
        "- Run antimalware software on activex controls" = @{ "ID" = "270C"; "Expected" = "Enable" };
    };
    "TrustedSites Zone" = @{
        "- Download signed activex controls" = @{ "ID" = "1001"; "Expected" = "Enable" };
        "- Download unsigned activex controls" = @{ "ID" = "1004"; "Expected" = "Enable" };
        "- Run activex controls and plugins" = @{ "ID" = "1200"; "Expected" = "Enable" };
        "- Initialize and script activex controls not marked as safe for scripting" = @{ "ID" = "1201"; "Expected" = "Enable" };
        "- Allow previously unused activex controls to run without prompt" = @{ "ID" = "1208"; "Expected" = "Enable" };
        "- Allow scriptlets" = @{ "ID" = "1209"; "Expected" = "Enable" };
        "- Script activex controls marked safe for scripting" = @{ "ID" = "1405"; "Expected" = "Enable" };
        "- Binary and script behaviors" = @{ "ID" = "2000"; "Expected" = "Enable" };
        "- Automatic prompting for activex controls" = @{ "ID" = "2201"; "Expected" = "Enable" };
        "- Allow activex filtering" = @{ "ID" = "2702"; "Expected" = "Enable" };
        "- Display video animation on a webpage that does not use external media player" = @{ "ID" = "120A"; "Expected" = "Enable" };
        "- Only allow approved domains to use activex without prompt" = @{ "ID" = "120B"; "Expected" = "Enable" };
        "- Run antimalware software on activex controls" = @{ "ID" = "270C"; "Expected" = "Enable" };
    };
    "Internet Zone" = @{
        "- Download signed activex controls" = @{ "ID" = "1001"; "Expected" = "Prompt" };
        "- Download unsigned activex controls" = @{ "ID" = "1004"; "Expected" = "Prompt" };
        "- Run activex controls and plugins" = @{ "ID" = "1200"; "Expected" = "Enable" };
        "- Initialize and script activex controls not marked as safe for scripting" = @{ "ID" = "1201"; "Expected" = "Prompt" };
        "- Allow previously unused activex controls to run without prompt" = @{ "ID" = "1208"; "Expected" = "Enable" };
        "- Allow scriptlets" = @{ "ID" = "1209"; "Expected" = "Enable" };
        "- Script activex controls marked safe for scripting" = @{ "ID" = "1405"; "Expected" = "Enable" };
        "- Binary and script behaviors" = @{ "ID" = "2000"; "Expected" = "Enable" };
        "- Automatic prompting for activex controls" = @{ "ID" = "2201"; "Expected" = "Enable" };
        "- Allow activex filtering" = @{ "ID" = "2702"; "Expected" = "Enable" };
        "- Display video animation on a webpage that does not use external media player" = @{ "ID" = "120A"; "Expected" = "Enable" };
        "- Only allow approved domains to use activex without prompt" = @{ "ID" = "120B"; "Expected" = "Enable" };
        "- Run antimalware software on activex controls" = @{ "ID" = "270C"; "Expected" = "Enable" };
    };
}

# Timestamped logs
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "[yyyy-MM-dd HH:mm:ss]"
    Write-Output "$Message"
}

# Get current user SID
function Get-LoggedInUserSID {
    $userName = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    if (-not $userName) {
        Write-Output "No logged in user detected. Exiting."
        exit 0
    }

    $user = $userName.Split('\')[1]
    $sidKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $userSID = (Get-ChildItem $sidKey | Where-Object {
        (Get-ItemProperty $_.PSPath).ProfileImagePath -like "*\$user"
    }).PSChildName

    if (-not $userSID) {
        Write-Output "Could not determine SID for user $user."
        exit 1
    }

    return $userSID
}

# Initialize Logging
function Initialize-Log {
    $logFolderPath = "$env:ProgramData\InternetOptions\Logs"
    if (-not (Test-Path -Path $logFolderPath)) {
        New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null
    }

    $logFilePath = "$logFolderPath\script_log.txt"
    Start-Transcript -Path $logFilePath -Force
}

# Helper to describe DWORD values
function Get-ValueDescription($value) {
    switch ($value) {
        0 { return "Enable" }
        1 { return "Prompt" }
        3 { return "Disable" }
        default { return "Unknown" }
    }
}


# Core Validation & Remediation
function ValidateAndCorrectIEZoneSettings {
    Write-Output "Validating IE security zone settings..."
    
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    $sid = Get-LoggedInUserSID
    Write-Output "User SID = $sid"
    
    $zones = @{
        "Local Intranet Zone" = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1";
        "TrustedSites Zone" = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2";
        "Internet Zone" = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3";
    }

    foreach ($zoneName in $zones.Keys) {
        $zonePath = $zones[$zoneName]
	    Write-Output ""
        Write-Log "Zone: $zoneName"

        foreach ($setting in $zoneSettings[$zoneName].Keys) {
            $description = $setting
            $id = $zoneSettings[$zoneName][$setting]["ID"]
            $expected = $zoneSettings[$zoneName][$setting]["Expected"]
            $expectedValue = switch ($expected) {
                "Enable"  { 0 }
                "Prompt"  { 1 }
                "Disable" { 3 }
                default   { 0 }
            }

            $currentValue = (Get-ItemProperty -Path $zonePath -Name $id -ErrorAction SilentlyContinue).$id
            $currentDesc = Get-ValueDescription $currentValue

            if ($null -eq $currentValue) {
                New-ItemProperty -Path $zonePath -Name $id -Value $expectedValue -PropertyType DWORD -Force | Out-Null
                Write-Log " Created [$description] [$id] = $expected"
            } elseif ($currentDesc -ne $expected) {
                Set-ItemProperty -Path $zonePath -Name $id -Value $expectedValue | Out-Null
                Write-Log " Updated [$description] [$id] from $currentDesc to $expected"
            } else {
                Write-Log "Verified [$description] [$id] = $expected"
            }
        }
    }
}

# Java version check
function Test-JavaVersion {
    Write-Output "`nChecking Java version..."
    try {
        $output = java -version 2>&1 | Select-String 'version "(\d+)\.(\d+)\.(\d+)_?(\d*)"' -AllMatches
        if ($output) {
            $major = [int]$output.Matches[0].Groups[2].Value
            $update = [int]$output.Matches[0].Groups[4].Value
            if ($major -eq 8 -and $update -ge 361) {
                Write-Output " Java 8 Update $update is installed."
            } elseif ($major -eq 8) {
                Write-Output " Java 8 is installed but update < 361."
            } else {
                Write-Output " Java version $major found (not 8)."
            }
        } else {
            throw "Java not installed or not in PATH."
        }
    } catch {
        Write-Output " Java check failed: $($_.Exception.Message)"
    }
}

function Write-ScriptLocally {
    param (
        [string]$LocalFolder = "$env:ProgramData\InternetOptions",
        [string]$ScriptName  = "ActiveX_Script.ps1"
    )

    if (-not (Test-Path $LocalFolder)) {
        New-Item -Path $LocalFolder -ItemType Directory -Force | Out-Null
    }

    $scriptPath = Join-Path $LocalFolder $ScriptName
    $thisScript = $MyInvocation.MyCommand.Definition
    Set-Content -Path $scriptPath -Value $thisScript -Force -Encoding UTF8
    return $scriptPath
}

function Write-ScriptLocally {
    param (
        [string]$LocalFolder = "$env:ProgramData\InternetOptions",
        [string]$ScriptName  = "ActiveX-Script_V2_Remediation.ps1",
        [string]$TaskName    = "IE_Zone_Remediation",
        [string]$TaskDescription = "Reconfigures IE/Edge ActiveX and security zone settings for the current logged-in user."
    )

    if (-not (Test-Path $LocalFolder)) {
        New-Item -Path $LocalFolder -ItemType Directory -Force | Out-Null
    }

    $scriptPath = Join-Path $LocalFolder $ScriptName

    $thisScript = Get-Content -Raw -Path $MyInvocation.PSCommandPath


    # Write the complete script to disk
    Set-Content -Path $scriptPath -Value $thisScript -Force -Encoding UTF8
    Write-Log "Wrote script to: $scriptPath"

    # --- Embed Task Creation ---
    try {
        Write-Log "Ensuring scheduled task '$TaskName' exists..."

        # Remove old task if present
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Log "Removed existing scheduled task '$TaskName'"
        }

        # Determine current logged-in user
        $userName = (Get-WmiObject Win32_ComputerSystem).UserName
        if (-not $userName) {
            Write-Log "No logged-in user detected. Skipping task creation."
            return $scriptPath
        }

        # Define trigger (runs at logon with 30s delay)
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $trigger.Delay = "PT30S"
        # Define action — run the script
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""

        # Define principal as the logged-in user, elevated
     #   $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType Interactive -RunLevel Highest
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

        # Register new task
        Register-ScheduledTask -TaskName $TaskName `
            -Description $TaskDescription `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Force

        Write-Log "Scheduled task '$TaskName' created successfully for user '$userName'."
    }
    catch {
        Write-Log "Failed to create scheduled task: $($_.Exception.Message)"
    }

    return $scriptPath
}



function Set-EdgeIEModePolicies {
    Write-Output "`nConfiguring Microsoft Edge IE mode policies..."

    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

    if (-not (Test-Path $edgePolicyPath)) {
        New-Item -Path $edgePolicyPath -Force | Out-Null
        Write-Log "Created registry path: $edgePolicyPath"
    }

    # Get current username (for site list path)
    $userName = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    if (-not $userName) {
        Write-Log "No logged-in user detected for site list path."
        return
    }

    $user = $userName.Split('\')[1]

    $siteListPath = "C:\Users\$user\Downloads\ie.xml"

    # Define policy values
    $policyValues = @{
        "InternetExplorerIntegrationLevel"= 1
        "InternetExplorerIntegrationReloadInIEModeAllowed"= 1
        "InternetExplorerModeToolbarButtonEnabled"= 1 
        "InternetExplorerIntegrationSiteList"= $siteListPath
    }

    # Apply values
    foreach ($name in $policyValues.Keys) {
        $value = $policyValues[$name]
        $type  = if ($value -is [int]) { "DWord" } else { "String" }
        New-ItemProperty -Path $edgePolicyPath -Name $name -Value $value -PropertyType $type -Force | Out-Null
        Write-Log "Set [$name] = $value ($type)"
    }

    Write-Output "Edge IE mode configuration applied successfully."

    gpupdate /force

}



# Main
try {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Initialize-Log
    Write-Log "Starting IE Zone Hardening..."

    Write-ScriptLocally
    ValidateAndCorrectIEZoneSettings
    Test-JavaVersion
    Set-EdgeIEModePolicies


    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "`n[$timestamp] Script execution completed successfully."

} catch {
    Write-Output "Script failed with error: $($_.Exception.Message)"
} finally {
    Stop-Transcript
}
