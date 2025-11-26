# Caminho onde os scripts estão copiados
$scriptPath = "C:\ProgramData\InternetOptions"
$remediationScript = Join-Path $scriptPath "ActiveX-Script_V2_Remediation.ps1"

$global:NonCompliant = $false

# Paths esperados
$scriptFolder = "C:\ProgramData\InternetOptions"
$detectionScript = Join-Path $scriptFolder "ActiveX-Script_V2_Detection.ps1"
$remediationScript = Join-Path $scriptFolder "ActiveX-Script_V2_Remediation.ps1"

# Scheduled Tasks esperadas
$taskDetect = "IE_Zone_Detection"
$taskRemed = "IE_Zone_Remediation"


$scriptURL_Detection = "https://github.com/N0rbelio/ActiveX-Script.git\ActiveX-Script_V2_Detection.ps1"
$scriptURL_Remediation = "https://github.com/N0rbelio/ActiveX-Script.git\ActiveX-Script_V2_Remediation.ps1"

# Cria pasta se não existir
if (-not (Test-Path $scriptPath)) {
    Write-Output "[INFO] Pasta não existe. Criando: $scriptPath"
    New-Item -Path $scriptPath -ItemType Directory -Force | Out-Null
}

# Download do Detection Script
if (-not (Test-Path $detectionScript)) {
    Write-Output "[INFO] Detection script não encontrado. A fazer download..."
    try {
        Invoke-WebRequest -Uri $scriptURL_Detection -OutFile $detectionScript -UseBasicParsing
        Write-Output "[OK] Detection script descarregado."
    } catch {
        Write-Output "[ERRO] Falha ao descarregar detection script: $($_.Exception.Message)"
        $global:NonCompliant = $true
    }
}

# Download do Remediation Script
if (-not (Test-Path $remediationScript)) {
    Write-Output "[INFO] Remediation script não encontrado. A fazer download..."
    try {
        Invoke-WebRequest -Uri $scriptURL_Remediation -OutFile $remediationScript -UseBasicParsing
        Write-Output "[OK] Remediation script descarregado."
    } catch {
        Write-Output "[ERRO] Falha ao descarregar remediation script: $($_.Exception.Message)"
        $global:NonCompliant = $true
    }
}

# Definições de zonas
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

# Função para obter o SID do usuário logado
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

function Get-ValueDescription($value) {
    switch ($value) {
        0 { return "Enable" }
        1 { return "Prompt" }
        3 { return "Disable" }
        default { return "Unknown" }
    }
}


if (-not (Test-Path $scriptPath)) {
    Write-Output "[MISSING] Folder missing: $scriptPath"
    $global:NonCompliant = $true
}

if (-not (Test-Path $detectionScript)) {
    Write-Output "[MISSING] Detection script missing"
    $global:NonCompliant = $true
}

if (-not (Test-Path $remediationScript)) {
    Write-Output "[MISSING] Remediation script missing"
    $global:NonCompliant = $true
}

if (-not (Get-ScheduledTask -TaskName $taskDetect -ErrorAction SilentlyContinue)) {
    Write-Output "[MISSING] Scheduled task missing: $taskDetect"
    $global:NonCompliant = $true
}

if (-not (Get-ScheduledTask -TaskName $taskRemed -ErrorAction SilentlyContinue)) {
    Write-Output "[MISSING] Scheduled task missing: $taskRemed"
    $global:NonCompliant = $true
}


# Cria HKU PSDrive se não existir
function validar-IESettings {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        Write-Output "Criando PSDrive HKU..."
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    $sid = Get-LoggedInUserSID
    Write-Output "User SID = $sid"


    $zones = @{
        "Local Intranet Zone" = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1";
        "TrustedSites Zone" = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2";
        "Internet Zone" = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3";
    }

    $global:NonCompliant = $false



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
            
            try {
                if ($currentValue -eq $expectedValue) {
                    Write-Output "[OK] $zoneName - $id = $expected"
                } else {
                    Write-Output "[NOT OK] $zoneName - $id Current=$currentValue Expected=$expectedValue"
                    $global:NonCompliant = $true
                }
            } catch {
                Write-Output "[MISSING] $zoneName - $id not present"
                $global:NonCompliant = $true
            }
        }
    }
}





function validar-BotaoIE {
    # Validação das políticas do Edge IE mode
    $edgePolicies = @{
        "InternetExplorerIntegrationLevel" = 1
        "InternetExplorerIntegrationReloadInIEModeAllowed" = 1
        "InternetExplorerModeToolbarButtonEnabled" = 1
    }
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    Write-Output "`nChecking Edge IE Mode policies..."
    foreach ($policyName in $edgePolicies.Keys) {
        try {
            $value = (Get-ItemProperty -Path $edgePolicyPath -Name $policyName -ErrorAction Stop).$policyName
            if ($value -eq $edgePolicies[$policyName]) {
                Write-Output "[OK] $policyName = $value"
            } else {
                Write-Output "[NOT OK] $policyName Current=$value Expected=$($edgePolicies[$policyName])"
                $global:NonCompliant = $true
            }
        } catch {
            Write-Output "[MISSING] $policyName not set"
            $global:NonCompliant = $true
        }
    }
}


function validar-Taskscheduler {
    # Criar a task de remediação se não existir
    $remedTaskName = "IE_Zone_Remediation"
    $remedTaskPath = "C:\ProgramData\InternetOptions\ActiveX-Script_V2_Remediation.ps1"

    if (-not (Get-ScheduledTask -TaskName $remedTaskName -ErrorAction SilentlyContinue)) {
        Write-Output "[INFO] Criando task de remediação..."
        $action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$remedTaskPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $remedTaskName -RunLevel Highest -User "SYSTEM"
    }

    # Criar a task de deteção se não existir
    $detectTaskName = "IE_Zone_Detection"
    $detectTaskPath = "C:\ProgramData\InternetOptions\ActiveX-Script_V2_Detection.ps1"

    if (-not (Get-ScheduledTask -TaskName $detectTaskName -ErrorAction SilentlyContinue)) {
        Write-Output "[INFO] Criando task de deteção..."
        $action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$detectTaskPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $detectTaskName -RunLevel Highest -User "SYSTEM"
    }

    # Se houver não conformidade, chama a task de remediação
    if ($global:NonCompliant) {
        Write-Output "[INFO] Non-Compliant detected, starting remediation task..."
        Start-ScheduledTask -TaskName $remedTaskName
    }
}

function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "[yyyy-MM-dd HH:mm:ss]"
    Write-Output "$Message"
}

try {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Log "Starting IE Zone Hardening..."

    $global:NonCompliant = $false

    Get-LoggedInUserSID
    validar-IESettings
    validar-BotaoIE
    validar-Taskscheduler
    
    if ($global:NonCompliant) {
        Write-Output "[INFO] Non-Compliant detected - triggering remediation task..."
        Write-Output "`n[INFO] Non-Compliant detected - triggering remediation task..."
        Start-ScheduledTask -TaskName "IE_Zone_Remediation"
    } else {
        Write-Output "[INFO] All settings compliant - no remediation needed."
        Write-Output "`n[INFO]All settings compliant - no remediation needed."
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "`n[$timestamp] Script execution completed successfully."

} catch {
    Write-Output "Script failed with error: $($_.Exception.Message)"
}
