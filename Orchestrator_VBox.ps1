$vmName = "FlareVM"
$snapshotName = "baseline2"
$shareRoot = "C:\LabShare"
$malwareDir = Join-Path $shareRoot "Malware"
$reportsDir = Join-Path $shareRoot "Reports"

$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# User credentials for guest OS
$guestUser = "FlareVM"
$guestPass = "password"  

# Inicial checks
if (-not (Test-Path $VBoxManage)) {
    Write-Error "[INFO] VBoxManage not found at: $VBoxManage"
    exit 1
}

if (-not (Test-Path $malwareDir)) {
    Write-Error "[INFO] Malware folder does not exist: $malwareDir"
    exit 1
}

if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir | Out-Null
}

Write-Host "[INFO] Starting analysis loop..."

while ($true) {
    $pending = Get-ChildItem -Path $malwareDir -File

    if ($pending.Count -eq 0) {
        Write-Host "[INFO] No samples left in $malwareDir. Experiment finished."
        break
    }

    Write-Host "[INFO] $($pending.Count) samples pending."

    $vmState = (& $VBoxManage showvminfo $vmName --machinereadable |
        Select-String 'VMState=').ToString().Split('=')[1].Trim('"')
    $isRunning = $vmState -ne "poweroff"

    if ($isRunning) {
        Write-Host "[INFO] VM is running, requesting ACPI shutdown..."
        & $VBoxManage controlvm $vmName poweroff
        do {
            Write-Host "[INFO] Waiting for VM to power off..."
            Start-Sleep -Seconds 5
            $vmState = (& $VBoxManage showvminfo $vmName --machinereadable |
                Select-String 'VMState=').ToString().Split('=')[1].Trim('"')
            $isRunning = $vmState -ne "poweroff"
        } while ($isRunning)
    }

    Write-Host "[INFO] VM is powered off. Proceeding with snapshot restore."

    # 1) Restore snapshot
    Write-Host "[INFO] Restoring snapshot '$snapshotName'..."
    & $VBoxManage snapshot $vmName restore $snapshotName

    # 2) Start the VM in headless mode
    Write-Host "[INFO] Starting the VM..."
    & $VBoxManage startvm $vmName --type headless

    # 3) Wait for the guest OS to boot fully (Guest Additions RunLevel = 3)
    Write-Host "[INFO] Waiting for guest OS to fully boot..."
    $bootTimeout = 60
    $bootElapsed = 0
    $guestReady  = $false

    do {
        Start-Sleep -Seconds 5
        $bootElapsed += 5

        $rlMatch = & $VBoxManage showvminfo $vmName --machinereadable |
            Select-String 'GuestAdditionsRunLevel='

        if ($rlMatch) {
            $runLevelState = $rlMatch.ToString().Split('=')[1].Trim('"')
            if ($runLevelState -eq "3") {
                $guestReady = $true
            }
        }
    } while (-not $guestReady -and $bootElapsed -lt $bootTimeout)

    if (-not $guestReady) {
        Write-Warning "[INFO] Guest Additions did not reach RunLevel 3 after $bootTimeout seconds. Continuing anyway..."
    }

    Write-Host "[INFO] Guest OS is fully booted."
    
    # 4) Record existing report folders before launching analysis
    $beforeReportNames = @(Get-ChildItem -Path $reportsDir -Directory | Select-Object -ExpandProperty Name)

    # 5) Run Analyzer.ps1 inside the VM via guestcontrol (non-blocking)
    #    Launched without --wait-stdout to avoid hanging when child processes
    #    keep the stdout handle open after the Analyzer finishes.
    $psExe = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $remoteScript = "Z:\\Analyzer.ps1"

    Write-Host "[INFO] Launching Analyzer.ps1 inside the VM..."

    & $VBoxManage guestcontrol $vmName run --username $guestUser --password $guestPass --exe $psExe -- powershell.exe "-ExecutionPolicy Bypass -File $remoteScript"

    Write-Host "[INFO] Analyzer launched. Waiting for report..."

    # 6) Wait for a new report folder to appear
    $timeoutSec = 600   
    $elapsed = 0
    $pollInterval = 10
    $newReportName = $null

    do {
        Start-Sleep -Seconds $pollInterval
        $elapsed += $pollInterval
        $currentReportNames = @(Get-ChildItem -Path $reportsDir -Directory | Select-Object -ExpandProperty Name)
        $newFolders = $currentReportNames | Where-Object { $_ -notin $beforeReportNames }
        if ($newFolders) {
            $newReportName = $newFolders | Select-Object -First 1
        }
    } while (-not $newReportName -and $elapsed -lt $timeoutSec)

    if (-not $newReportName) {
        Write-Warning "[INFO] No new report detected after $timeoutSec seconds."
    }
    else {
        Write-Host "[INFO] New report detected: $newReportName"
    }

    # 7) Shut down the VM cleanly
    Write-Host "[INFO] Requesting ACPI shutdown..."
    & $VBoxManage controlvm $vmName poweroff

    do {
        Write-Host "[INFO] Waiting for VM to power off..."
        Start-Sleep -Seconds 5
        $vmState = (& $VBoxManage showvminfo $vmName --machinereadable |
            Select-String 'VMState=').ToString().Split('=')[1].Trim('"')
        $isRunning = $vmState -ne "poweroff"
    } while ($isRunning)

    Write-Host "[INFO] VM is powered off. Preparing next sample..."

    # 8) Delete the sample that was actually analyzed
    #    The Analyzer names the report folder after the sample's BaseName,
    #    so we match it back to the file in Malware.
    if ($newReportName) {
        $analyzedSample = $pending | Where-Object { $_.BaseName -eq $newReportName } | Select-Object -First 1
        if ($analyzedSample) {
            Write-Host "[INFO] Deleting analyzed sample: $($analyzedSample.FullName)"
            Remove-Item -Path $analyzedSample.FullName -Force
        }
        else {
            Write-Warning "[INFO] Could not find sample matching report '$newReportName'. Skipping deletion."
        }
    }
    else {
        Write-Warning "[INFO] No report was generated. Skipping sample deletion."
    }
}

Write-Host "[INFO] All binaries processed. Reports are in: $reportsDir"
