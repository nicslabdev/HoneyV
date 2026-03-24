$vmxPath      = "C:\VMs\FlareVM\FlareVM.vmx"   # Path to the .vmx file of the VM
$snapshotName = "baseline"
$shareRoot    = "C:\LabShare"
$malwareDir   = Join-Path $shareRoot "Malware"
$reportsDir   = Join-Path $shareRoot "Reports"

$vmrun        = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"

# User credentials for guest OS
$guestUser    = "FlareVM"
$guestPass    = "password"

# Initial checks
if (-not (Test-Path $vmrun)) {
    Write-Error "[INFO] vmrun not found at: $vmrun"
    exit 1
}

if (-not (Test-Path $vmxPath)) {
    Write-Error "[INFO] VMX file not found at: $vmxPath"
    exit 1
}

if (-not (Test-Path $malwareDir)) {
    Write-Error "[INFO] Malware folder does not exist: $malwareDir"
    exit 1
}

if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir | Out-Null
}

Write-Host "[INFO] Starting analysis loop (VMware)..."

while ($true) {
    $pending = Get-ChildItem -Path $malwareDir -File

    if ($pending.Count -eq 0) {
        Write-Host "[INFO] No samples left in $malwareDir. Experiment finished."
        break
    }

    Write-Host "[INFO] $($pending.Count) samples pending."

    # Check if the VM is currently running
    $runningList = & $vmrun list
    $isRunning   = $runningList -match [regex]::Escape($vmxPath)

    if ($isRunning) {
        Write-Host "[INFO] VM is running, powering off..."
        & $vmrun stop $vmxPath hard
        Start-Sleep -Seconds 5
    }

    Write-Host "[INFO] VM is powered off. Proceeding with snapshot restore."

    # 1) Restore snapshot
    Write-Host "[INFO] Restoring snapshot '$snapshotName'..."
    & $vmrun revertToSnapshot $vmxPath $snapshotName

    # 2) Start the VM (nogui = headless mode)
    Write-Host "[INFO] Starting the VM..."
    & $vmrun start $vmxPath nogui

    # 3) Wait for the guest OS to boot fully (VMware Tools must be running)
    Write-Host "[INFO] Waiting for guest OS to fully boot (VMware Tools)..."
    $bootTimeout = 300
    $bootElapsed = 0

    do {
        Start-Sleep -Seconds 5
        $bootElapsed += 5

        # Try to check if VMware Tools is responding by listing processes
        $toolsReady = $false
        try {
            $procCheck = & $vmrun listProcessesInGuest $vmxPath -gu $guestUser -gp $guestPass 2>&1
            if ($procCheck -notmatch "Error" -and $procCheck -notmatch "error") {
                $toolsReady = $true
            }
        } catch {
            $toolsReady = $false
        }
    } while (-not $toolsReady -and $bootElapsed -lt $bootTimeout)

    if (-not $toolsReady) {
        Write-Warning "[INFO] VMware Tools did not respond after $bootTimeout seconds. Skipping this iteration."
        & $vmrun stop $vmxPath hard
        Start-Sleep -Seconds 5
        continue
    }

    Write-Host "[INFO] Guest OS is fully booted."

    # 4) Record existing report folders before launching analysis
    $beforeReportNames = @(Get-ChildItem -Path $reportsDir -Directory | Select-Object -ExpandProperty Name)

    # 5) Run Analyzer.ps1 inside the VM via vmrun runProgramInGuest (non-blocking)
    #    Launched with -noWait to avoid hanging when child processes keep running.
    #    The shared folder is mapped as Z:\ inside the guest (configure in VMware VM settings)
    $psExe        = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $remoteScript = "Z:\\Analyzer.ps1"

    Write-Host "[INFO] Launching Analyzer.ps1 inside the VM..."

    & $vmrun runProgramInGuest $vmxPath -gu $guestUser -gp $guestPass -activeWindow -noWait $psExe "-ExecutionPolicy Bypass -File $remoteScript"

    Write-Host "[INFO] Analyzer launched. Waiting for report..."

    # 6) Wait for a new report folder to appear
    $timeoutSec   = 600
    $elapsed      = 0
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
    } else {
        Write-Host "[INFO] New report detected: $newReportName"
    }

    # 7) Shut down the VM
    Write-Host "[INFO] Shutting down the VM..."
    & $vmrun stop $vmxPath hard

    # Wait for the VM to fully power off
    $shutdownTimeout = 60
    $shutdownElapsed = 0

    do {
        Start-Sleep -Seconds 5
        $shutdownElapsed += 5
        $runningList = & $vmrun list
        $isRunning   = $runningList -match [regex]::Escape($vmxPath)
    } while ($isRunning -and $shutdownElapsed -lt $shutdownTimeout)

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
