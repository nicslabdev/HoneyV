<#
.SYNOPSIS
    Generate a JSON report for a sample on FlareVM.

.DESCRIPTION
    Finds the most recent binary in the specified folder, creates metadata,
    and performs a hybrid analysis producing artifacts.
#>

param(
    [Parameter(Mandatory=$false, HelpMessage="Dynamic analysis time in seconds (1-300). Default: 60s")]
    [ValidateRange(1,300)]
    [int]$DynamicTime = 60
)

#--------------------------#
#--- Fixed configuration ---#
#--------------------------#
# Expected paths and tools. Consider externalizing these variables as parameters
$MalwareDir         = "Z:\Malware"
$BaseOutDir         = "Z:\Reports"
$FlossPath          = "C:\Tools\FLOSS\floss.exe"
$DiecPath           = "C:\Tools\die\diec.exe"
$ProcmonPath        = "C:\Tools\sysinternals\Procmon.exe"
$TsharkPath         = "C:\Program Files\Wireshark\tshark.exe"
$ProcDumpPath       = "C:\Tools\sysinternals\procdump.exe"
$honeypotLogsPath   = "F:\"

# Metadata / context that will be included in the final JSON.
$Operator       = "OperatorName"
$Source         = "T-Pot"

# Internal network: pick only the first IPv4 address that starts with 10.* ---
# Purpose: record the internal network used by the VM; if no 10.* IP is found, set to "unknown".
try {
    $ipObj = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "10.*" } | Select-Object -First 1
    if ($ipObj) {
            # Build a simplified representation of the network: A.B.C.0/prefix
        $octets = $ipObj.IPAddress.Split(".")
        $Network = "$($octets[0]).$($octets[1]).$($octets[2]).0/$($ipObj.PrefixLength)"
    } else {
        $Network = "unknown"
    }
} catch {
        # If an error occurs (e.g., lack of permissions), leave as unknown.
    $Network = "unknown"
}

#----------------------------#
#--- Helper functions -------#
#----------------------------#
# Log writer with timestamp.
function Write-Log {
    param($msg, $level="INFO")
    $ts = (Get-Date).ToString("o")
    Write-Output "[$ts] [$level] $msg"
}

# Serialize the report object to JSON and save it to disk.
# Note: ConvertTo-Json -Depth 10 allows nested structures. Support for -Compress:$false
# may vary across PowerShell versions; if issues arise, use ConvertTo-Json -Depth 10.
function Save-ReportJson {
    param($obj, $outDir)
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
    $rid = $obj.report_id -replace '[^0-9a-zA-Z\-]'
    $fname = "Report_${timestamp}_${rid}.json"
    $outPath = Join-Path -Path $outDir -ChildPath $fname
    $json = $obj | ConvertTo-Json -Depth 10 -Compress:$false
    $json | Out-File -FilePath $outPath -Encoding utf8
    Write-Log ("Report saved to: {0}" -f $outPath)
    return $outPath
}

#---------------------------#
#--- Main execution -------#
#---------------------------#
Write-Log ("Start. Searching for binaries in: {0}" -f $MalwareDir)

# Verify that the samples directory exists; if not, abort with exit code 2.
if (-not (Test-Path $MalwareDir)) {
    Write-Error "Path $MalwareDir does not exist. Fix the path and try again."
    exit 2
}

# Select candidates by extension (non-recursive).
$exts = @(".exe",".dll",".sys",".scr",".com",".bin")
$candidates = Get-ChildItem -Path $MalwareDir -File -ErrorAction SilentlyContinue | Where-Object { $exts -contains $_.Extension.ToLower() }

# If there are no binaries, log and exit (code 0 => not an error, nothing to do).
if (-not $candidates -or $candidates.Count -eq 0) {
    Write-Log "No binaries with common extensions found in $MalwareDir" "WARN"
    exit 0
}

# Choose the most recently written file for analysis.
$sample = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Log ("Selected file: {0} (size: {1} bytes)" -f $sample.FullName, $sample.Length)

# --- Generate report_id and OutDir ---
# Use the file base name as the reportId and sanitize invalid characters
$reportId = $sample.BaseName
$OutDir = Join-Path -Path $BaseOutDir -ChildPath $reportId
if (-not (Test-Path $OutDir)) {
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
}

# --- Start transcript in OutDir to save everything printed to console ---
# Start-Transcript captures host stdout/stderr for auditing.
$ConsoleLogPath = Join-Path -Path $OutDir -ChildPath "ANALYSIS_CONSOLE_LOG.txt"
$__transcriptStarted = $false
try {
    # Ensure the folder that will contain the transcript exists.
    $consoleDir = Split-Path -Path $ConsoleLogPath -Parent
    if ($consoleDir -and -not (Test-Path $consoleDir)) { New-Item -Path $consoleDir -ItemType Directory -Force | Out-Null }

    # Start the transcript; this may fail if permissions or PS version are lacking.
    Start-Transcript -Path $ConsoleLogPath -Force
    $__transcriptStarted = $true
    Write-Log ("Transcript started at: {0}" -f $ConsoleLogPath)
} catch {
    # If it's not possible to start the transcript, continue but log the situation.
    Write-Log ("Could not start transcript at {0}: {1}" -f $ConsoleLogPath, $_.Exception.Message) "WARN"
}

# Get all log files from the honeypot path (e.g., Z:\)
# They are copied to OutDir and listed in the report as artifacts.
#$honeypotLogs = Get-ChildItem -Path $honeypotLogsPath -Filter "*.json" -File -ErrorAction SilentlyContinue
#$honeypotArtifacts = @()
#foreach ($log in $honeypotLogs) {
#    $honeypotArtifacts += $log.Name
#    Copy-Item -Path $log.FullName -Destination $OutDir -Force
#}

#-------------------------#
#--- Static analysis ----#
#-------------------------#
# Create an ordered structure to hold results from FLOSS, DIEC, etc.
$staticAnalysis = [ordered]@{
    virus_total = "No internet"
    strings = [ordered]@{
        total       = $null
        characters  = $null
        artifacts   = @()
    }
    packers = [ordered]@{
        heur             = $null
        operation_system = $null
        compiler         = $null
        language          = $null
        artifacts        = @()
    }
    embedded_resources = [ordered]@{
        note = "CFF Explorer must be run manually to check the following fields"
        manifest    = $null
        certificate = $null
        icon        = $null
    }
    decompilers = [ordered]@{
        note             = "Ghidra/Binary Ninja must be run manually to check the following fields"
        suspicious_functions    = $null
        heat_map                = $null
    }
}

# --- Calculate hashes (MD5, SHA1, SHA256) ---
try {
    $md5Obj = Get-FileHash -Path $sample.FullName -Algorithm MD5
    $sha1Obj = Get-FileHash -Path $sample.FullName -Algorithm SHA1
    $sha256Obj = Get-FileHash -Path $sample.FullName -Algorithm SHA256
} catch {
    # If hashes cannot be calculated, abort with code 3 (preparation failure).
    Write-Error ("Error calculating hashes: {0}" -f $_.Exception.Message)
    exit 3
}

# --- Run FLOSS (string extraction and heuristic unpacking) ---
try {
    if (-not (Test-Path $FlossPath)) {
        Write-Log ("FLOSS not found at: {0}. Skipping execution." -f $FlossPath) "WARN"
    } else {
        Write-Log ("Running FLOSS on {0}" -f $sample.FullName)

        $flossStdout = Join-Path -Path $OutDir -ChildPath "Floss.txt"
        $flossStderr = Join-Path -Path $OutDir -ChildPath "Floss_logs.txt"

        # Start-Process con redirección de stdout/stderr; timeout de 10 minutos.
        $p = Start-Process -FilePath $FlossPath -ArgumentList "`"$($sample.FullName)`"" `
             -RedirectStandardOutput $flossStdout -RedirectStandardError $flossStderr `
             -NoNewWindow -PassThru

        $flossFinished = $p.WaitForExit(600000)  # 600s = 10 min
        if (-not $flossFinished) {
            Write-Log "FLOSS timed out after 10 minutes. Killing process and keeping partial output." "WARN"
            try { $p.Kill() } catch { }
            Start-Sleep -Seconds 3  # Wait for file handles to release
        } else {
            Write-Log "FLOSS finished."
        }

        # Si los ficheros se han creado, añadir sus nombres a artifacts para el reporte.
        if (Test-Path $flossStdout) { $staticAnalysis.strings.artifacts += [System.IO.Path]::GetFileName($flossStdout) }
        if (Test-Path $flossStderr) { $staticAnalysis.strings.artifacts += [System.IO.Path]::GetFileName($flossStderr) }
    }
} catch {
    # On error running FLOSS, continue to avoid aborting the whole flow.
    Write-Log ("Error running FLOSS: {0}" -f $_.Exception.Message) "ERROR"
}

# --- Extraer info de FLOSS para strings (parseo del header) ---
try {
    $flossFile = $staticAnalysis.strings.artifacts | Where-Object { $_ -eq "Floss.txt" } | Select-Object -First 1
    if ($flossFile) {
        $flossTxt = Join-Path -Path $OutDir -ChildPath $flossFile
        if (Test-Path $flossTxt) {
            $content = Get-Content -Path $flossTxt
            # We look for a line like: "| static strings | 123 (456 characters)"
            $staticLine = $content | Where-Object { $_ -match '^\|\s+static strings\s+\|\s+(\d+)\s+\((\d+)\s+characters\)' }
            $numStrings = 0
            $numChars   = 0
            if ($staticLine) {
                $matches = [regex]::Matches($staticLine, '^\|\s+static strings\s+\|\s+(\d+)\s+\((\d+)\s+characters\)')
                if ($matches.Count -gt 0) {
                    $numStrings = [int]$matches[0].Groups[1].Value
                    $numChars   = [int]$matches[0].Groups[2].Value
                }
            }
            $staticAnalysis.strings.total      = $numStrings
            $staticAnalysis.strings.characters = $numChars
        }
    } else {
        # Si no hay salida FLOSS, dejamos a cero los contadores.
        $staticAnalysis.strings.total      = 0
        $staticAnalysis.strings.characters = 0
    }
} catch {
    # If parsing fails, log the situation but do not abort the analysis.
    Write-Log ("Error reading FLOSS header: {0}" -f $_.Exception.Message) "WARN"
    $staticAnalysis.strings.total      = 0
    $staticAnalysis.strings.characters = 0
}

# --- Run DIEC (Detect It Easy) for packer heuristics and binary metadata ---
try {
    if (-not (Test-Path $DiecPath)) {
        Write-Log ("DIEC not found at: {0}. Skipping execution." -f $DiecPath) "WARN"
    } else {
        Write-Log ("Running Detect It Easy (DIEC) on {0}" -f $sample.FullName)
        $diecOut = Join-Path -Path $OutDir -ChildPath "Diec.txt"
        # Ejecutamos diec redirigiendo la salida a un fichero para parseo posterior.
        & $DiecPath --heuristicscan --verbose $sample.FullName | Out-File -FilePath $diecOut -Encoding utf8
        Write-Log ("DIEC finished. Result saved to: {0}" -f $diecOut)
        if (Test-Path $diecOut) { $staticAnalysis.packers.artifacts += [System.IO.Path]::GetFileName($diecOut) }
        try {
            $diecContent = Get-Content -Path $diecOut -ErrorAction SilentlyContinue
            if ($diecContent -and $diecContent.Count -gt 0) {
                # Buscamos heurística de packer en líneas que contienen "(Heur)Packer:" u otras variantes.
                $packerLine = $diecContent | Where-Object { $_ -match '\(Heur\)Packer:' } | Select-Object -First 1
                if (-not $packerLine) { $packerLine = $diecContent | Where-Object { $_ -match 'Heur\)Packer:' } | Select-Object -First 1 }
                if ($packerLine) {
                    $m = [regex]::Match($packerLine, '\(Heur\)Packer:\s*(.+)$')
                    $staticAnalysis.packers.heur = if ($m.Success) { $m.Groups[1].Value.Trim() } else { $packerLine.Trim() }
                }
                # Parseamos Operation system / Compiler / Language si aparecen en la salida.
                $opLine = $diecContent | Where-Object { $_ -match '^\s*Operation system\s*:' } | Select-Object -First 1
                if ($opLine) { $staticAnalysis.packers.operation_system = ($opLine -replace '^\s*Operation system\s*:\s*', '').Trim() }
                $compLine = $diecContent | Where-Object { $_ -match '^\s*Compiler\s*:' } | Select-Object -First 1
                if ($compLine) { $staticAnalysis.packers.compiler = ($compLine -replace '^\s*Compiler\s*:\s*', '').Trim() }
                $langLine = $diecContent | Where-Object { $_ -match '^\s*Language\s*:' } | Select-Object -First 1
                if ($langLine) { $staticAnalysis.packers.language = ($langLine -replace '^\s*Language\s*:\s*', '').Trim() }
            }
        } catch { Write-Log ("Error parsing Diec.txt: {0}" -f $_.Exception.Message) "WARN" }
    }
} catch { Write-Log ("Error ejecutando DIEC: {0}" -f $_.Exception.Message) "ERROR" }

#-------------------------#
#--- Dynamic analysis ---#
#-------------------------#
# Create the structure that will hold artifacts generated during sample execution.
$dynamicAnalysis = [ordered]@{
    duration_seconds = $DynamicTime
    note = "The following artifacts must be analyzed manually"
    artifacts = [ordered]@{
        procmon              = $null
        volatility_workbench = $null
        wireshark            = $null
        fakenet              = $null    
        fakenet_logs         = $null   
        packet_capture       = $null
    }
}

# Expected paths for logs and dumps.
$procmonLog  = Join-Path -Path $OutDir -ChildPath "Procmon.pml"
$memDump     = Join-Path -Path $OutDir -ChildPath "$($sample.BaseName)_dump.dmp"
$fakenetDir  = "C:\Tools\fakenet\fakenet3.5"
$fakenetPath = Join-Path $fakenetDir "fakenet.exe"

$fakenetStdOut = Join-Path -Path $OutDir -ChildPath "FakeNet_log.txt"
$fakenetStdErr = Join-Path -Path $OutDir -ChildPath "FakeNet.txt"
$tsharkOut = Join-Path -Path $OutDir -ChildPath "FullNetworkCapture.pcap"

Write-Log "Starting monitoring tools..."

# --- Procmon: start capturing system events (PML backing file) ---
try {
    if (Test-Path $ProcmonPath) {
        $procmon = Start-Process -FilePath $ProcmonPath -ArgumentList "/accepteula /Minimized /Quiet /Backingfile `"$procmonLog`"" -PassThru
        Write-Log "Procmon started."
    }
} catch {
    Write-Log ("Error starting Procmon: {0}" -f $_.Exception.Message) "ERROR"
}

Start-Sleep -Seconds 10  # Short sleep to ensure Procmon has started.

# --- FakeNet: start and redirect stdout/stderr to files ---
try {
    if (Test-Path $fakenetPath) {
        if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
        New-Item -Path $fakenetStdOut -ItemType File -Force | Out-Null
        New-Item -Path $fakenetStdErr -ItemType File -Force | Out-Null

        Write-Log ("Starting FakeNet (stdout: {0}, stderr: {1})..." -f $fakenetStdOut, $fakenetStdErr)

        $fakenet = Start-Process -FilePath $fakenetPath `
                                 -WorkingDirectory $fakenetDir `
                                 -RedirectStandardOutput $fakenetStdOut `
                                 -RedirectStandardError $fakenetStdErr `
                                 -NoNewWindow -PassThru
        Write-Log "FakeNet started."
    } else {
        Write-Log ("FakeNet not found at: {0}" -f $fakenetPath) "WARN"
    }
} catch {
    Write-Log ("Error starting FakeNet (may need elevation): {0}" -f $_.Exception.Message) "ERROR"
}

# --- Start tshark for network capture ---
try {
    if (Test-Path $TsharkPath) {
        Write-Log ("Starting tshark for network capture (output: {0})..." -f $tsharkOut)
        $tsharkArgs = "-i", "Ethernet", "-w", "`"$tsharkOut`""
        $tshark = Start-Process -FilePath $TsharkPath -ArgumentList $tsharkArgs -NoNewWindow -PassThru
        Write-Log "tshark started."
    } else {
        Write-Log ("tshark not found at: {0}" -f $TsharkPath) "WARN"
    }
} catch {
    Write-Log ("Error starting tshark (may need elevation): {0}" -f $_.Exception.Message) "ERROR"
}

# Short sleep to ensure monitoring services have started.
Start-Sleep -Seconds 3
Write-Log "Running malware with ProcDump..."

# --- ProcDump / sample execution ---
try {
    if (Test-Path $ProcDumpPath) {
        $procDumpArgs = "-ma -x `"$OutDir`" `"$($sample.FullName)`" -accepteula"
        $procdump = Start-Process -FilePath $ProcDumpPath -ArgumentList $procDumpArgs -PassThru
        Write-Log "ProcDump started."
    } else {
        Write-Log "ProcDump not found; launching malware directly (no dump will be generated)" "WARN"
        $malwareProc = Start-Process -FilePath $sample.FullName -PassThru
    }
} catch {
    Write-Log ("Error launching sample/ProcDump: {0}" -f $_.Exception.Message) "ERROR"
}

# --- Esperar tiempo de análisis dinámico ---
Start-Sleep -Seconds $DynamicTime

# Intento de cierre del proceso de malware si sigue en ejecución.
try { if ($malwareProc -and -not $malwareProc.HasExited) { $malwareProc.Kill() } } catch { }

# --- Stop Procmon ---
if ($procmon -and -not $procmon.HasExited) {
    Write-Log "Stopping Procmon..."
    try {
        Start-Process -FilePath $ProcmonPath -ArgumentList "/accepteula","/terminate","/quiet" -Wait -NoNewWindow -ErrorAction Stop
    } catch {
        Write-Log ("Could not run procmon /terminate: {0}" -f $_.Exception.Message) "WARN"
    }
    Start-Sleep -Seconds 1
    try { if (-not $procmon.HasExited) { $procmon.Kill() } } catch { }
    if (Test-Path $procmonLog) {
        $dynamicAnalysis.artifacts.procmon = [System.IO.Path]::GetFileName($procmonLog)
        Write-Log ("Procmon saved: {0}" -f $procmonLog)
    }
}

# --- Stop FakeNet ---
if ($fakenet -and -not $fakenet.HasExited) {
    Write-Log "Stopping FakeNet..."
    try { $fakenet.Kill() } catch { }
    Start-Sleep -Seconds 1
    Get-Process -Name "fakenet" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Log "FakeNet stopped."
}

# --- Stop tshark ---
if ($tshark -and -not $tshark.HasExited) {
    Write-Log "Stopping tshark..."
    try { $tshark.Kill() } catch { }
    Start-Sleep -Seconds 1
    Get-Process -Name "tshark" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Log "tshark stopped."
}

# --- Copiar stdout/stderr de FakeNet y actualizar JSON ---
if (Test-Path $fakenetStdOut) {
    $dynamicAnalysis.artifacts.fakenet = [System.IO.Path]::GetFileName($fakenetStdOut)
    Write-Log ("FakeNet stdout saved: {0}" -f $fakenetStdOut)
}
if (Test-Path $fakenetStdErr) {
    $dynamicAnalysis.artifacts.fakenet_logs = [System.IO.Path]::GetFileName($fakenetStdErr)
    Write-Log ("FakeNet stderr saved: {0}" -f $fakenetStdErr)
}

# --- Copiar los .pcap generados por FakeNet (si los hay) ---
$pcapFiles = Get-ChildItem -Path $fakenetDir -Filter "packets*.pcap*" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
if ($pcapFiles -and $pcapFiles.Count -gt 0) {
    $pcap = $pcapFiles[0]
    $dest = Join-Path -Path $OutDir -ChildPath $pcap.Name
    Copy-Item -Path $pcap.FullName -Destination $dest -Force
    $dynamicAnalysis.artifacts.wireshark = $pcap.Name
    Write-Log ("PCAP copied: {0}" -f $dest)
} else {
    Write-Log "No PCAPs generated by FakeNet found." "WARN"
}

# tshark output
if (Test-Path $tsharkOut) {
    $dynamicAnalysis.artifacts.packet_capture = [System.IO.Path]::GetFileName($tsharkOut)
    Write-Log ("tshark PCAP saved: {0}" -f $tsharkOut)
}

# --- Esperar a que ProcDump termine y recoger dumps ---
if ($procdump -and -not $procdump.HasExited) {
    Write-Log "Waiting for ProcDump to generate dumps..."
    $procdump.WaitForExit()
}

# Buscamos dumps generados en OutDir con patrón que incluya el basename de la muestra.
$dumps = Get-ChildItem -Path $OutDir -Filter "*$($sample.BaseName)*.dmp" -File -ErrorAction SilentlyContinue
if ($dumps) {
    $dump = $dumps[0]
    $dynamicAnalysis.artifacts.volatility_workbench = $dump.Name
    Write-Log ("Dump saved: {0}" -f $dump.FullName)
} else {
    Write-Log "No .dmp files found in the output directory." "WARN"
}

#------------------------------#
#--- Reporte y finalización ---#
#------------------------------#
# --- Preparar el objeto reporte final ---
$reportObj = [ordered]@{
    report_id     = $reportId
    generated     = (Get-Date).ToUniversalTime().ToString("o")
    operator      = $Operator
    sample = [ordered]@{
        filename      = $sample.Name
        size_bytes    = $sample.Length
        hashes        = [ordered]@{
            md5    = $md5Obj.Hash
            sha1   = $sha1Obj.Hash
            sha256 = $sha256Obj.Hash
        }
        source        = $Source
        # Se prefiere CreationTimeUtc si está disponible, en caso contrario LastWriteTimeUtc.
        acquired_utc  = if ($sample.CreationTimeUtc -and $sample.CreationTimeUtc -ne [datetime]::MinValue) { $sample.CreationTimeUtc.ToString("o") } else { $sample.LastWriteTimeUtc.ToString("o") }
    }
    environment = [ordered]@{
        machine  = "Flare-VM"
        honeypot = [ordered]@{
            name      = "T-Pot"
            artifacts = $honeypotArtifacts
        }
        network  = $Network
    }
    static_analysis = $staticAnalysis
    dynamic_analysis = $dynamicAnalysis
}

# --- Stop transcript if it was started ---
if ($__transcriptStarted) {
    try {
        Stop-Transcript
        Write-Log ("Transcript finished: {0}" -f $ConsoleLogPath)
    } catch {
        Write-Log ("Error closing transcript: {0}" -f $_.Exception.Message) "WARN"
    }
}

# --- Guardar JSON inicial ---
Save-ReportJson -obj $reportObj -outDir $OutDir | Out-Null
Write-Log ("Report generated successfully. report_id: {0}" -f $reportObj.report_id)
Write-Log "End."

# Comprimir la carpeta en un archivo ZIP para transporte/almacenamiento.
$zipPath = "$OutDir.zip"
$zipRetries = 3
for ($i = 1; $i -le $zipRetries; $i++) {
    try {
        Compress-Archive -Path $OutDir\* -DestinationPath $zipPath -Force -ErrorAction Stop
        Write-Log "ZIP created: $zipPath"
        break
    } catch {
        if ($i -lt $zipRetries) {
            Write-Log ("ZIP attempt $i failed (file may be locked). Retrying in 5s...") "WARN"
            Start-Sleep -Seconds 5
        } else {
            Write-Log ("ZIP failed after $zipRetries attempts: {0}" -f $_.Exception.Message) "ERROR"
        }
    }
}