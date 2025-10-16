#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$BackupRoot = '',
    [string[]]$SelectContainers = @(),
    [ValidateSet('load','skip')]
    [string]$Images = 'load',
    [ValidateSet('recreate','skip')]
    [string]$Networks = 'recreate',
    [ValidateSet('keep','auto-remap','fail')]
    [string]$PortStrategy = 'keep',
    [string]$NameSuffix = '',
    [string]$BindRoot = '',
    [ValidateSet('no','always','unless-stopped','on-failure')]
    [string]$RestartPolicy = '',
    [switch]$Decrypt,
    [string]$Passphrase = '',
    [switch]$DryRun,
    [switch]$Force,
    [string]$LogLevel = 'debug',
    [string]$LogFile = '',
    [switch]$NonInteractive,
    [switch]$Help
)

# Handle execution policy with UAC elevation if needed
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    # Check if already running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "PowerShell execution policy is restricted. Requesting administrator privileges..." -ForegroundColor Yellow
        $scriptPath = $MyInvocation.MyCommand.Path
        $arguments = $args -join ' '
        try {
            Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`" $arguments" -Verb RunAs -Wait
            exit
        } catch {
            Write-Host "ERROR: Unable to elevate privileges. Please run as administrator or change execution policy." -ForegroundColor Red
            Write-Host "Alternative: Run from elevated PowerShell with: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
            Read-Host "Press Enter to exit"
            exit 1
        }
    } else {
        # Already admin but still restricted - set policy temporarily
        Write-Host "Setting execution policy temporarily..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
    }
}

<#
.SYNOPSIS
    Restore Docker containers and their data from backup

.DESCRIPTION
    Restores a complete Docker environment from backup including:
    - Container images (docker load)
    - Named volumes with full contents
    - Bind-mounted host directories
    - Docker networks
    - Container recreation with original configurations

.PARAMETER BackupRoot
    Path to backup directory (auto-detect latest if omitted)

.PARAMETER SelectContainers
    Comma-separated list of container names to restore (default: all)

.PARAMETER Images
    Image handling: load,skip (default: load)

.PARAMETER Networks
    Network handling: recreate,skip (default: recreate)

.PARAMETER PortStrategy
    Port conflict resolution: keep,auto-remap,fail (default: keep)

.PARAMETER NameSuffix
    Suffix to append to container and network names to avoid collisions

.PARAMETER BindRoot
    Base path for restored bind mounts if originals unavailable

.PARAMETER RestartPolicy
    Override restart policy: no,always,unless-stopped,on-failure

.PARAMETER Decrypt
    Enable decryption for encrypted backups

.PARAMETER Passphrase
    Decryption passphrase (required if decrypt is enabled)

.PARAMETER DryRun
    Show what would be restored without performing actual restore

.PARAMETER Force
    Skip confirmation prompts

.PARAMETER LogLevel
    Logging verbosity: info,warn,debug (default: info)

.PARAMETER LogFile
    Custom log file path

.PARAMETER NonInteractive
    Run without user prompts (for automation/CI/CD)

.PARAMETER Help
    Show detailed help and examples

.EXAMPLE
    .\restore.ps1
    Restore latest backup from script directory

.EXAMPLE
    .\restore.ps1 --backup-root E:\docker-backup\20241008-1030 --name-suffix -restored
    Restore specific backup with name suffix

.EXAMPLE
    .\restore.ps1 --select-containers web,db --port-strategy auto-remap
    Restore only specific containers with port remapping

.EXAMPLE
    .\restore.ps1 --bind-root C:\RestoredData --dry-run
    Preview restore with custom bind mount location

.EXAMPLE
    .\restore.ps1 --non-interactive
    Restore without prompts (for automation)
#>

# Emergency logging setup (before any other operations)
$script:EmergencyLogFile = Join-Path (Split-Path -Parent $PSCommandPath) "restore-emergency-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
try { "=== Docker Restore Script Started ===" | Add-Content -Path $script:EmergencyLogFile } catch { }
try { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Script started with PowerShell version: $($PSVersionTable.PSVersion)" | Add-Content -Path $script:EmergencyLogFile } catch { }
try { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Script path: $PSCommandPath" | Add-Content -Path $script:EmergencyLogFile } catch { }
try { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Working directory: $(Get-Location)" | Add-Content -Path $script:EmergencyLogFile } catch { }

# Global variables
$script:LogLevel = $LogLevel
$script:LogFile = $LogFile
$script:StartTime = Get-Date
$script:Manifest = $null
$script:PortMappings = @{}
$script:NetworkMappings = @{}
$script:RestoredContainers = @()

function Show-Help {
    Get-Help $PSCommandPath -Detailed
    Write-Host "`nCommon Usage Examples:" -ForegroundColor Green
    Write-Host "  .\restore.ps1                                           # Restore latest backup"
    Write-Host "  .\restore.ps1 --backup-root E:\backup\20241008-1030     # Restore specific backup"
    Write-Host "  .\restore.ps1 --select-containers web,db                # Restore specific containers"
    Write-Host "  .\restore.ps1 --name-suffix -test --port-strategy auto-remap  # Test restore with remapping"
    Write-Host "  .\restore.ps1 --bind-root C:\NewLocation --dry-run      # Preview with custom bind location"
    Write-Host "  .\restore.ps1 --non-interactive                         # Restore without prompts (automation)"
    exit 0
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('info','warn','error','debug')]
        [string]$Level = 'info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$($Level.ToUpper())] $Message"
    
    # Console output with colors
    switch ($Level) {
        'error' { Write-Host $logMessage -ForegroundColor Red }
        'warn'  { Write-Host $logMessage -ForegroundColor Yellow }
        'debug' { if ($script:LogLevel -eq 'debug') { Write-Host $logMessage -ForegroundColor Gray } }
        default { Write-Host $logMessage -ForegroundColor White }
    }
    
    # File output
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $logMessage -Encoding UTF8
    }
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level info
    
    # Check Docker availability
    try {
        $dockerVersion = docker --version 2>$null
        if (-not $dockerVersion) {
            throw "Docker not found in PATH"
        }
        Write-Log "Docker found: $dockerVersion" -Level debug
    }
    catch {
        Write-Log "Docker is not available. Please ensure Docker Desktop is installed and running." -Level error
        return $false
    }
    
    # Check Docker daemon
    try {
        docker info 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Docker daemon not responding"
        }
        Write-Log "Docker daemon is running" -Level debug
    }
    catch {
        Write-Log "Docker daemon is not running. Please start Docker Desktop." -Level error
        return $false
    }
    
    return $true
}

function Find-LatestBackup {
    $scriptDir = Split-Path -Parent $PSCommandPath
    $backupDir = Join-Path $scriptDir "docker-backup"
    
    if (-not (Test-Path $backupDir)) {
        Write-Log "No backup directory found at: $backupDir" -Level error
        return $null
    }
    
    $backups = Get-ChildItem -Path $backupDir -Directory | 
               Where-Object { $_.Name -match '^\d{8}-\d{6}$' } |
               Sort-Object Name -Descending
    
    if ($backups.Count -eq 0) {
        Write-Log "No backup directories found in: $backupDir" -Level error
        return $null
    }
    
    $latest = $backups[0].FullName
    Write-Log "Found latest backup: $latest" -Level info
    return $latest
}

function Load-Manifest {
    param([string]$BackupPath)
    
    $manifestFile = Join-Path $BackupPath "manifest.json"
    
    if (-not (Test-Path $manifestFile)) {
        Write-Log "Manifest file not found: $manifestFile" -Level error
        return $false
    }
    
    try {
        $manifestContent = Get-Content -Path $manifestFile -Raw -Encoding UTF8
        $script:Manifest = ConvertFrom-Json $manifestContent
        
        Write-Log "Loaded manifest: version $($script:Manifest.version), created $($script:Manifest.created)" -Level info
        Write-Log "Backup contains: $($script:Manifest.containers.Count) containers, $($script:Manifest.images.Count) images, $($script:Manifest.volumes.Count) volumes" -Level info
        
        return $true
    }
    catch {
        Write-Log "Failed to load manifest: $_" -Level error
        return $false
    }
}

function Verify-BackupIntegrity {
    param([string]$BackupPath)
    
    Write-Log "Verifying backup integrity..." -Level info
    
    # Debug: List all files in backup directory
    Write-Log "DEBUG: Listing all files in backup directory:" -Level debug
    try {
        $allFiles = Get-ChildItem -Path $BackupPath -Recurse -File
        foreach ($file in $allFiles) {
            $relativePath = $file.FullName.Substring($BackupPath.Length + 1)
            Write-Log "  Found file: $relativePath" -Level debug
        }
    } catch {
        Write-Log "Failed to list backup files: $_" -Level debug
    }
    
    $errors = 0
    
    # Check for split archives and reassemble if needed
    if ($script:Manifest.metadata.split_archives.Count -gt 0) {
        Write-Log "Found split archives, reassembling..." -Level info
        if (-not (Reassemble-SplitFiles $BackupPath)) {
            $errors++
        }
    }
    
    # Debug: Show what manifest expects
    Write-Log "DEBUG: Manifest expects these files:" -Level debug
    foreach ($file in $script:Manifest.checksums.PSObject.Properties) {
        Write-Log "  Expected: $($file.Name)" -Level debug
    }
    
    # Verify checksums
    foreach ($file in $script:Manifest.checksums.PSObject.Properties) {
        $filePath = Join-Path $BackupPath $file.Name
        $expectedHash = $file.Value
        
        if (Test-Path $filePath) {
            try {
                $actualHash = Get-FileHash -Path $filePath -Algorithm SHA256
                if ($actualHash.Hash -ne $expectedHash) {
                    Write-Log "Checksum mismatch for $($file.Name): expected $expectedHash, got $($actualHash.Hash)" -Level error
                    $errors++
                }
                else {
                    Write-Log "Checksum verified: $($file.Name)" -Level debug
                }
            }
            catch {
                Write-Log ("Failed to verify checksum for " + $file.Name + ": " + $_) -Level error
                $errors++
            }
        }
        else {
            Write-Log "Missing file: $($file.Name)" -Level error
            Write-Log "Expected path: $filePath" -Level debug
            # List similar files to help debug filename issues
            $parentDir = Split-Path $filePath -Parent
            if (Test-Path $parentDir) {
                $fileName = Split-Path $filePath -Leaf
                $fileBase = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
                $similarFiles = Get-ChildItem -Path $parentDir -File | Where-Object { $_.Name -like "*$fileBase*" }
                if ($similarFiles) {
                    Write-Log "Similar files found: $($similarFiles.Name -join ', ')" -Level debug
                }
            }
            $errors++
        }
    }
    
    if ($errors -eq 0) {
        Write-Log "Backup integrity verified successfully" -Level info
        return $true
    }
    else {
        Write-Log "Backup integrity check failed with $errors errors" -Level error
        return $false
    }
}

function Reassemble-SplitFiles {
    param([string]$BackupPath)
    
    $splitGroups = $script:Manifest.metadata.split_archives | Group-Object original_file
    
    foreach ($group in $splitGroups) {
        $originalFile = $group.Name
        $chunks = $group.Group | Sort-Object chunk_index
        
        Write-Log "Reassembling $originalFile from $($chunks.Count) chunks" -Level info
        
        # Find the directory containing the chunks
        $firstChunk = $chunks[0].chunk_file
        $chunkPath = Get-ChildItem -Path $BackupPath -Recurse -Filter $firstChunk | Select-Object -First 1
        
        if (-not $chunkPath) {
            Write-Log "Could not find chunk file: $firstChunk" -Level error
            return $false
        }
        
        $outputPath = Join-Path $chunkPath.Directory.FullName $originalFile
        
        if (-not $DryRun) {
            try {
                $writer = [System.IO.File]::Create($outputPath)
                
                foreach ($chunk in $chunks) {
                    $chunkFile = Join-Path $chunkPath.Directory.FullName $chunk.chunk_file
                    if (Test-Path $chunkFile) {
                        $chunkData = [System.IO.File]::ReadAllBytes($chunkFile)
                        $writer.Write($chunkData, 0, $chunkData.Length)
                        Write-Log "Merged chunk: $($chunk.chunk_file)" -Level debug
                    }
                    else {
                        throw "Missing chunk file: $chunkFile"
                    }
                }
                
                $writer.Close()
                
                # Clean up chunk files
                foreach ($chunk in $chunks) {
                    $chunkFile = Join-Path $chunkPath.Directory.FullName $chunk.chunk_file
                    Remove-Item $chunkFile -Force
                }
                
                Write-Log "Successfully reassembled: $originalFile" -Level info
            }
            catch {
                Write-Log ("Failed to reassemble " + $originalFile + ": " + $_) -Level error
                if ($writer) { $writer.Close() }
                return $false
            }
        }
        else {
            Write-Log "[DRY RUN] Would reassemble $originalFile from $($chunks.Count) chunks" -Level info
        }
    }
    
    return $true
}

function Restore-Snapshots {
    param([string]$BackupPath, [object]$Manifest)

    if (-not $Manifest.snapshots -or $Manifest.snapshots.Count -eq 0) {
        Write-Log "No snapshots to restore" -Level debug
        return $true
    }

    Write-Log "Restoring container snapshots..." -Level info

    $snapshotsDir = Join-Path $BackupPath "snapshots"
    if (-not (Test-Path $snapshotsDir)) {
        Write-Log "Snapshots directory not found: $snapshotsDir" -Level warn
        return $true
    }

    $success = $true

    foreach ($snapshot in $Manifest.snapshots) {
        $snapshotFile = Join-Path $snapshotsDir (Split-Path -Leaf $snapshot.file)
        
        if (-not (Test-Path $snapshotFile)) {
            Write-Log "Snapshot file not found: $snapshotFile" -Level error
            $success = $false
            continue
        }

        Write-Log "Loading snapshot: $($snapshot.container)" -Level info

        if (-not $DryRun) {
            try {
                $process = Start-Process -FilePath 'docker' -ArgumentList @('load', '-i', $snapshotFile) -Wait -PassThru -NoNewWindow
                if ($process.ExitCode -ne 0) {
                    throw "Docker load failed with exit code $($process.ExitCode)"
                }
                Write-Log "Loaded snapshot for container: $($snapshot.container)" -Level debug
            }
            catch {
                Write-Log "Failed to load snapshot $($snapshot.container): $_" -Level error
                $success = $false
            }
        }
        else {
            Write-Log "[DRY RUN] Would load snapshot: $snapshotFile" -Level info
        }
    }

    return $success
}

function Restore-Images {
    param([string]$BackupPath)
    
    if ($Images -eq 'skip') {
        Write-Log "Skipping image restoration" -Level info
        return $true
    }
    
    Write-Log "Restoring Docker images..." -Level info
    
    $imagesDir = Join-Path $BackupPath "images"
    if (-not (Test-Path $imagesDir)) {
        Write-Log "No images directory found, skipping image restoration" -Level warn
        return $true
    }
    
    $imageFiles = Get-ChildItem -Path $imagesDir -Filter "*.tar"
    $success = $true
    
    foreach ($imageFile in $imageFiles) {
        Write-Log "Loading image: $($imageFile.Name)" -Level info
        
        if (-not $DryRun) {
            try {
                $process = Start-Process -FilePath 'docker' -ArgumentList @('load', '-i', $imageFile.FullName) -Wait -PassThru -NoNewWindow
                if ($process.ExitCode -ne 0) {
                    throw "Docker load failed with exit code $($process.ExitCode)"
                }
                Write-Log "Loaded image: $($imageFile.Name)" -Level debug
            }
            catch {
                Write-Log ("Failed to load image " + $imageFile.Name + ": " + $_) -Level error
                $success = $false
            }
        }
        else {
            Write-Log "[DRY RUN] Would load image: $($imageFile.FullName)" -Level info
        }
    }
    
    return $success
}

function Restore-Networks {
    param([string]$BackupPath)
    
    if ($Networks -eq 'skip') {
        Write-Log "Skipping network restoration" -Level info
        return $true
    }
    
    Write-Log "Restoring Docker networks..." -Level info
    
    $networksFile = Join-Path $BackupPath "networks.json"
    if (-not (Test-Path $networksFile)) {
        Write-Log "No networks file found, skipping network restoration" -Level warn
        return $true
    }
    
    try {
        $networks = Get-Content -Path $networksFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $success = $true
        
        foreach ($network in $networks) {
            $networkName = $network.Name + $NameSuffix
            
            # Check if network already exists
            $existingNetwork = docker network ls --filter "name=$networkName" --format "{{.Name}}" 2>$null
            if ($existingNetwork -eq $networkName) {
                Write-Log "Network already exists: $networkName" -Level warn
                $script:NetworkMappings[$network.Name] = $networkName
                continue
            }
            
            Write-Log "Creating network: $networkName" -Level info
            
            if (-not $DryRun) {
                try {
                    $createArgs = @('network', 'create')
                    
                    if ($network.Driver) {
                        $createArgs += @('--driver', $network.Driver)
                    }
                    
                    if ($network.IPAM -and $network.IPAM.Config) {
                        foreach ($config in $network.IPAM.Config) {
                            if ($config.Subnet) {
                                $createArgs += @('--subnet', $config.Subnet)
                            }
                            if ($config.Gateway) {
                                $createArgs += @('--gateway', $config.Gateway)
                            }
                        }
                    }
                    
                    $createArgs += $networkName
                    
                    $process = Start-Process -FilePath 'docker' -ArgumentList $createArgs -Wait -PassThru -NoNewWindow
                    if ($process.ExitCode -ne 0) {
                        throw "Network creation failed with exit code $($process.ExitCode)"
                    }
                    
                    $script:NetworkMappings[$network.Name] = $networkName
                    Write-Log "Created network: $networkName" -Level debug
                }
                catch {
                    Write-Log ("Failed to create network " + $networkName + ": " + $_) -Level error
                    $success = $false
                }
            }
            else {
                Write-Log "[DRY RUN] Would create network: $networkName" -Level info
                $script:NetworkMappings[$network.Name] = $networkName
            }
        }
        
        return $success
    }
    catch {
        Write-Log "Failed to restore networks: $_" -Level error
        return $false
    }
}

function Restore-Volumes {
    param(
        [string]$BackupPath,
        [hashtable]$VolumeOwnerInfo = @{}
    )
    
    Write-Log "Restoring Docker volumes..." -Level info
    
    $volumesDir = Join-Path $BackupPath "volumes"
    if (-not (Test-Path $volumesDir)) {
        Write-Log "No volumes directory found, skipping volume restoration" -Level warn
        return $true
    }
    
    # Look for both .zip and .tar.gz volume files
    $volumeFiles = @()
    $volumeFiles += Get-ChildItem -Path $volumesDir -Filter "*.zip" -ErrorAction SilentlyContinue
    $volumeFiles += Get-ChildItem -Path $volumesDir -Filter "*.tar.gz" -ErrorAction SilentlyContinue
    $success = $true
    
    foreach ($volumeFile in $volumeFiles) {
        # Handle both .zip and .tar.gz extensions
        $volumeName = if ($volumeFile.Name.EndsWith('.tar.gz')) {
            $volumeFile.Name.Substring(0, $volumeFile.Name.Length - 7) + $NameSuffix
        } else {
            [System.IO.Path]::GetFileNameWithoutExtension($volumeFile.Name) + $NameSuffix
        }
        
        Write-Log "Restoring volume: $volumeName" -Level info
        
        if (-not $DryRun) {
            try {
                # Create volume if it doesn't exist
                $existingVolume = docker volume ls --filter "name=$volumeName" --format "{{.Name}}" 2>$null
                if ($existingVolume -ne $volumeName) {
                    docker volume create $volumeName 2>$null | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to create volume $volumeName"
                    }
                }
                
                # Get archive size for logging
                $archiveSize = [math]::Round($volumeFile.Length / 1MB, 2)
                Write-Log "Archive file: $($volumeFile.FullName) (${archiveSize}MB)" -Level debug
                
                if ($volumeFile.Extension -eq '.gz') {
                    # Handle .tar.gz files: copy archive into volume, then extract it
                    # This avoids Windows path mounting issues by using docker cp
                    Write-Log "Restoring tar.gz archive using docker cp into volume..." -Level debug
                    
                    $tempContainer = "restore-helper-$(Get-Random)"
                    
                    try {
                        # Create and run a temporary container with the volume mounted
                        Write-Log "Creating temporary container with volume mounted..." -Level debug
                        $runArgs = @('run', '--name', $tempContainer, '-v', "${volumeName}:/volume", 'busybox', 'true')
                        $runProcess = Start-Process -FilePath 'docker' -ArgumentList $runArgs -Wait -PassThru -NoNewWindow
                        
                        if ($runProcess.ExitCode -ne 0) {
                            throw "Failed to create temporary container"
                        }
                        
                        # Copy archive from Windows directly into the mounted volume (not /tmp)
                        # This way the file is accessible when we mount the same volume in another container
                        Write-Log "Copying archive from Windows into volume..." -Level debug
                        $copyArgs = @('cp', $volumeFile.FullName, "${tempContainer}:/volume/restore.tar.gz")
                        Write-Log "Docker cp command: docker $($copyArgs -join ' ')" -Level debug
                        $copyProcess = Start-Process -FilePath 'docker' -ArgumentList $copyArgs -Wait -PassThru -NoNewWindow -RedirectStandardError "$env:TEMP\docker_cp_err.log"
                        
                        if ($copyProcess.ExitCode -ne 0) {
                            $copyError = Get-Content "$env:TEMP\docker_cp_err.log" -Raw -ErrorAction SilentlyContinue
                            throw "Failed to copy archive to volume: $copyError"
                        }
                        
                        Write-Log "Archive copied successfully, verifying..." -Level debug
                        
                        # Extract archive by mounting the same volume
                        Write-Log "Extracting archive inside volume..." -Level debug
                        $extractArgs = @('run', '--rm', '-v', "${volumeName}:/volume", 'busybox', 'sh', '-c', 'cd /volume && tar -xzf restore.tar.gz && rm restore.tar.gz')
                        Write-Log "Docker extract command: docker $($extractArgs -join ' ')" -Level debug
                        $extractProcess = Start-Process -FilePath 'docker' -ArgumentList $extractArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\tar_extract.log" -RedirectStandardError "$env:TEMP\tar_extract_err.log"
                        
                        if ($extractProcess.ExitCode -ne 0) {
                            $extractError = Get-Content "$env:TEMP\tar_extract_err.log" -Raw -ErrorAction SilentlyContinue
                            $extractOutput = Get-Content "$env:TEMP\tar_extract.log" -Raw -ErrorAction SilentlyContinue
                            Write-Log "Archive extraction failed. Error: $extractError" -Level error
                            Write-Log "Archive extraction output: $extractOutput" -Level debug
                            throw "Failed to extract tar.gz archive: $extractError"
                        }
                        
                        $extractOutput = Get-Content "$env:TEMP\tar_extract.log" -Raw -ErrorAction SilentlyContinue
                        if ($extractOutput) {
                            Write-Log "Extraction output: $extractOutput" -Level debug
                        }
                        
                        # Fix ownership if we know which container uses this volume
                        if ($VolumeOwnerInfo.ContainsKey($volumeName)) {
                            $ownerData = $VolumeOwnerInfo[$volumeName]
                            $user = $ownerData.user
                            $image = $ownerData.image
                            
                            Write-Log "Setting ownership for volume $volumeName to '$user' using image $image" -Level debug
                            
                            # Try using the actual container image for chown - it knows about the user
                            $chownArgs = @('run', '--rm', '-v', "${volumeName}:/volume", $image, 'chown', '-R', $user, '/volume')
                            $chownProcess = Start-Process -FilePath 'docker' -ArgumentList $chownArgs -Wait -PassThru -NoNewWindow -RedirectStandardError "$env:TEMP\chown_err.log"
                            
                            if ($chownProcess.ExitCode -ne 0) {
                                $chownError = Get-Content "$env:TEMP\chown_err.log" -Raw -ErrorAction SilentlyContinue
                                Write-Log "Failed to set ownership using image's chown: $chownError" -Level debug
                                
                                # Fallback: resolve username to numeric UID:GID and use busybox
                                Write-Log "Attempting fallback: resolving '$user' to numeric UID:GID" -Level debug
                                
                                $numericUser = $null
                                if ($user -match '^\d+:\d+$') {
                                    # Already numeric
                                    $numericUser = $user
                                } else {
                                    # Try to resolve using the container image
                                    try {
                                        $idOutput = docker run --rm $image sh -c "id -u $user 2>/dev/null && id -g $user 2>/dev/null" 2>&1
                                        if ($LASTEXITCODE -eq 0 -and $idOutput) {
                                            $lines = $idOutput -split "`n" | Where-Object { $_ -match '^\d+$' }
                                            if ($lines.Count -ge 2) {
                                                $numericUser = "$($lines[0].Trim()):$($lines[1].Trim())"
                                                Write-Log "Resolved '$user' to $numericUser" -Level debug
                                            }
                                        }
                                    } catch {
                                        Write-Log "Could not resolve user '$user' to numeric ID: $_" -Level debug
                                    }
                                }
                                
                                if ($numericUser) {
                                    # Use busybox with numeric IDs
                                    Write-Log "Setting ownership using busybox with numeric ID: $numericUser" -Level debug
                                    $busyboxArgs = @('run', '--rm', '-v', "${volumeName}:/volume", 'busybox', 'chown', '-R', $numericUser, '/volume')
                                    $busyboxProcess = Start-Process -FilePath 'docker' -ArgumentList $busyboxArgs -Wait -PassThru -NoNewWindow -RedirectStandardError "$env:TEMP\chown_err2.log"
                                    
                                    if ($busyboxProcess.ExitCode -eq 0) {
                                        Write-Log "Ownership set successfully using busybox" -Level debug
                                    } else {
                                        $busyboxError = Get-Content "$env:TEMP\chown_err2.log" -Raw -ErrorAction SilentlyContinue
                                        Write-Log "Warning: Failed to set ownership using busybox: $busyboxError" -Level warn
                                    }
                                } else {
                                    Write-Log "Warning: Could not resolve user '$user' to numeric ID, skipping ownership fix" -Level warn
                                }
                            } else {
                                Write-Log "Ownership set successfully" -Level debug
                            }
                        }
                        
                        Write-Log "Archive extracted successfully to volume: $volumeName" -Level debug
                    }
                    finally {
                        # Clean up temporary container
                        Write-Log "Cleaning up temporary container..." -Level debug
                        docker rm $tempContainer 2>&1 | Out-Null
                    }
                    
                } else {
                    # Handle .zip files - extract to temp directory first, then copy to volume
                    Write-Log "Extracting zip archive to volume..." -Level debug
                    
                    $tempDir = Join-Path $env:TEMP "docker-restore-$(Get-Random)"
                    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
                    
                    try {
                        # Extract zip file
                        Expand-Archive -Path $volumeFile.FullName -DestinationPath $tempDir -Force
                        
                        # Copy contents to volume using container
                        $copyArgs = @(
                            'run', '--rm',
                            '-v', "${volumeName}:/volume",
                            '-v', "${tempDir}:/source:ro",
                            'busybox', 'sh', '-c', 'cp -r /source/* /volume/ 2>/dev/null || cp -r /source/. /volume/'
                        )
                        
                        $process = Start-Process -FilePath 'docker' -ArgumentList $copyArgs -Wait -PassThru -NoNewWindow
                        if ($process.ExitCode -ne 0) {
                            throw "Failed to copy extracted files to volume"
                        }
                        
                        Write-Log "Archive extracted successfully to volume: $volumeName" -Level debug
                    }
                    finally {
                        # Clean up temp directory
                        if (Test-Path $tempDir) {
                            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                
                Write-Log "Successfully restored volume: $volumeName" -Level info
            }
            catch {
                Write-Log ("Failed to restore volume " + $volumeName + ": " + $_) -Level error
                $success = $false
            }
        }
        else {
            Write-Log "[DRY RUN] Would restore volume: $volumeName from $($volumeFile.FullName)" -Level info
        }
    }
    
    return $success
}

function Restore-BindMounts {
    param([string]$BackupPath)
    
    Write-Log "Restoring bind mounts..." -Level info
    
    $bindsDir = Join-Path $BackupPath "binds"
    if (-not (Test-Path $bindsDir)) {
        Write-Log "No binds directory found, skipping bind mount restoration" -Level warn
        return $true
    }
    
    $bindFiles = Get-ChildItem -Path $bindsDir -Filter "*.zip"
    $success = $true
    
    foreach ($bindFile in $bindFiles) {
        # Find corresponding bind mount info from manifest
        $archiveName = $bindFile.Name
        $bindInfo = $script:Manifest.binds | Where-Object { $_.archive_name -eq $archiveName }
        
        if (-not $bindInfo) {
            Write-Log "No bind mount info found for archive: $archiveName" -Level warn
            continue
        }
        
        # Determine restore path
        $restorePath = $bindInfo.source_path
        if ($BindRoot) {
            $relativePath = $bindInfo.source_path -replace '^[A-Z]:', '' -replace '^\\', ''
            $restorePath = Join-Path $BindRoot $relativePath
        }
        
        Write-Log "Restoring bind mount to: $restorePath" -Level info
        
        if (-not $DryRun) {
            try {
                # Create parent directory if it doesn't exist
                $parentDir = Split-Path -Parent $restorePath
                if (-not (Test-Path $parentDir)) {
                    New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
                }
                
                # Extract archive
                Expand-Archive -Path $bindFile.FullName -DestinationPath $restorePath -Force
                
                Write-Log "Restored bind mount: $restorePath" -Level debug
            }
            catch {
                Write-Log ("Failed to restore bind mount to " + $restorePath + ": " + $_) -Level error
                $success = $false
            }
        }
        else {
            Write-Log "[DRY RUN] Would restore bind mount to: $restorePath" -Level info
        }
    }
    
    return $success
}

function Get-AvailablePort {
    param([int]$PreferredPort)
    
    # Check if preferred port is in use
    $connection = Get-NetTCPConnection -LocalPort $PreferredPort -ErrorAction SilentlyContinue
    $portInUse = $null -ne $connection
    
    if ($PortStrategy -eq 'keep') {
        if ($portInUse) {
            Write-Log "Port $PreferredPort is already in use" -Level warn
            
            # In non-interactive mode, fail immediately
            if ($NonInteractive) {
                throw "Port $PreferredPort is already in use. Use -PortStrategy auto-remap to automatically find available ports, or -PortStrategy fail to abort on conflicts."
            }
            
            # Interactive: prompt user for what to do
            Write-Host ""
            Write-Host "Port Conflict Detected" -ForegroundColor Yellow
            Write-Host "Port $PreferredPort is already in use." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Options:" -ForegroundColor Cyan
            Write-Host "  [A] Auto-remap to next available port (recommended)" -ForegroundColor White
            Write-Host "  [C] Choose a different port manually" -ForegroundColor White
            Write-Host "  [Q] Quit restore process" -ForegroundColor White
            Write-Host ""
            
            do {
                $choice = Read-Host "Your choice [A/C/Q]"
                $choice = $choice.Trim().ToUpper()
                
                if ($choice -eq 'Q') {
                    throw "Restore cancelled by user due to port conflict"
                }
                elseif ($choice -eq 'A') {
                    # Find next available port
                    for ($port = $PreferredPort + 1; $port -le 65535; $port++) {
                        $testConnection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
                        if (-not $testConnection) {
                            Write-Log "Auto-remapped port $PreferredPort to $port" -Level info
                            Write-Host "Using port $port instead of $PreferredPort" -ForegroundColor Green
                            return $port
                        }
                    }
                    throw "No available ports found starting from $PreferredPort"
                }
                elseif ($choice -eq 'C') {
                    # Let user choose custom port
                    do {
                        $customPortStr = Read-Host "Enter port number (1-65535)"
                        if ($customPortStr -match '^\d+$') {
                            $customPort = [int]$customPortStr
                            if ($customPort -ge 1 -and $customPort -le 65535) {
                                $testConnection = Get-NetTCPConnection -LocalPort $customPort -ErrorAction SilentlyContinue
                                if (-not $testConnection) {
                                    Write-Log "Using custom port $customPort instead of $PreferredPort" -Level info
                                    Write-Host "Using port $customPort" -ForegroundColor Green
                                    return $customPort
                                }
                                else {
                                    Write-Host "Port $customPort is also in use. Try another port." -ForegroundColor Red
                                }
                            }
                            else {
                                Write-Host "Port must be between 1 and 65535" -ForegroundColor Red
                            }
                        }
                        else {
                            Write-Host "Invalid port number" -ForegroundColor Red
                        }
                    } while ($true)
                }
                else {
                    Write-Host "Invalid choice. Please enter A, C, or Q." -ForegroundColor Red
                }
            } while ($true)
        }
        return $PreferredPort
    }
    
    if ($PortStrategy -eq 'fail') {
        if ($portInUse) {
            throw "Port $PreferredPort is already in use"
        }
        return $PreferredPort
    }
    
    if ($PortStrategy -eq 'auto-remap') {
        if (-not $portInUse) {
            return $PreferredPort
        }
        
        # Find next available port
        for ($port = $PreferredPort + 1; $port -le 65535; $port++) {
            $connection = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
            if (-not $connection) {
                Write-Log "Remapped port $PreferredPort to $port" -Level info
                return $port
            }
        }
        
        throw "No available ports found starting from $PreferredPort"
    }
    
    return $PreferredPort
}

function Restore-Containers {
    param([string]$BackupPath)
    
    Write-Log "Restoring containers..." -Level info
    
    $containersToRestore = $script:Manifest.containers
    
    # Filter containers if specific ones requested
    if ($SelectContainers.Count -gt 0) {
        $containersToRestore = $containersToRestore | Where-Object { $_.name -in $SelectContainers }
        Write-Log "Filtering to restore only: $($SelectContainers -join ', ')" -Level info
    }
    
    $success = $true
    
    foreach ($container in $containersToRestore) {
        $containerName = $container.name + $NameSuffix
        
        Write-Log "Restoring container: $containerName" -Level info
        
        if (-not $DryRun) {
            try {
                # Check if container already exists
                $existingContainer = docker ps -a --filter "name=$containerName" --format "{{.Names}}" 2>$null
                if ($existingContainer -eq $containerName) {
                    Write-Log "Container already exists: $containerName" -Level warn
                    continue
                }
                
                # Build docker run command
                $runArgs = @('run', '-d', '--name', $containerName)
                
                # Add restart policy
                $restartPolicy = if ($RestartPolicy) { $RestartPolicy } else { $container.restart_policy }
                if ($restartPolicy -and $restartPolicy -ne 'no') {
                    $runArgs += @('--restart', $restartPolicy)
                }
                
                # Add environment variables
                if ($container.environment) {
                    foreach ($env in $container.environment) {
                        $runArgs += @('-e', $env)
                    }
                }
                
                # Add labels
                if ($container.labels) {
                    $container.labels.PSObject.Properties | ForEach-Object {
                        $runArgs += @('--label', "$($_.Name)=$($_.Value)")
                    }
                }
                
                # Add working directory
                if ($container.working_dir) {
                    $runArgs += @('-w', $container.working_dir)
                }
                
                # Add user
                if ($container.user) {
                    $runArgs += @('-u', $container.user)
                }
                
                # Add port mappings
                if ($container.ports) {
                    foreach ($port in $container.ports) {
                        try {
                            # Debug: Log port configuration for troubleshooting
                            Write-Log "Processing port: host_port=$($port.host_port), container_port=$($port.container_port), host_ip=$($port.host_ip)" -Level debug
                            
                            # Validate port values and fail if invalid (don't skip)
                            if (-not $port.host_port -or -not $port.container_port) {
                                throw "Invalid port mapping in backup data: host_port=$($port.host_port), container_port=$($port.container_port). Backup may be corrupted."
                            }
                            
                            $hostPort = Get-AvailablePort -PreferredPort ([int]$port.host_port)
                            $containerPort = $port.container_port
                            $portMapping = "${hostPort}:${containerPort}"
                            if ($port.host_ip -and $port.host_ip -ne '0.0.0.0') {
                                $portMapping = "${port.host_ip}:$portMapping"
                            }
                            $runArgs += @('-p', $portMapping)
                            
                            if ($hostPort -ne [int]$port.host_port) {
                                $script:PortMappings["${container.name}:${port.container_port}"] = $hostPort
                            }
                        }
                        catch {
                            Write-Log ("Failed to map port " + $port.host_port + ": " + $_) -Level error
                            if ($PortStrategy -eq 'fail') {
                                throw
                            }
                        }
                    }
                }
                
                # Add volume mounts
                if ($container.volumes) {
                    foreach ($volume in $container.volumes) {
                        if ($volume.type -eq 'volume') {
                            # Debug: Log volume configuration for troubleshooting
                            Write-Log "Processing volume: name=$($volume.name), destination=$($volume.destination), type=$($volume.type)" -Level debug
                            
                            # Validate volume values and fail if invalid (don't skip)
                            if (-not $volume.name -or -not $volume.destination) {
                                throw "Invalid volume mount in backup data: name=$($volume.name), destination=$($volume.destination). Backup may be corrupted."
                            }
                            
                            $volumeName = $volume.name + $NameSuffix
                            $volumeDestination = $volume.destination
                            $volumeMount = "${volumeName}:${volumeDestination}"
                            if ($volume.read_only) {
                                $volumeMount += ':ro'
                            }
                            $runArgs += @('-v', $volumeMount)
                        }
                        elseif ($volume.type -eq 'bind') {
                            $sourcePath = $volume.source
                            if ($BindRoot) {
                                $relativePath = $volume.source -replace '^[A-Z]:', '' -replace '^\\', ''
                                $sourcePath = Join-Path $BindRoot $relativePath
                            }
                            
                            $bindMount = "${sourcePath}:${volume.destination}"
                            if ($volume.read_only) {
                                $bindMount += ':ro'
                            }
                            $runArgs += @('-v', $bindMount)
                        }
                    }
                }
                
                # Add networks
                if ($container.networks) {
                    foreach ($network in $container.networks) {
                        if ($network.name -ne 'bridge') {
                            $networkName = if ($script:NetworkMappings[$network.name]) { 
                                $script:NetworkMappings[$network.name] 
                            } else { 
                                $network.name + $NameSuffix 
                            }
                            $runArgs += @('--network', $networkName)
                        }
                    }
                }
                
                # Add privileged if needed
                if ($container.privileged) {
                    $runArgs += '--privileged'
                }
                
                # Add image (check for snapshot first)
                $imageToUse = $container.image
                
                # Check if there's a snapshot for this container
                $snapshot = $script:Manifest.snapshots | Where-Object { $_.container -eq $container.name }
                if ($snapshot) {
                    # Use snapshot image instead of original image
                    $imageToUse = $snapshot.snapshot_tag
                    Write-Log "Using snapshot image for container: $($container.name) -> $imageToUse" -Level info
                } else {
                    Write-Log "Using original image for container: $($container.name) -> $imageToUse" -Level debug
                }
                
                # Verify image exists
                $imageExists = docker images --format "{{.Repository}}:{{.Tag}}" | Select-String -Pattern "^$([regex]::Escape($imageToUse))$" -Quiet
                if (-not $imageExists) {
                    # Try without tag
                    $imageBase = $imageToUse -replace ':.*$', ''
                    $imageExists = docker images --format "{{.Repository}}" | Select-String -Pattern "^$([regex]::Escape($imageBase))$" -Quiet
                    if (-not $imageExists) {
                        throw "Image not found: $imageToUse. Make sure images were loaded successfully."
                    }
                }
                Write-Log "Verified image exists: $imageToUse" -Level debug
                
                # Handle entrypoint: --entrypoint only accepts ONE value (the executable)
                # Any additional entrypoint args must be part of the command
                $entrypointExec = $null
                $entrypointArgs = @()
                
                if ($container.entrypoint -and $container.entrypoint.Count -gt 0) {
                    $entrypointExec = $container.entrypoint[0]
                    if ($container.entrypoint.Count -gt 1) {
                        $entrypointArgs = $container.entrypoint[1..($container.entrypoint.Count - 1)]
                    }
                }
                
                # Add entrypoint if present (only the executable, not args)
                if ($entrypointExec) {
                    $runArgs += @('--entrypoint', $entrypointExec)
                }
                
                $runArgs += $imageToUse
                
                # Add command AFTER image (combine entrypoint args + original command)
                $fullCommand = @()
                if ($entrypointArgs.Count -gt 0) {
                    $fullCommand += $entrypointArgs
                }
                if ($container.command) {
                    $fullCommand += $container.command
                }
                if ($fullCommand.Count -gt 0) {
                    $runArgs += $fullCommand
                }
                
                # Execute docker run
                Write-Log "Running: docker $($runArgs -join ' ')" -Level debug
                
                # Use native PowerShell invocation instead of Start-Process to properly handle arguments with spaces
                # Redirect stderr to capture Docker errors
                $output = & docker $runArgs 2>&1
                $exitCode = $LASTEXITCODE
                
                if ($exitCode -ne 0) {
                    # Separate stdout and stderr from combined output
                    $stderr = ($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { $_.Exception.Message }) -join "`n"
                    $stdout = ($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Out-String).Trim()
                    
                    $errorMsg = "Container creation failed with exit code $exitCode"
                    if ($stderr) {
                        $errorMsg += "`nDocker error: $stderr"
                        Write-Log "Docker stderr: $stderr" -Level debug
                    }
                    if ($stdout) {
                        Write-Log "Docker stdout: $stdout" -Level debug
                    }
                    throw $errorMsg
                }
                
                $script:RestoredContainers += $containerName
                Write-Log "Restored container: $containerName" -Level debug
            }
            catch {
                Write-Log ("Failed to restore container " + $containerName + ": " + $_) -Level error
                $success = $false
            }
        }
        else {
            Write-Log "[DRY RUN] Would restore container: $containerName" -Level info
        }
    }
    
    return $success
}

function Start-RestoredContainers {
    if ($script:RestoredContainers.Count -eq 0) {
        return
    }
    
    Write-Host ""
    Write-Host "=== CONTAINER STARTUP ===" -ForegroundColor Cyan
    Write-Host "Restored containers:"
    foreach ($container in $script:RestoredContainers) {
        Write-Host "  - $container" -ForegroundColor Gray
    }
    
    if ($NonInteractive) {
        Write-Host "Non-interactive mode - containers left stopped" -ForegroundColor Yellow
        return
    }
    
    Write-Host ""
    $response = Read-Host "Start all restored containers now? (y/n)"
    
    if ($response -eq 'y' -or $response -eq 'yes') {
        Write-Host "Starting containers..." -ForegroundColor Green
        foreach ($containerName in $script:RestoredContainers) {
            Write-Host "Starting $containerName..." -NoNewline
            try {
                docker start $containerName | Out-Null
                Write-Host " OK" -ForegroundColor Green
            }
            catch {
                Write-Host " FAILED" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "Containers left stopped" -ForegroundColor Gray
    }
}

function Show-Summary {
    $duration = (Get-Date) - $script:StartTime
    
    Write-Host "`n" -NoNewline
    Write-Host "=== RESTORE SUMMARY ===" -ForegroundColor Green
    Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))"
    Write-Host "Backup Source: $($script:Manifest.source_host) ($($script:Manifest.created))"
    Write-Host "Containers Restored: $($script:RestoredContainers.Count)"
    
    if ($script:PortMappings.Count -gt 0) {
        Write-Host "Port Remappings:" -ForegroundColor Yellow
        $script:PortMappings.GetEnumerator() | ForEach-Object {
            Write-Host "  $($_.Key) -> $($_.Value)"
        }
    }
    
    if ($script:NetworkMappings.Count -gt 0) {
        Write-Host "Network Mappings:" -ForegroundColor Yellow
        $script:NetworkMappings.GetEnumerator() | ForEach-Object {
            Write-Host "  $($_.Key) -> $($_.Value)"
        }
    }
    
    if ($DryRun) {
        Write-Host "Mode: DRY RUN - No changes were made" -ForegroundColor Yellow
    }
    else {
        Write-Host "Restored Containers:" -ForegroundColor Cyan
        $script:RestoredContainers | ForEach-Object {
            Write-Host "  $_"
        }
    }
    
    Write-Host "========================" -ForegroundColor Green
}

# Main execution
function Main {
    try { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Main function started" | Add-Content -Path $script:EmergencyLogFile } catch { }
    
    if ($Help) {
        Show-Help
        return
    }
    
    # Initialize logging
    try { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Initializing logging system" | Add-Content -Path $script:EmergencyLogFile } catch { }
    
    if (-not $LogFile) {
        $LogFile = Join-Path (Split-Path -Parent $PSCommandPath) "restore-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    }
    $script:LogFile = $LogFile
    
    try { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Log file set to: $LogFile" | Add-Content -Path $script:EmergencyLogFile } catch { }
    
    Write-Log "Starting Docker restore process..." -Level info
    Write-Log "Parameters: BackupRoot=$BackupRoot, SelectContainers=$($SelectContainers -join ','), Images=$Images, Networks=$Networks, PortStrategy=$PortStrategy, DryRun=$DryRun" -Level debug
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        exit 1
    }
    
    # Find backup directory
    if (-not $BackupRoot) {
        $BackupRoot = Find-LatestBackup
        if (-not $BackupRoot) {
            exit 1
        }
    }
    
    if (-not (Test-Path $BackupRoot)) {
        Write-Log "Backup directory not found: $BackupRoot" -Level error
        exit 1
    }
    
    # Load and verify backup
    if (-not (Load-Manifest $BackupRoot)) {
        exit 1
    }
    
    if (-not (Verify-BackupIntegrity $BackupRoot)) {
        if (-not $Force) {
            Write-Log 'Backup integrity check failed. Use --force to proceed anyway.' -Level error
            exit 1
        }
        else {
            Write-Log 'Proceeding despite integrity check failures (--force specified)' -Level warn
        }
    }
    
    # Confirmation prompt
    if (-not $DryRun -and -not $Force) {
        Write-Host "`nAbout to restore:" -ForegroundColor Yellow
        Write-Host "  Backup: $BackupRoot"
        Write-Host "  Containers: $($script:Manifest.containers.Count)"
        Write-Host "  Images: $($script:Manifest.images.Count)"
        Write-Host "  Volumes: $($script:Manifest.volumes.Count)"
        Write-Host "  Networks: $($script:Manifest.networks.Count)"
        
        $response = Read-Host "`nProceed with restore? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Log "Restore cancelled by user" -Level info
            exit 0
        }
    }
    
    # Perform restore operations
    $success = $true
    
    # Restore images
    if (-not (Restore-Images $BackupRoot)) {
        $success = $false
    }
    
    # Restore snapshots
    if (-not (Restore-Snapshots $BackupRoot $manifest)) {
        $success = $false
    }
    
    # Restore networks
    if (-not (Restore-Networks $BackupRoot)) {
        $success = $false
    }
    
    # Build volume ownership map from container configs
    # This fixes a common issue: when restoring volumes, extracted files are owned by root,
    # but containers often run as non-root users (node, postgres, redis, etc.)
    # Without this, containers get permission denied errors when accessing their own data.
    # 
    # This is GENERIC - works for any container that specifies a user in its config.
    # If multiple containers share a volume with different users, the last one wins
    # (which may not be ideal, but is better than root-owned files).
    # 
    # We store both the username AND the image, so we can use that image's chown command
    # (which understands the username). This is simpler than resolving to numeric IDs.
    $volumeOwners = @{}
    foreach ($container in $script:Manifest.containers) {
        if ($container.user -and $container.volumes -and $container.image) {
            foreach ($volume in $container.volumes) {
                if ($volume.type -eq 'volume' -and $volume.name) {
                    $ownerData = @{
                        user = $container.user
                        image = $container.image
                    }
                    
                    if ($volumeOwners.ContainsKey($volume.name)) {
                        $existing = $volumeOwners[$volume.name]
                        if ($existing.user -ne $ownerData.user) {
                            Write-Log "Warning: Volume $($volume.name) is used by multiple containers with different users. Using $($ownerData.user)" -Level warn
                        }
                    }
                    
                    $volumeOwners[$volume.name] = $ownerData
                    Write-Log "Volume $($volume.name) will be owned by '$($ownerData.user)' (via image $($ownerData.image))" -Level debug
                }
            }
        }
    }
    
    # Restore volumes
    if (-not (Restore-Volumes $BackupRoot $volumeOwners)) {
        $success = $false
    }
    
    # Restore bind mounts
    if (-not (Restore-BindMounts $BackupRoot)) {
        $success = $false
    }
    
    # Restore containers
    if (-not (Restore-Containers $BackupRoot)) {
        $success = $false
    }
    
    # Ask user if they want to start the restored containers
    if ($script:RestoredContainers.Count -gt 0 -and -not $DryRun) {
        Start-RestoredContainers
    }
    
    # Show summary
    Show-Summary
    
    if ($success) {
        Write-Log "Restore completed successfully" -Level info
        if (-not $NonInteractive) {
            Write-Host ""
            Read-Host "Press Enter to exit"
        }
        exit 0
    }
    else {
        Write-Log "Restore completed with errors" -Level error
        if (-not $NonInteractive) {
            Write-Host ""
            Read-Host "Press Enter to exit"
        }
        exit 1
    }
}

# Execute main function with emergency error handling
try {
    Main
}
catch {
    Write-Host "CRITICAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    if (-not $NonInteractive) {
        Read-Host "Press Enter to exit"
    }
    exit 1
}