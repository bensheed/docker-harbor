#Requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$Include = @('images','configs','volumes','binds','networks','compose'),
    [string[]]$Exclude = @(),
    [ValidateSet('none','zip')]
    [string]$Compress = 'zip',
    [int]$SplitSize = 0,
    [ValidateSet('off','zip-aes256')]
    [string]$Encrypt = 'off',
    [string]$Passphrase = '',
    [string]$OutputRoot = '',
    [string]$LogLevel = 'debug',  # Default to maximum detail
    [string]$LogFile = '',
    [switch]$DryRun,
    [switch]$Help,
    [switch]$TestEnvironment
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
    Backup Docker containers and their data to USB/flash drive

.DESCRIPTION
    Creates a complete backup of running Docker containers including:
    - Container images (docker save)
    - Container configurations and run specifications
    - Named volumes with full contents
    - Bind-mounted host directories
    - Docker networks
    - Generated docker-compose.yaml for easy restoration

.PARAMETER AllRunning
    Backup all currently running containers (default)

.PARAMETER AllContainers
    Include stopped containers in backup

.PARAMETER Include
    Specify components to include: images,configs,volumes,binds,networks,compose

.PARAMETER Exclude
    Specify components to exclude: images,configs,volumes,binds,networks,compose

.PARAMETER Compress
    Compression method: none,zip (default: zip for volumes/binds, none for images)

.PARAMETER SplitSize
    Split archives larger than specified MB (auto-detect for FAT32)

.PARAMETER Encrypt
    Encryption method: off,zip-aes256 (default: off)

.PARAMETER Passphrase
    Encryption passphrase (required if encrypt is enabled)

.PARAMETER OutputRoot
    Base directory for backup (default: script directory)

.PARAMETER LogLevel
    Logging verbosity: info,warn,debug (default: info)

.PARAMETER LogFile
    Custom log file path

.PARAMETER DryRun
    Show what would be backed up without performing actual backup

.PARAMETER Help
    Show detailed help and examples

.PARAMETER TestEnvironment
    Test Docker environment and prerequisites only

.EXAMPLE
    .\backup.ps1
    Shows interactive menu to select containers for backup with maximum logging

.EXAMPLE
    .\backup.ps1 --include images,volumes --dry-run
    Preview backup with only images and volumes (no bind mounts or networks)

.EXAMPLE
    .\backup.ps1 --output-root D:\backups
    Backup to custom location with interactive container selection
#>

# IMMEDIATE ERROR LOGGING - Start logging before anything else
$script:EmergencyLogFile = Join-Path (Split-Path -Parent $PSCommandPath) "backup-emergency-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
try {
    "=== BACKUP SCRIPT EMERGENCY LOG ===" | Out-File -FilePath $script:EmergencyLogFile -Encoding UTF8 -Force
    "Script started at: $(Get-Date)" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
    "PowerShell Version: $($PSVersionTable.PSVersion)" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
    "Script Path: $PSCommandPath" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
    "Script started successfully" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
} catch {
    Write-Host "CRITICAL: Cannot create emergency log file: $_" -ForegroundColor Red
}

# Log global variable initialization
try {
    "Initializing global variables..." | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
} catch { }

# Global variables
$script:LogLevel = $LogLevel
$script:LogFile = $LogFile
$script:StartTime = Get-Date
$script:BackupRoot = ''
$script:Manifest = @{
    version = '1.0'
    created = $script:StartTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    source_host = $env:COMPUTERNAME
    containers = @()
    images = @()
    volumes = @()
    networks = @()
    binds = @()
    snapshots = @()
    checksums = @{}
    metadata = @{
        total_size = 0
        split_archives = @()
        filesystem_type = ''
    }
}

# Log successful global variable initialization
try {
    "Global variables initialized successfully" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
    "Start time: $script:StartTime" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
} catch { }

function Show-Help {
    Get-Help $PSCommandPath -Detailed
    Write-Host "`nCommon Usage Examples:" -ForegroundColor Green
    Write-Host "  .\backup.ps1                                    # Backup all running containers"
    Write-Host "  .\backup.ps1 --all-containers                  # Include stopped containers"
    Write-Host "  .\backup.ps1 --exclude binds --compress none   # Skip bind mounts, no compression"
    Write-Host "  .\backup.ps1 --dry-run --log-level debug       # Preview with detailed logging"
    Write-Host "  .\backup.ps1 --encrypt zip-aes256 --passphrase 'secret123'  # Encrypted backup"
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
    
    # File output with error handling
    if ($script:LogFile) {
        try {
            Add-Content -Path $script:LogFile -Value $logMessage -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # If we can't write to log file, at least show it on console
            Write-Host "[LOG ERROR] Could not write to log file: ${_}" -ForegroundColor Magenta
        }
    }
}



function Show-StartupBanner {
    Write-Host ""
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "    Docker Container Backup Tool    " -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "Interactive & User-Friendly Edition" -ForegroundColor Green
    Write-Host "Maximum logging enabled by default" -ForegroundColor Yellow
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
}

function Test-Environment {
    Write-Host "Testing Docker Environment..." -ForegroundColor Cyan
    Write-Host ""
    
    $allPassed = $true
    
    # Test Docker CLI
    Write-Host "1. Docker CLI..." -ForegroundColor Yellow
    try {
        $dockerVersion = docker --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   $dockerVersion - PASSED" -ForegroundColor Green
        } else {
            Write-Host "   Docker CLI not found - FAILED" -ForegroundColor Red
            $allPassed = $false
        }
    } catch {
        Write-Host "   Docker CLI not available - FAILED" -ForegroundColor Red
        $allPassed = $false
    }
    
    # Test Docker daemon
    Write-Host "2. Docker Daemon..." -ForegroundColor Yellow
    try {
        docker info >$null 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   Docker daemon running - PASSED" -ForegroundColor Green
        } else {
            Write-Host "   Docker daemon not running - FAILED" -ForegroundColor Red
            Write-Host "   Solution: Start Docker Desktop" -ForegroundColor Cyan
            $allPassed = $false
        }
    } catch {
        Write-Host "   Cannot connect to Docker daemon - FAILED" -ForegroundColor Red
        $allPassed = $false
    }
    
    # Test file system access
    Write-Host "3. File System Access..." -ForegroundColor Yellow
    try {
        $testFile = Join-Path (Split-Path -Parent $PSCommandPath) "test-write-$(Get-Date -Format 'HHmmss').tmp"
        "test" | Out-File -FilePath $testFile -Force
        Remove-Item $testFile -Force
        Write-Host "   Write access available - PASSED" -ForegroundColor Green
    } catch {
        Write-Host "   Cannot write to script directory - FAILED" -ForegroundColor Red
        $allPassed = $false
    }
    
    Write-Host ""
    if ($allPassed) {
        Write-Host "RESULT: Environment ready for backup operations" -ForegroundColor Green
    } else {
        Write-Host "RESULT: Fix issues before proceeding" -ForegroundColor Red
    }
    Write-Host ""
    
    return $allPassed
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level info
    
    # Check PowerShell version first
    $psVersion = $PSVersionTable.PSVersion
    Write-Log "PowerShell version: $psVersion" -Level info
    
    if ($psVersion.Major -lt 5) {
        Write-Log "PowerShell 5.0 or higher is required. Current version: $psVersion" -Level error
        Write-Host "ERROR: PowerShell 5.0 or higher is required. Current version: $psVersion" -ForegroundColor Red
        return $false
    }
    
    # Check Docker availability
    Write-Log "Checking Docker availability..." -Level debug
    try {
        $dockerVersion = docker --version 2>$null
        if (-not $dockerVersion -or $LASTEXITCODE -ne 0) {
            throw "Docker command not found or failed"
        }
        Write-Log "Docker found: $dockerVersion" -Level info
    }
    catch {
        $errorMsg = "Docker is not available. Please ensure Docker Desktop is installed and added to PATH."
        Write-Log $errorMsg -Level error
        Write-Host "ERROR: $errorMsg" -ForegroundColor Red
        Write-Host "  - Download Docker Desktop from: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
        Write-Host "  - Ensure Docker Desktop is running" -ForegroundColor Yellow
        Write-Host "  - Restart PowerShell after installation" -ForegroundColor Yellow
        return $false
    }
    
    # Check Docker daemon
    Write-Log "Checking Docker daemon..." -Level debug
    try {
        $dockerInfo = docker info 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Docker daemon not responding (exit code: $LASTEXITCODE)"
        }
        Write-Log "Docker daemon is running" -Level info
        
        # Extract some useful info from docker info
        $dockerInfo | ForEach-Object {
            if ($_ -match "Server Version: (.+)") {
                Write-Log "Docker Server Version: $($matches[1])" -Level debug
            }
            if ($_ -match "Operating System: (.+)") {
                Write-Log "Docker OS: $($matches[1])" -Level debug
            }
        }
    }
    catch {
        $errorMsg = "Docker daemon is not running. Please start Docker Desktop."
        Write-Log $errorMsg -Level error
        Write-Host "ERROR: $errorMsg" -ForegroundColor Red
        Write-Host "  - Open Docker Desktop application" -ForegroundColor Yellow
        Write-Host "  - Wait for Docker to start (check system tray icon)" -ForegroundColor Yellow
        Write-Host "  - Try running 'docker ps' to test connectivity" -ForegroundColor Yellow
        return $false
    }
    
    # Check available disk space
    try {
        $scriptDir = Split-Path -Parent $PSCommandPath
        $drive = Split-Path -Qualifier $scriptDir
        $driveInfo = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $drive }
        if ($driveInfo) {
            $freeSpaceGB = [math]::Round($driveInfo.FreeSpace / 1GB, 2)
            Write-Log "Available disk space on ${drive}: ${freeSpaceGB}GB" -Level info
            
            if ($freeSpaceGB -lt 1) {
                Write-Log "WARNING: Low disk space (${freeSpaceGB}GB). Backup may fail." -Level warn
                Write-Host "WARNING: Low disk space (${freeSpaceGB}GB). Backup may fail." -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Log "Could not check disk space: ${_}" -Level warn
    }
    
    Write-Log "All prerequisites checks passed" -Level info
    return $true
}

function Get-FilesystemType {
    param([string]$Path)
    
    try {
        $drive = Split-Path -Qualifier $Path
        $driveInfo = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $drive }
        return $driveInfo.FileSystem
    }
    catch {
        Write-Log "Could not determine filesystem type for $Path" -Level warn
        return 'UNKNOWN'
    }
}

function Initialize-BackupDirectory {
    $timestamp = $script:StartTime.ToString('yyyyMMdd-HHmmss')
    
    if (-not $OutputRoot) {
        $OutputRoot = Split-Path -Parent $PSCommandPath
    }
    
    $script:BackupRoot = Join-Path $OutputRoot "docker-backup\$timestamp"
    
    # Detect filesystem type
    $fsType = Get-FilesystemType $OutputRoot
    $script:Manifest.metadata.filesystem_type = $fsType
    Write-Log "Detected filesystem: $fsType" -Level debug
    
    # Auto-configure split size for FAT32
    if ($fsType -eq 'FAT32' -and $SplitSize -eq 0) {
        $SplitSize = 3500  # 3.5GB limit for FAT32
        Write-Log "Auto-configured split size for FAT32: ${SplitSize}MB" -Level info
    }
    
    if (-not $DryRun) {
        try {
            New-Item -Path $script:BackupRoot -ItemType Directory -Force | Out-Null
            New-Item -Path "$script:BackupRoot\configs" -ItemType Directory -Force | Out-Null
            New-Item -Path "$script:BackupRoot\images" -ItemType Directory -Force | Out-Null
            New-Item -Path "$script:BackupRoot\volumes" -ItemType Directory -Force | Out-Null
            New-Item -Path "$script:BackupRoot\binds" -ItemType Directory -Force | Out-Null
            New-Item -Path "$script:BackupRoot\compose" -ItemType Directory -Force | Out-Null
            New-Item -Path "$script:BackupRoot\logs" -ItemType Directory -Force | Out-Null
            
            Write-Log "Created backup directory: $script:BackupRoot" -Level info
        }
        catch {
            Write-Log "Failed to create backup directory: ${_}" -Level error
            return $false
        }
    }
    else {
        Write-Log "[DRY RUN] Would create backup directory: $script:BackupRoot" -Level info
    }
    
    return $true
}

function Get-ContainerList {
    Write-Log "Discovering all containers..." -Level info
    
    try {
        # Get all containers (running and stopped) for user selection
        Write-Log "Running: docker ps -a --format table" -Level debug
        $containerInfo = docker ps -a --format "{{.ID}}`t{{.Names}}`t{{.Status}}`t{{.Image}}" 2>$null
        Write-Log "Docker ps exit code: $LASTEXITCODE" -Level debug
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to list containers"
        }
        
        Write-Log "Raw container info output: '$containerInfo'" -Level debug
        
        $containers = @()
        if ($containerInfo) {
            $containerInfo -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
                $line = $_.Trim()
                if ($line) {
                    $parts = $line -split "`t"
                    if ($parts.Length -ge 4) {
                        $containers += @{
                            ID = $parts[0].Substring(0, [Math]::Min(12, $parts[0].Length))
                            Names = $parts[1]
                            Status = $parts[2]
                            Image = $parts[3]
                        }
                        Write-Log "Found container: $($parts[1]) ($($parts[2]))" -Level debug
                    }
                }
            }
        }
        
        if ($containers.Count -eq 0) {
            Write-Log "No containers found" -Level warn
            return @()
        }
        
        # Interactive container selection
        Write-Host "`n=== CONTAINER SELECTION ===" -ForegroundColor Cyan
        Write-Host "Found $($containers.Count) containers. Please select which ones to backup:`n" -ForegroundColor Yellow
        
        for ($i = 0; $i -lt $containers.Count; $i++) {
            $container = $containers[$i]
            $statusColor = if ($container.Status -like "*Up*") { "Green" } elseif ($container.Status -like "*Exited*") { "Yellow" } else { "Red" }
            Write-Host "[$($i+1)] " -NoNewline -ForegroundColor White
            Write-Host "$($container.Names)" -NoNewline -ForegroundColor Cyan
            Write-Host " (" -NoNewline
            Write-Host "$($container.Status)" -NoNewline -ForegroundColor $statusColor
            Write-Host ") - $($container.Image)"
        }
        
        Write-Host "`nOptions:" -ForegroundColor Yellow
        Write-Host "  Enter numbers (e.g., 1,3,5 or 1-3 or 'all'): " -NoNewline
        $selection = Read-Host
        
        $selectedContainers = @()
        if ($selection.ToLower() -eq 'all') {
            $selectedContainers = $containers
        } else {
            $selection -split ',' | ForEach-Object {
                $range = $_.Trim()
                if ($range -match '(\d+)-(\d+)') {
                    $start = [int]$matches[1]
                    $end = [int]$matches[2]
                    for ($j = $start; $j -le $end; $j++) {
                        if ($j -ge 1 -and $j -le $containers.Count) {
                            $selectedContainers += $containers[$j-1]
                        }
                    }
                } elseif ($range -match '^\d+$') {
                    $index = [int]$range
                    if ($index -ge 1 -and $index -le $containers.Count) {
                        $selectedContainers += $containers[$index-1]
                    }
                }
            }
        }
        
        if ($selectedContainers.Count -eq 0) {
            Write-Host "No containers selected. Exiting." -ForegroundColor Red
            exit 1
        }
        
        Write-Host "`nSelected containers:" -ForegroundColor Green
        $selectedContainers | ForEach-Object {
            Write-Host "  - $($_.Names) ($($_.Status))" -ForegroundColor Green
        }
        Write-Host ""
        
        Write-Log "User selected $($selectedContainers.Count) containers for backup" -Level info
        return $selectedContainers
    }
    catch {
        Write-Log ("Failed to discover containers: " + $_) -Level error
        return @()
    }
}

function Get-ContainerDetails {
    param([object]$Container)
    
    try {
        $inspectJson = docker inspect $Container.ID 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to inspect container $($Container.Names)"
        }
        
        $details = ConvertFrom-Json ($inspectJson -join '')
        return $details[0]
    }
    catch {
        Write-Log "Failed to get details for container $($Container.Names): ${_}" -Level error
        return $null
    }
}

function Analyze-ContainerStorage {
    param([object]$ContainerDetails)
    
    $analysis = @{
        HasVolumes = $false
        HasBindMounts = $false
        VolumeCount = 0
        BindMountCount = 0
        Volumes = @()
        BindMounts = @()
        StorageType = "none"
        Recommendation = ""
    }
    
    if ($ContainerDetails.Mounts -and $ContainerDetails.Mounts.Count -gt 0) {
        foreach ($mount in $ContainerDetails.Mounts) {
            if ($mount.Type -eq "volume") {
                $analysis.HasVolumes = $true
                $analysis.VolumeCount++
                $analysis.Volumes += $mount
            }
            elseif ($mount.Type -eq "bind") {
                $analysis.HasBindMounts = $true
                $analysis.BindMountCount++
                $analysis.BindMounts += $mount
            }
        }
    }
    
    # Determine storage type and recommendation
    if ($analysis.HasVolumes -or $analysis.HasBindMounts) {
        $analysis.StorageType = "persistent"
        $analysis.Recommendation = "Standard backup (volumes and bind mounts will be preserved)"
    }
    else {
        $analysis.StorageType = "ephemeral"
        $analysis.Recommendation = "Container stores data in filesystem - consider filesystem snapshot"
    }
    
    return $analysis
}



function Show-ContainerAnalysis {
    param([array]$ContainerAnalyses)
    
    Write-Host "`n=== CONTAINER STORAGE ANALYSIS ===" -ForegroundColor Cyan
    Write-Host "Analyzing storage configuration for selected containers...`n" -ForegroundColor Yellow
    
    $hasEphemeralContainers = $false
    
    for ($i = 0; $i -lt $ContainerAnalyses.Count; $i++) {
        $analysis = $ContainerAnalyses[$i]
        $container = $analysis.Container
        $storage = $analysis.Storage
        
        Write-Host "[$($i+1)] " -NoNewline -ForegroundColor White
        Write-Host "$($container.Names)" -NoNewline -ForegroundColor Cyan
        
        if ($storage.StorageType -eq "persistent") {
            Write-Host " - " -NoNewline
            Write-Host "HAS PERSISTENT STORAGE" -ForegroundColor Green
            if ($storage.HasVolumes) {
                $volumeNames = $storage.Volumes | ForEach-Object { $_.Name }
                Write-Host "    Volumes: $($storage.VolumeCount) ($($volumeNames -join ', '))" -ForegroundColor Gray
            }
            if ($storage.HasBindMounts) {
                Write-Host "    Bind Mounts: $($storage.BindMountCount)" -ForegroundColor Gray
            }
        }
        else {
            Write-Host " - " -NoNewline
            Write-Host "NO PERSISTENT STORAGE DETECTED" -ForegroundColor Red
            Write-Host "    WARNING: Data stored inside container filesystem" -ForegroundColor Yellow
            $hasEphemeralContainers = $true
        }
    }
    
    if ($hasEphemeralContainers) {
        Write-Host "`n" -NoNewline
        Write-Host "IMPORTANT:" -ForegroundColor Red
        Write-Host "Some containers store data inside their filesystem instead of using volumes." -ForegroundColor Yellow
        Write-Host "This is not recommended for production use. Data will be lost when containers are removed." -ForegroundColor Yellow
        Write-Host "`nFor containers without persistent storage, you can:" -ForegroundColor Yellow
        Write-Host "  [A] Create filesystem snapshot (captures ALL container data + runtime files)" -ForegroundColor White
        Write-Host "  [B] Backup configuration only (no data - fresh container on restore)" -ForegroundColor White
        Write-Host "  [C] Skip this container" -ForegroundColor White
    }
    
    return $hasEphemeralContainers
}

function Get-UserBackupChoices {
    param([array]$ContainerAnalyses)
    
    $choices = @{}
    
    foreach ($analysis in $ContainerAnalyses) {
        $container = $analysis.Container
        $storage = $analysis.Storage
        
        if ($storage.StorageType -eq "ephemeral") {
            Write-Host "`nContainer: " -NoNewline
            Write-Host "$($container.Names)" -ForegroundColor Cyan
            Write-Host "This container has no persistent storage configured." -ForegroundColor Yellow
            Write-Host "Choose backup strategy:" -ForegroundColor Yellow
            Write-Host "  [A] Filesystem snapshot (recommended - captures all data)" -ForegroundColor Green
            Write-Host "  [B] Configuration only (no data backup)" -ForegroundColor Yellow
            Write-Host "  [C] Skip this container" -ForegroundColor Red
            
            do {
                Write-Host "Choice [A/B/C]: " -NoNewline -ForegroundColor White
                $choice = Read-Host
                $choice = $choice.ToUpper().Trim()
            } while ($choice -notin @('A', 'B', 'C'))
            
            $choices[$container.Names] = switch ($choice) {
                'A' { 'snapshot' }
                'B' { 'config-only' }
                'C' { 'skip' }
            }
            
            $actionText = switch ($choice) {
                'A' { "Will create filesystem snapshot" }
                'B' { "Will backup configuration only" }
                'C' { "Will skip this container" }
            }
            Write-Host "$actionText" -ForegroundColor Green
        }
        else {
            $choices[$container.Names] = 'standard'
        }
    }
    
    return $choices
}

function Export-ContainerSnapshot {
    param(
        [object]$ContainerDetails,
        [string]$BackupPath
    )
    
    try {
        $containerName = $ContainerDetails.Name -replace '^/', ''
        $imageName = "$containerName-snapshot"
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $snapshotTag = "${imageName}:${timestamp}"
        
        Write-Log "Creating filesystem snapshot for container: $containerName" -Level info
        Write-Log "This captures all data stored inside the container filesystem" -Level info
        
        # Create snapshot using docker commit
        Write-Log "Running: docker commit $($ContainerDetails.Id) $snapshotTag" -Level debug
        $commitOutput = docker commit $ContainerDetails.Id $snapshotTag 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create container snapshot: $commitOutput"
        }
        
        Write-Log "Created snapshot image: $snapshotTag" -Level debug
        
        # Export the snapshot image
        $snapshotPath = Join-Path $BackupPath "snapshots"
        if (-not (Test-Path $snapshotPath)) {
            New-Item -ItemType Directory -Path $snapshotPath -Force | Out-Null
        }
        
        $sanitizedName = $containerName -replace '[<>:"/\\|?*]', '_'
        $snapshotFile = Join-Path $snapshotPath "$sanitizedName-snapshot.tar"
        
        Write-Log "Exporting snapshot to: $snapshotFile" -Level debug
        Write-Log "Running: docker save $snapshotTag -o $snapshotFile" -Level debug
        
        $saveOutput = docker save $snapshotTag -o $snapshotFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to export snapshot: $saveOutput"
        }
        
        # Verify the file was created and has content
        if (-not (Test-Path $snapshotFile)) {
            throw "Snapshot file was not created: $snapshotFile"
        }
        
        $fileSize = (Get-Item $snapshotFile).Length
        if ($fileSize -eq 0) {
            throw "Snapshot file is empty: $snapshotFile"
        }
        
        Write-Log "Snapshot exported successfully: $([math]::Round($fileSize/1MB, 2))MB" -Level info
        
        # Clean up the temporary snapshot image
        Write-Log "Cleaning up temporary snapshot image: $snapshotTag" -Level debug
        docker rmi $snapshotTag 2>&1 | Out-Null
        
        # Update manifest
        $script:Manifest.snapshots += @{
            container = $containerName
            file = "snapshots/$sanitizedName-snapshot.tar"
            size = $fileSize
            created = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
            original_image = $ContainerDetails.Config.Image
            snapshot_tag = $snapshotTag
        }
        
        Write-Log "Added snapshot to manifest for container: $containerName" -Level debug
        return $true
    }
    catch {
        Write-Log "Failed to create snapshot for container $($ContainerDetails.Name): $_" -Level error
        return $false
    }
}



function Export-ContainerConfig {
    param([object]$ContainerDetails)
    
    $containerName = $ContainerDetails.Name -replace '^/', ''
    Write-Log "Exporting configuration for container: $containerName" -Level debug
    
    # Create normalized run specification
    $runSpec = @{
        name = $containerName
        image = $ContainerDetails.Config.Image
        command = $ContainerDetails.Config.Cmd
        entrypoint = $ContainerDetails.Config.Entrypoint
        environment = $ContainerDetails.Config.Env
        labels = $ContainerDetails.Config.Labels
        working_dir = $ContainerDetails.Config.WorkingDir
        user = $ContainerDetails.Config.User
        ports = @()
        volumes = @()
        networks = @()
        restart_policy = $ContainerDetails.HostConfig.RestartPolicy.Name
        privileged = $ContainerDetails.HostConfig.Privileged
        created = $ContainerDetails.Created
        state = $ContainerDetails.State.Status
    }
    
    # Extract port mappings
    if ($ContainerDetails.HostConfig.PortBindings) {
        $ContainerDetails.HostConfig.PortBindings.PSObject.Properties | ForEach-Object {
            $containerPort = $_.Name
            $hostBindings = $_.Value
            foreach ($binding in $hostBindings) {
                $runSpec.ports += @{
                    host_port = $binding.HostPort
                    container_port = $containerPort
                    host_ip = $binding.HostIp
                }
            }
        }
    }
    
    # Extract volume mounts
    if ($ContainerDetails.Mounts) {
        foreach ($mount in $ContainerDetails.Mounts) {
            $runSpec.volumes += @{
                type = $mount.Type
                source = $mount.Source
                destination = $mount.Destination
                read_only = $mount.RW -eq $false
                name = $mount.Name
            }
        }
    }
    
    # Extract network connections
    if ($ContainerDetails.NetworkSettings.Networks) {
        $ContainerDetails.NetworkSettings.Networks.PSObject.Properties | ForEach-Object {
            $runSpec.networks += @{
                name = $_.Name
                ip_address = $_.Value.IPAddress
                aliases = $_.Value.Aliases
            }
        }
    }
    
    $configFile = "$script:BackupRoot\configs\$containerName.json"
    
    if (-not $DryRun) {
        try {
            $runSpec | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
            $checksum = Get-FileHash -Path $configFile -Algorithm SHA256
            $script:Manifest.checksums["configs/$containerName.json"] = $checksum.Hash
            Write-Log "Exported config for $containerName" -Level debug
        }
        catch {
            Write-Log ("Failed to export config for " + $containerName + ": " + $_) -Level error
            return $false
        }
    }
    else {
        Write-Log "[DRY RUN] Would export config to: $configFile" -Level info
    }
    
    $script:Manifest.containers += $runSpec
    return $true
}

function Test-DiskSpace {
    param([string]$Path, [long]$RequiredBytes)
    
    try {
        $drive = (Get-Item $Path).PSDrive
        $freeSpace = $drive.Free
        
        if ($freeSpace -lt $RequiredBytes) {
            $requiredGB = [math]::Round($RequiredBytes / 1GB, 2)
            $availableGB = [math]::Round($freeSpace / 1GB, 2)
            Write-Log "Insufficient disk space. Required: ${requiredGB}GB, Available: ${availableGB}GB" -Level error
            return $false
        }
        return $true
    }
    catch {
        Write-Log ("Failed to check disk space: " + $_) -Level warn
        return $true  # Assume OK if we can't check
    }
}

function Export-ContainerImage {
    param([string]$ImageName)
    
    if ($Exclude -contains 'images') {
        Write-Log "Skipping image export (excluded): $ImageName" -Level debug
        return $true
    }
    
    # Check if image already exported
    $sanitizedName = $ImageName -replace '[<>:"/\\|?*]', '_'
    $imageFile = "$script:BackupRoot\images\$sanitizedName.tar"
    
    if ($script:Manifest.images -contains $ImageName) {
        Write-Log "Image already queued for export: $ImageName" -Level debug
        return $true
    }
    
    Write-Log "Exporting image: $ImageName" -Level info
    
    if (-not $DryRun) {
        try {
            # Check available disk space (estimate 2GB per image as minimum)
            if (-not (Test-DiskSpace -Path $script:BackupRoot -RequiredBytes (2GB))) {
                throw "Insufficient disk space for image export"
            }
            
            $process = Start-Process -FilePath 'docker' -ArgumentList @('save', '-o', $imageFile, $ImageName) -Wait -PassThru -NoNewWindow
            if ($process.ExitCode -ne 0) {
                throw "Docker save failed with exit code $($process.ExitCode)"
            }
            
            # Handle file splitting for FAT32
            if ($SplitSize -gt 0) {
                $fileSize = (Get-Item $imageFile).Length / 1MB
                if ($fileSize -gt $SplitSize) {
                    Write-Log "Splitting large image file: $sanitizedName.tar (${fileSize}MB)" -Level info
                    Split-LargeFile -FilePath $imageFile -SizeMB $SplitSize
                }
            }
            
            $checksum = Get-FileHash -Path $imageFile -Algorithm SHA256
            $script:Manifest.checksums["images/$sanitizedName.tar"] = $checksum.Hash
            Write-Log "Exported image: $ImageName" -Level debug
        }
        catch {
            Write-Log ("Failed to export image " + $ImageName + ": " + $_) -Level error
            return $false
        }
    }
    else {
        Write-Log "[DRY RUN] Would export image to: $imageFile" -Level info
    }
    
    $script:Manifest.images += $ImageName
    return $true
}

function Export-Volume {
    param([string]$VolumeName)
    
    if ($Exclude -contains 'volumes') {
        Write-Log "Skipping volume export (excluded): $VolumeName" -Level debug
        return $true
    }
    
    Write-Log "Exporting volume: $VolumeName" -Level info
    
    # Determine final file extension based on compression
    $volumeFile = if ($Compress -eq 'zip') { 
        "$script:BackupRoot\volumes\$VolumeName.zip" 
    } else { 
        "$script:BackupRoot\volumes\$VolumeName.tar.gz" 
    }
    
    if (-not $DryRun) {
        try {
            # Use a temporary container to tar the volume contents
            $tempContainer = "backup-helper-$(Get-Random)"
            
            # Create tar archive of volume
            $tarArgs = @(
                'run', '--rm', '--name', $tempContainer,
                '-v', "${VolumeName}:/volume:ro",
                '-v', "${script:BackupRoot}\volumes:/backup",
                'busybox', 'tar', 'czf', "/backup/$VolumeName.tar.gz", '-C', '/volume', '.'
            )
            
            Write-Log "Running Docker command: docker $($tarArgs -join ' ')" -Level debug
            Write-Log "Volume name for file path: '$VolumeName'" -Level debug
            
            # Use direct docker command instead of Start-Process to avoid hanging
            $dockerCmd = "docker $($tarArgs -join ' ')"
            $output = cmd /c "$dockerCmd 2>&1"
            $exitCode = $LASTEXITCODE
            
            Write-Log "Docker command output: $output" -Level debug
            Write-Log "Docker command exit code: $exitCode" -Level debug
            if ($exitCode -ne 0) {
                throw "Volume backup failed with exit code $exitCode. Output: $output"
            }
            
            $tarFile = "$script:BackupRoot\volumes\$VolumeName.tar.gz"
            Write-Log "Expected tar file path: '$tarFile'" -Level debug
            
            # Verify the file was actually created and has content
            if (-not (Test-Path $tarFile)) {
                # List what files were actually created in the volumes directory
                $volumesDir = "$script:BackupRoot\volumes"
                if (Test-Path $volumesDir) {
                    $actualFiles = Get-ChildItem -Path $volumesDir -File | Select-Object -ExpandProperty Name
                    Write-Log "Files actually created in volumes directory: $($actualFiles -join ', ')" -Level debug
                } else {
                    Write-Log "Volumes directory does not exist: $volumesDir" -Level debug
                }
                throw "Volume backup file was not created: $tarFile"
            }
            if ((Get-Item $tarFile).Length -eq 0) {
                throw "Volume backup file is empty: $tarFile"
            }
            
            # Convert to zip if compression requested
            if ($Compress -eq 'zip') {
                # For zip compression, we need to extract and recompress
                # This is complex, so for now just keep as tar.gz
                Write-Log "Note: Keeping volume as tar.gz format for compatibility" -Level debug
                $volumeFile = $tarFile
            }
            
            $checksum = Get-FileHash -Path $volumeFile -Algorithm SHA256
            $volumeFileName = Split-Path $volumeFile -Leaf
            $script:Manifest.checksums["volumes/$volumeFileName"] = $checksum.Hash
            $script:Manifest.volumes += $VolumeName
            Write-Log "Exported volume: $VolumeName" -Level debug
        }
        catch {
            Write-Log ("Failed to export volume " + $VolumeName + ": " + $_) -Level error
            return $false
        }
    }
    else {
        Write-Log "[DRY RUN] Would export volume to: $volumeFile" -Level info
        $script:Manifest.volumes += $VolumeName
    }
    
    return $true
}

function Export-BindMount {
    param([string]$SourcePath, [string]$ContainerPath)
    
    if ($Exclude -contains 'binds') {
        Write-Log "Skipping bind mount export (excluded): $SourcePath" -Level debug
        return $true
    }
    
    # Skip Unix socket paths and other special paths on Windows
    if ($SourcePath -match '^//(var/run/docker\.sock|run/docker\.sock)$' -or 
        $SourcePath -match '^/(var/run/docker\.sock|run/docker\.sock)$' -or
        $SourcePath -match '\.sock$') {
        Write-Log "Skipping Unix socket path (not applicable on Windows): $SourcePath" -Level debug
        return $true
    }

    Write-Log "Exporting bind mount: $SourcePath" -Level info
    
    # Create unique filename for bind mount
    $pathHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($SourcePath))
    $hashString = [System.BitConverter]::ToString($pathHash).Replace('-', '').Substring(0, 8)
    $sanitizedPath = ($SourcePath -replace '[<>:"/\\|?*]', '_').Substring(0, [Math]::Min(50, $SourcePath.Length))
    $bindFile = "$script:BackupRoot\binds\${hashString}__$sanitizedPath.zip"
    
    if (-not $DryRun) {
        try {
            if (Test-Path $SourcePath) {
                # Check if source path has any content to archive
                $items = Get-ChildItem -Path $SourcePath -Force -ErrorAction SilentlyContinue
                if (-not $items) {
                    Write-Log "Bind mount source path is empty: $SourcePath" -Level warn
                    return $false
                }
                
                Compress-Archive -Path "$SourcePath\*" -DestinationPath $bindFile -Force
                
                # Verify the archive was actually created and has content
                if (-not (Test-Path $bindFile)) {
                    throw "Bind mount archive was not created: $bindFile"
                }
                if ((Get-Item $bindFile).Length -eq 0) {
                    throw "Bind mount archive is empty: $bindFile"
                }
                
                $checksum = Get-FileHash -Path $bindFile -Algorithm SHA256
                $script:Manifest.checksums["binds/${hashString}__$sanitizedPath.zip"] = $checksum.Hash
                $script:Manifest.binds += @{
                    source_path = $SourcePath
                    container_path = $ContainerPath
                    archive_name = "${hashString}__$sanitizedPath.zip"
                }
                Write-Log "Exported bind mount: $SourcePath" -Level debug
            }
            else {
                Write-Log "Bind mount source path not found: $SourcePath" -Level warn
                return $false
            }
        }
        catch {
            Write-Log ("Failed to export bind mount " + $SourcePath + ": " + $_) -Level error
            return $false
        }
    }
    else {
        Write-Log "[DRY RUN] Would export bind mount to: $bindFile" -Level info
        $script:Manifest.binds += @{
            source_path = $SourcePath
            container_path = $ContainerPath
            archive_name = "${hashString}__$sanitizedPath.zip"
        }
    }
    
    return $true
}

function Export-Networks {
    Write-Log "Exporting Docker networks..." -Level info
    
    if ($Exclude -contains 'networks') {
        Write-Log "Skipping network export (excluded)" -Level debug
        return $true
    }
    
    try {
        $networksJson = docker network ls --format json 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to list networks"
        }
        
        $networks = @()
        $networksJson -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
            $network = ConvertFrom-Json $_
            if ($network.Name -notin @('bridge', 'host', 'none')) {
                $networkDetails = docker network inspect $network.Name | ConvertFrom-Json
                $networks += $networkDetails[0]
            }
        }
        
        $networksFile = "$script:BackupRoot\networks.json"
        
        if (-not $DryRun) {
            $networks | ConvertTo-Json -Depth 10 | Set-Content -Path $networksFile -Encoding UTF8
            $checksum = Get-FileHash -Path $networksFile -Algorithm SHA256
            $script:Manifest.checksums["networks.json"] = $checksum.Hash
        }
        else {
            Write-Log "[DRY RUN] Would export networks to: $networksFile" -Level info
        }
        
        $script:Manifest.networks = $networks
        Write-Log "Exported $($networks.Count) custom networks" -Level debug
        return $true
    }
    catch {
        Write-Log "Failed to export networks: ${_}" -Level error
        return $false
    }
}

function Generate-DockerCompose {
    if ($Exclude -contains 'compose') {
        Write-Log "Skipping docker-compose generation (excluded)" -Level debug
        return $true
    }
    
    Write-Log "Generating docker-compose.yaml..." -Level info
    
    $compose = @{
        version = '3.8'
        services = @{}
        volumes = @{}
        networks = @{}
    }
    
    # Add services from containers
    foreach ($container in $script:Manifest.containers) {
        $serviceName = $container.name
        $service = @{
            image = $container.image
            container_name = $container.name
        }
        
        if ($container.command) {
            $service.command = $container.command
        }
        
        if ($container.environment) {
            $service.environment = $container.environment
        }
        
        if ($container.ports) {
            $service.ports = @()
            foreach ($port in $container.ports) {
                $service.ports += "${port.host_port}:${port.container_port}"
            }
        }
        
        if ($container.volumes) {
            $service.volumes = @()
            foreach ($volume in $container.volumes) {
                if ($volume.type -eq 'volume') {
                    $service.volumes += "${volume.name}:${volume.destination}"
                    $compose.volumes[$volume.name] = @{}
                }
                elseif ($volume.type -eq 'bind') {
                    $service.volumes += "${volume.source}:${volume.destination}"
                }
            }
        }
        
        if ($container.networks) {
            $service.networks = @()
            foreach ($network in $container.networks) {
                if ($network.name -ne 'bridge') {
                    $service.networks += $network.name
                    $compose.networks[$network.name] = @{ external = $true }
                }
            }
        }
        
        if ($container.restart_policy -and $container.restart_policy -ne 'no') {
            $service.restart = $container.restart_policy
        }
        
        $compose.services[$serviceName] = $service
    }
    
    $composeFile = "$script:BackupRoot\compose\docker-compose.generated.yaml"
    
    if (-not $DryRun) {
        try {
            $compose | ConvertTo-Json -Depth 10 | Set-Content -Path $composeFile -Encoding UTF8
            $checksum = Get-FileHash -Path $composeFile -Algorithm SHA256
            $script:Manifest.checksums["compose/docker-compose.generated.yaml"] = $checksum.Hash
            Write-Log "Generated docker-compose.yaml" -Level debug
        }
        catch {
            Write-Log "Failed to generate docker-compose.yaml: ${_}" -Level error
            return $false
        }
    }
    else {
        Write-Log "[DRY RUN] Would generate docker-compose.yaml at: $composeFile" -Level info
    }
    
    return $true
}

function Split-LargeFile {
    param([string]$FilePath, [int]$SizeMB)
    
    $file = Get-Item $FilePath
    $chunkSize = $SizeMB * 1MB
    $totalSize = $file.Length
    $chunks = [Math]::Ceiling($totalSize / $chunkSize)
    
    Write-Log "Splitting file into $chunks chunks of ${SizeMB}MB each" -Level info
    
    try {
        $reader = [System.IO.File]::OpenRead($FilePath)
        $buffer = New-Object byte[] $chunkSize
        
        for ($i = 0; $i -lt $chunks; $i++) {
            $chunkFile = "$FilePath.part$($i.ToString('000'))"
            $writer = [System.IO.File]::Create($chunkFile)
            
            $bytesRead = $reader.Read($buffer, 0, $chunkSize)
            $writer.Write($buffer, 0, $bytesRead)
            $writer.Close()
            
            $script:Manifest.metadata.split_archives += @{
                original_file = Split-Path -Leaf $FilePath
                chunk_file = Split-Path -Leaf $chunkFile
                chunk_index = $i
                chunk_size = $bytesRead
            }
        }
        
        $reader.Close()
        Remove-Item $FilePath -Force
        Write-Log "File split successfully into $chunks parts" -Level debug
    }
    catch {
        Write-Log "Failed to split file: ${_}" -Level error
        if ($reader) { $reader.Close() }
        if ($writer) { $writer.Close() }
        return $false
    }
    
    return $true
}

function Save-Manifest {
    $manifestFile = "$script:BackupRoot\manifest.json"
    
    # Calculate total backup size
    if (-not $DryRun) {
        $totalSize = 0
        Get-ChildItem -Path $script:BackupRoot -Recurse -File | ForEach-Object {
            $totalSize += $_.Length
        }
        $script:Manifest.metadata.total_size = $totalSize
    }
    
    $script:Manifest.completed = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
    
    if (-not $DryRun) {
        try {
            $script:Manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestFile -Encoding UTF8
            Write-Log "Saved manifest: $manifestFile" -Level debug
        }
        catch {
            Write-Log "Failed to save manifest: ${_}" -Level error
            return $false
        }
    }
    else {
        Write-Log "[DRY RUN] Would save manifest to: $manifestFile" -Level info
    }
    
    return $true
}

function Show-Summary {
    $duration = (Get-Date) - $script:StartTime
    
    Write-Host "`n" -NoNewline
    Write-Host "=== BACKUP SUMMARY ===" -ForegroundColor Green
    Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))"
    Write-Host "Containers: $($script:Manifest.containers.Count)"
    Write-Host "Images: $($script:Manifest.images.Count)"
    Write-Host "Snapshots: $($script:Manifest.snapshots.Count)"
    Write-Host "Volumes: $($script:Manifest.volumes.Count)"
    Write-Host "Bind Mounts: $($script:Manifest.binds.Count)"
    Write-Host "Networks: $($script:Manifest.networks.Count)"
    
    if (-not $DryRun) {
        $totalSizeMB = [Math]::Round($script:Manifest.metadata.total_size / 1MB, 2)
        Write-Host "Total Size: ${totalSizeMB}MB"
        Write-Host "Backup Location: $script:BackupRoot" -ForegroundColor Cyan
    }
    else {
        Write-Host "Mode: DRY RUN - No files were created" -ForegroundColor Yellow
    }
    
    Write-Host "=======================" -ForegroundColor Green
}



# Main execution
function Main {
    # Log entry to Main function
    try {
        "Entered Main function" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
    } catch { }
    
    # Show startup banner first
    try {
        Show-StartupBanner
        "Startup banner displayed" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
    } catch {
        try {
            "ERROR displaying startup banner: ${_}" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
        } catch { }
        Write-Host "Error displaying startup banner: ${_}" -ForegroundColor Red
    }
    
    # Initialize logging FIRST - before any other operations
    try {
        if (-not $LogFile) {
            $scriptDir = Split-Path -Parent $PSCommandPath
            $LogFile = Join-Path $scriptDir "backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        }
        $script:LogFile = $LogFile
        
        # Create log file and test write access
        "=== Docker Backup Script Started ===" | Out-File -FilePath $script:LogFile -Encoding UTF8 -Force
        Write-Log "Logging initialized: $script:LogFile" -Level info
        Write-Host "Log file: $script:LogFile" -ForegroundColor Gray
        
    } catch {
        Write-Host "CRITICAL ERROR: Failed to initialize logging: ${_}" -ForegroundColor Red
        Write-Host "This might be due to insufficient permissions or read-only media." -ForegroundColor Yellow
        Write-Host "Try running from a writable location or with administrator privileges." -ForegroundColor Yellow
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    if ($Help) {
        Show-Help
        return
    }
    
    if ($TestEnvironment) {
        Show-StartupBanner
        $testResult = Test-Environment
        if ($testResult) {
            exit 0
        } else {
            exit 1
        }
    }
    
    Write-Log "Starting Docker backup process..." -Level info
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)" -Level debug
    Write-Log "Script Path: $PSCommandPath" -Level debug
    Write-Log "Working Directory: $(Get-Location)" -Level debug
    Write-Log "Parameters: AllRunning=$AllRunning, AllContainers=$AllContainers, Include=$($Include -join ','), Exclude=$($Exclude -join ','), DryRun=$DryRun" -Level debug
    
    # If no parameters were provided and we're running interactively, offer a simple test
    if ($MyInvocation.Line -match '^\s*\.\s*\\.*backup\.ps1\s*$' -and -not $DryRun -and -not $Help) {
        Write-Host "No parameters provided. Would you like to:" -ForegroundColor Cyan
        Write-Host "  1. Run a dry-run test (recommended for first time)" -ForegroundColor White
        Write-Host "  2. Proceed with actual backup" -ForegroundColor White
        Write-Host "  3. Show help and examples" -ForegroundColor White
        Write-Host "  4. Exit" -ForegroundColor White
        Write-Host ""
        
        do {
            $choice = Read-Host "Enter your choice (1-4)"
            switch ($choice) {
                '1' { 
                    Write-Host "Running dry-run test..." -ForegroundColor Green
                    $DryRun = $true
                    break
                }
                '2' { 
                    Write-Host "Proceeding with actual backup..." -ForegroundColor Green
                    break
                }
                '3' { 
                    Show-Help
                    return
                }
                '4' { 
                    Write-Host "Exiting..." -ForegroundColor Gray
                    return
                }
                default { 
                    Write-Host "Invalid choice. Please enter 1, 2, 3, or 4." -ForegroundColor Red
                }
            }
        } while ($choice -notin @('1','2','3','4'))
    }
    
    # Check prerequisites with error handling
    try {
        Write-Log "Checking prerequisites..." -Level info
        if (-not (Test-Prerequisites)) {
            Write-Log "Prerequisites check failed" -Level error
            Write-Host "Press any key to exit..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
        Write-Log "Prerequisites check passed" -Level info
    } catch {
        Write-Log "Exception during prerequisites check: ${_}" -Level error
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    # Initialize backup directory with error handling
    try {
        Write-Log "Initializing backup directory..." -Level info
        if (-not (Initialize-BackupDirectory)) {
            Write-Log "Failed to initialize backup directory" -Level error
            Write-Host "Press any key to exit..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 1
        }
        Write-Log "Backup directory initialized successfully" -Level info
    } catch {
        Write-Log "Exception during backup directory initialization: ${_}" -Level error
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    # Get container list with error handling
    try {
        Write-Log "Getting container list..." -Level info
        $containers = Get-ContainerList
        if ($containers.Count -eq 0) {
            Write-Log "No containers found to backup" -Level warn
            Write-Host "No containers found to backup. Press any key to exit..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            exit 0
        }
        Write-Log "Found $($containers.Count) containers to process" -Level info
    } catch {
        Write-Log "Exception while getting container list: ${_}" -Level error
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    # Analyze container storage and get user choices
    Write-Log "Analyzing container storage configurations..." -Level info
    $containerAnalyses = @()
    
    foreach ($container in $containers) {
        $containerName = if ($container.Names) { $container.Names } else { $container.ID }
        Write-Log "Analyzing container: $containerName" -Level debug
        
        $details = Get-ContainerDetails $container
        if (-not $details) {
            Write-Log "Failed to get details for container: $containerName" -Level error
            continue
        }
        
        $storageAnalysis = Analyze-ContainerStorage $details
        $containerAnalyses += @{
            Container = $container
            Details = $details
            Storage = $storageAnalysis
        }
    }
    
    if ($containerAnalyses.Count -eq 0) {
        Write-Log "No containers to analyze" -Level error
        exit 1
    }
    
    # Show analysis and get user choices
    $hasEphemeralContainers = Show-ContainerAnalysis $containerAnalyses
    $userChoices = @{}
    
    if ($hasEphemeralContainers) {
        $userChoices = Get-UserBackupChoices $containerAnalyses
    } else {
        # All containers have persistent storage - use standard backup
        foreach ($analysis in $containerAnalyses) {
            $userChoices[$analysis.Container.Names] = 'standard'
        }
    }
    
    # Process each container based on user choices
    Write-Host "`n=== BACKUP EXECUTION ===" -ForegroundColor Cyan
    $success = $true
    
    foreach ($analysis in $containerAnalyses) {
        $container = $analysis.Container
        $details = $analysis.Details
        $storage = $analysis.Storage
        $containerName = $container.Names
        $choice = $userChoices[$containerName]
        
        if ($choice -eq 'skip') {
            Write-Log "Skipping container: $containerName (user choice)" -Level info
            continue
        }
        
        Write-Log "Processing container: $containerName (strategy: $choice)" -Level info
        
        # Handle different backup strategies
        if ($choice -eq 'snapshot') {
            # Create filesystem snapshot
            if ($Include -contains 'images') {
                if (-not (Export-ContainerSnapshot $details $script:BackupRoot)) {
                    $success = $false
                    continue
                }
            }
            
            # Still export configuration for snapshot containers
            if ($Include -contains 'configs') {
                if (-not (Export-ContainerConfig $details)) {
                    $success = $false
                }
            }
        }
        elseif ($choice -eq 'config-only') {
            # Export only configuration
            if ($Include -contains 'configs') {
                if (-not (Export-ContainerConfig $details)) {
                    $success = $false
                }
            }
            Write-Log "Configuration-only backup for container: $containerName" -Level info
        }
        else {
            # Standard backup (containers with persistent storage)
            
            # Export container configuration
            if ($Include -contains 'configs') {
                if (-not (Export-ContainerConfig $details)) {
                    $success = $false
                }
            }
            
            # Export container image
            if ($Include -contains 'images') {
                if (-not (Export-ContainerImage $details.Config.Image)) {
                    $success = $false
                }
            }
            
            # Export volumes and bind mounts
            if ($details.Mounts) {
                foreach ($mount in $details.Mounts) {
                    if ($mount.Type -eq 'volume' -and $Include -contains 'volumes') {
                        if (-not (Export-Volume $mount.Name)) {
                            $success = $false
                        }
                    }
                    elseif ($mount.Type -eq 'bind' -and $Include -contains 'binds') {
                        if (-not (Export-BindMount $mount.Source $mount.Destination)) {
                            $success = $false
                        }
                    }
                }
            }
        }
    }
    
    # Export networks
    if ($Include -contains 'networks') {
        if (-not (Export-Networks)) {
            $success = $false
        }
    }
    
    # Generate docker-compose
    if ($Include -contains 'compose') {
        if (-not (Generate-DockerCompose)) {
            $success = $false
        }
    }
    
    # Save manifest
    if (-not (Save-Manifest)) {
        $success = $false
    }
    
    # Show summary
    try {
        Show-Summary
    } catch {
        Write-Log "Exception while showing summary: ${_}" -Level error
        Write-Host "Error displaying summary: ${_}" -ForegroundColor Red
    }
    
    if ($success) {
        Write-Log "Backup completed successfully" -Level info
        Write-Host "`nBackup completed successfully!" -ForegroundColor Green
        if (-not $DryRun) {
            Write-Host "Press any key to exit..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        exit 0
    }
    else {
        Write-Log "Backup completed with errors" -Level error
        Write-Host "`nBackup completed with errors. Check the log file for details." -ForegroundColor Red
        Write-Host "Log file: $script:LogFile" -ForegroundColor Yellow
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
}



# Log before main execution
try {
    "About to execute Main function..." | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
} catch { }

# Execute main function with global error handling
try {
    Main
    
    # Log successful completion
    try {
        "Main function completed successfully" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
    } catch { }
    
} catch {
    $errorMsg = "CRITICAL ERROR: Unhandled exception in main execution: ${_}"
    Write-Host $errorMsg -ForegroundColor Red
    
    # Log to emergency log
    try {
        "CRITICAL ERROR in main execution: ${_}" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
        "Stack trace: $($_.ScriptStackTrace)" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
        "Error details: $($_.Exception | Out-String)" | Add-Content -Path $script:EmergencyLogFile -Encoding UTF8
    } catch { }
    
    # Try to log the error if logging is initialized
    try {
        if ($script:LogFile) {
            Write-Log $errorMsg -Level error
            Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level error
        }
    } catch {
        Write-Host "Could not write to log file: ${_}" -ForegroundColor Red
    }
    
    Write-Host "Emergency log file: $script:EmergencyLogFile" -ForegroundColor Cyan
    Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}