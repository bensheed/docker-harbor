# Docker Harbor

**Complete Docker Container Backup & Restore Solution**

A PowerShell-based tool for comprehensive Docker environment backup and restoration, designed for both development and production use cases.

## Key Features

### Universal Container Support
- **Smart Storage Detection** - Automatically detects containers with volumes, bind mounts, or filesystem-only storage
- **Filesystem Snapshots** - Captures ALL data from containers without persistent storage (perfect for databases like Metabase, MongoDB, etc.)
- **Interactive Mode** - User-friendly prompts guide you through backup decisions
- **Selective Backup** - Choose specific containers or backup all running/stopped containers

### Complete Environment Backup
- **Container Images** - Full image backup with `docker save`
- **Named Volumes** - Complete volume contents with compression
- **Bind Mounts** - Host directory backup and restoration
- **Networks** - Custom network configurations
- **Container Configs** - Runtime specifications, environment variables, ports, labels
- **Docker Compose** - Auto-generated compose files for easy restoration

### Advanced Features
- **Encryption** - AES-256 encryption for sensitive data
- **Compression** - ZIP compression with configurable options
- **Split Archives** - Auto-split for FAT32 compatibility (>4GB files)
- **Checksums** - SHA-256 verification for data integrity
- **Dry Run Mode** - Preview operations without making changes
- **Detailed Logging** - Comprehensive logging with multiple verbosity levels

### Restoration Capabilities
- **Intelligent Restore** - Automatically uses snapshots when available
- **Port Conflict Resolution** - Auto-remap or keep original ports
- **Name Collision Handling** - Suffix support to avoid conflicts
- **Selective Restore** - Choose specific containers to restore
- **Custom Bind Paths** - Restore to different host directories

## Quick Start

### Backup All Running Containers
```powershell
.\backup.ps1
```

### Backup with Specific Options
```powershell
# Backup only images and volumes
.\backup.ps1 --include images,volumes

# Encrypted backup
.\backup.ps1 --encrypt zip-aes256 --passphrase "your-secret"

# Preview what would be backed up
.\backup.ps1 --dry-run
```

### Restore from Backup
```powershell
# Restore latest backup
.\restore.ps1

# Restore specific backup with name suffix
.\restore.ps1 --backup-root "C:\backups\20241015-143022" --name-suffix "-restored"

# Restore only specific containers
.\restore.ps1 --select-containers "web,database"
```

## Container Storage Scenarios

### Containers with Persistent Storage
- **Volumes & Bind Mounts** - Standard backup of external storage
- **Automatic Detection** - No user intervention required

### Containers without Persistent Storage
When containers store data in their filesystem (like Metabase, some databases):
- **[A] Filesystem Snapshot** - Captures ALL container data (recommended)
- **[B] Configuration Only** - Backup settings, not data
- **[C] Skip Container** - Exclude from backup

## Requirements

- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core)
- **Docker Desktop** or Docker Engine
- **Administrator privileges** (for execution policy management)

## File Structure

```
docker-backup/
├── 20241015-143022/           # Timestamped backup
│   ├── configs/               # Container configurations
│   ├── images/                # Container images (.tar)
│   ├── volumes/               # Volume contents (.tar.gz)
│   ├── snapshots/             # Filesystem snapshots (.tar)
│   ├── binds/                 # Bind mount contents
│   ├── compose/               # Generated docker-compose.yaml
│   ├── networks.json          # Network configurations
│   └── manifest.json          # Backup metadata & checksums
```

## Advanced Usage

### Environment Testing
```powershell
.\backup.ps1 --test-environment
```

### Custom Output Location
```powershell
.\backup.ps1 --output-root "E:\docker-backups"
```

### Exclude Components
```powershell
.\backup.ps1 --exclude binds,networks
```

### Restore with Port Remapping
```powershell
.\restore.ps1 --port-strategy auto-remap
```

## Use Cases

- **Development Environment Backup** - Save complete dev setups
- **Production Migration** - Move containers between hosts
- **Disaster Recovery** - Full environment restoration
- **Container Archival** - Long-term storage of container states
- **Testing & Staging** - Clone production environments

## License

MIT License - see [LICENSE](LICENSE) file for details.