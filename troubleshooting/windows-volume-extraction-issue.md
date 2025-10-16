# Windows Volume Extraction Issue

## Root Problem

**Issue**: Volume extraction fails on Windows when restoring Docker backups containing persistent volumes.

**Core Symptom**: Files successfully copy (exit code 0) but don't actually exist in the target container, causing volume restoration to fail.

**Affected Containers**: Only containers with persistent volumes (e.g., n8n with n8n_data volume). Containers using snapshot strategy (e.g., Metabase) work fine because they don't require volume extraction.

## Technical Details

### What Works
- **Metabase restoration**: Uses snapshot strategy (`docker commit` → `docker save` → `docker load`)
- **Backup creation**: All backup operations work correctly
- **Network fixes**: Successfully resolved network export contamination issues
- **Integrity checks**: Backup verification passes completely

### What Fails
- **Volume extraction**: Files appear to copy but don't exist in target container
- **Container creation**: Also fails due to separate Docker command parsing bug (GitHub issue #4)

## Attempted Solutions & Results

### 1. Enhanced Docker cp with Retry Mechanism (FAILED)
**Commits**: `80abe39`, `c89525e`
- **Approach**: 3-attempt retry with Windows path handling and verification
- **Result**: `docker cp` reports success (exit code 0) but file not transferred
- **Issue**: `docker exec` verification failed because container was stopped
- **Status**: Fixed verification method but core issue remained

### 2. Remove Retry Mechanism (PARTIAL SUCCESS)
**Commit**: `c998ca6`
- **Approach**: Single-attempt volume-based transfer as primary method
- **Result**: Cleaner error handling, but same core failure
- **User Feedback**: Retry mechanisms are not best practice

### 3. Parent Directory Mounting (FAILED)
**Commit**: `b133c68`
- **Approach**: Mount parent directory instead of file directly
- **Command**: `-v "D:\path\to\volumes":/source:ro` then `cp /source/file.tar.gz`
- **Result**: Same error - `cp: omitting directory '/source/n8n_data.tar.gz'`
- **Issue**: Windows files still appear as directories to Linux containers

### 4. Temporary Simple Path Copy (FAILED)
**Commit**: `a0c233b`
- **Approach**: Copy to `%TEMP%\docker-restore\archive.tar.gz` first, then mount
- **Result**: Both copy operations succeed (exit code 0) but file missing in final container
- **Progress**: Got further than previous attempts but still fails verification

## Current Status

### What We Know
1. **Docker cp silent failure**: Reports success but doesn't transfer files on Windows
2. **Volume mounting issues**: Windows files appear as directories to Linux containers
3. **Container verification**: File transfers appear successful but files don't exist
4. **Workaround necessity**: Standard Docker operations don't work reliably on Windows

### What We Don't Know
1. **Why temp path approach fails**: Both copies succeed but file disappears
2. **Docker Desktop specifics**: How Windows filesystem translation affects containers
3. **Alternative approaches**: What Docker documentation actually recommends for this scenario

## Lessons Learned

### Avoid These Pitfalls
1. **Don't use retry mechanisms** - They mask root causes and aren't best practice
2. **Don't assume docker cp works reliably on Windows** - Silent failures are common
3. **Don't trust exit codes alone** - Always verify file existence after operations
4. **Don't mount Windows files directly** - Filesystem translation issues persist

### Successful Patterns
1. **Use busybox** - Docker documentation standard, don't change without reason
2. **Volume-based approaches** - More reliable than direct docker cp
3. **Comprehensive logging** - Essential for debugging Windows-specific issues
4. **Proper cleanup** - Always clean up temporary resources

## Next Steps

### Recommended Approach
1. **Follow Docker documentation exactly** - Use standard `docker cp` as documented
2. **Avoid complex workarounds** - Start with simplest documented approach
3. **Test incrementally** - Verify each step works before adding complexity
4. **Focus on verification** - Ensure files actually exist where expected

### Alternative Strategies to Consider
1. **Direct docker cp** - As documented, without workarounds
2. **Stdin/stdout streaming** - Using tar streams instead of file operations
3. **Different extraction containers** - Maybe the stopped container approach is the issue
4. **Windows-specific Docker commands** - PowerShell or cmd-based alternatives

## Related Issues
- **GitHub Issue #4**: Docker command parsing bug (separate from volume extraction)
- **Network export bug**: Fixed in commits `e0d3527` and `cc8b4c8`
- **Empty networks.json**: Fixed in same commits

## File References
- **Latest failing log**: `restore-20251016-121518.log`
- **Successful backup log**: `backup-20251015-171154.log`
- **Test volume**: `n8n_data.tar.gz` (561.36MB)