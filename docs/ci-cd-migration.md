# CI/CD Pipeline Migration Guide

This guide explains how to migrate your existing CI/CD pipeline to support musl cross-compilation for all architectures.

## What's Changed

### New Build Capabilities
- **musl static compilation** for maximum portability
- **All architecture support**: x86_64, aarch64, armv7l, armv6l
- **Both dynamic and static builds** for each architecture
- **Enhanced install script** with fallback logic

### Architecture Matrix
The new pipeline builds **16 total binaries**:

#### Agent Binaries (8)
- `streamdeploy-agent-linux-amd64` (dynamic)
- `streamdeploy-agent-linux-arm64` (dynamic)
- `streamdeploy-agent-linux-armv7l` (dynamic)
- `streamdeploy-agent-linux-armv6l` (dynamic)
- `streamdeploy-agent-linux-amd64-musl` (static)
- `streamdeploy-agent-linux-arm64-musl` (static)
- `streamdeploy-agent-linux-armv7l-musl` (static)
- `streamdeploy-agent-linux-armv6l-musl` (static)

#### Installer Binaries (8)
- `streamdeploy-installer-linux-amd64` (dynamic)
- `streamdeploy-installer-linux-arm64` (dynamic)
- `streamdeploy-installer-linux-armv7l` (dynamic)
- `streamdeploy-installer-linux-armv6l` (dynamic)
- `streamdeploy-installer-linux-amd64-musl` (static)
- `streamdeploy-installer-linux-arm64-musl` (static)
- `streamdeploy-installer-linux-armv7l-musl` (static)
- `streamdeploy-installer-linux-armv6l-musl` (static)

## Migration Steps

### 1. Replace Your Current Workflow

**Option A: Complete Replacement**
```bash
# Backup your current workflow
cp .github/workflows/build.yml .github/workflows/build.yml.backup

# Replace with new musl-enabled workflow
cp .github/workflows/build-musl.yml .github/workflows/build.yml
```

**Option B: Gradual Migration**
```bash
# Keep both workflows temporarily
# Rename current workflow
mv .github/workflows/build.yml .github/workflows/build-legacy.yml

# Use new workflow
mv .github/workflows/build-musl.yml .github/workflows/build.yml
```

### 2. Update Your Release Process

The new pipeline automatically:
- Builds all 16 binaries
- Uploads them as GitHub release assets
- Creates an enhanced install script with fallback logic

### 3. Test the New Pipeline

```bash
# Test locally first
cd agent
./build.sh --musl --arch aarch64 --clean

cd ../install
./build.sh --musl --arch aarch64 --clean

# Verify binaries
file agent/streamdeploy-agent-aarch64-musl
ldd agent/streamdeploy-agent-aarch64-musl
```

### 4. Update Documentation

Update your documentation to mention:
- musl static binaries for maximum portability
- Support for ARM32 (armv7l, armv6l) architectures
- Enhanced install script with automatic fallback

## Key Benefits

### 1. Maximum Portability
- musl static binaries run on any Linux system
- No dependency on system libraries
- Perfect for containers and embedded systems

### 2. Complete Architecture Coverage
- x86_64: Intel/AMD 64-bit
- aarch64: ARM 64-bit (Jetson, Raspberry Pi 4+, Apple Silicon)
- armv7l: ARM 32-bit hard float (Raspberry Pi 3)
- armv6l: ARM 32-bit soft float (older Raspberry Pi)

### 3. Smart Install Script
- Automatically detects architecture
- Prefers musl static binaries by default
- Falls back to dynamic binaries if needed
- Builds from source as last resort

### 4. Enhanced User Experience
```bash
# Users can now install on any supported architecture
curl -fsSL https://raw.githubusercontent.com/StreamDeploy/streamdeploy-agent/main/install.sh | sudo bash -s -- --token "your-token"

# Or prefer dynamic binaries
curl -fsSL https://raw.githubusercontent.com/StreamDeploy/streamdeploy-agent/main/install.sh | sudo bash -s -- --token "your-token" --no-musl
```

## Performance Considerations

### Build Time
- **16 parallel builds** instead of 2
- Each build takes ~5-10 minutes
- Total pipeline time: ~15-20 minutes (vs ~10 minutes before)

### Binary Sizes
- **Dynamic binaries**: ~2-5 MB
- **musl static binaries**: ~8-15 MB
- **Total release size**: ~200-300 MB (vs ~20 MB before)

### Storage
- GitHub releases will be larger
- Consider using GitHub's LFS if needed
- Archive old releases periodically

## Rollback Plan

If you need to rollback:

```bash
# Restore original workflow
mv .github/workflows/build.yml .github/workflows/build-musl.yml
mv .github/workflows/build-legacy.yml .github/workflows/build.yml

# Or disable the new workflow
mv .github/workflows/build.yml .github/workflows/build-musl.yml.disabled
```

## Monitoring

### Key Metrics to Watch
1. **Build success rate** - Should be >95%
2. **Build time** - Should complete within 30 minutes
3. **Binary sizes** - Monitor for unexpected growth
4. **User adoption** - Track which binary types users prefer

### Common Issues
1. **Cross-compilation failures** - Usually toolchain issues
2. **musl build failures** - Usually dependency issues
3. **ARM32 build failures** - Usually toolchain compatibility

## Next Steps

1. **Test the new pipeline** on a feature branch
2. **Update your documentation** to mention new capabilities
3. **Monitor the first few releases** for any issues
4. **Consider deprecating old binaries** after 6 months
5. **Gather user feedback** on binary preferences

## Support

If you encounter issues:
1. Check the build logs for specific errors
2. Test builds locally with the new scripts
3. Verify toolchain installation
4. Check GitHub Actions runner resources

The new pipeline provides significantly more flexibility and portability while maintaining backward compatibility through the enhanced install script.
