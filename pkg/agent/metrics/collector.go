package metrics

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Collector implements the MetricsCollector interface for full Go
// CPU collection now uses vmstat-style calculation:
// - 1-second sampling interval between readings
// - Includes all CPU time fields in total calculation
// - Uses only idle field (not idle + iowait) for idle calculation
// - Formula: 100 * (1 - (idle_diff / total_diff))
type Collector struct {
	// Sampling configuration
	SampleCount    int           // Number of samples to take for averaging
	SampleInterval time.Duration // Interval between samples
}

// NewCollector creates a new metrics collector with default sampling settings
func NewCollector() types.MetricsCollector {
	return &Collector{
		SampleCount:    2,               // Take 2 samples (like vmstat)
		SampleInterval: 1 * time.Second, // 1 second between samples (like vmstat)
	}
}

// CollectSystemMetrics collects system metrics (CPU, memory, disk usage)
func (c *Collector) CollectSystemMetrics() (*types.SystemMetrics, error) {
	metrics := &types.SystemMetrics{
		Custom: make(map[string]interface{}),
	}

	// Collect CPU usage with sampling
	cpuPct, err := c.getCPUUsageSampled()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU usage: %w", err)
	}
	metrics.CPUPercent = cpuPct

	// Collect memory usage with sampling
	memPct, err := c.getMemoryUsageSampled()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory usage: %w", err)
	}
	metrics.MemPercent = memPct

	// Collect swap usage (no sampling needed as it's typically stable)
	swapPct, err := c.getSwapUsage()
	if err != nil {
		// Swap is optional, don't fail if it's not available
		metrics.SwapPercent = 0
	} else {
		metrics.SwapPercent = swapPct
	}

	// Collect disk usage (no sampling needed as it's typically stable)
	diskPct, err := c.getDiskUsage("/")
	if err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}
	metrics.DiskPercent = diskPct

	return metrics, nil
}

// CollectCustomMetrics collects custom metrics using shell commands
func (c *Collector) CollectCustomMetrics(commands map[string]string) (map[string]interface{}, error) {
	metrics := make(map[string]interface{})

	for name, command := range commands {
		if command == "" {
			continue
		}

		// Execute the command
		cmd := exec.Command("sh", "-c", command)
		output, err := cmd.Output()
		if err != nil {
			// Log error but continue with other metrics
			metrics[name] = fmt.Sprintf("error: %v", err)
			continue
		}

		// Clean up the output
		result := strings.TrimSpace(string(output))

		// Try to parse as number, otherwise keep as string
		if floatVal, err := strconv.ParseFloat(result, 64); err == nil {
			metrics[name] = floatVal
		} else if intVal, err := strconv.ParseInt(result, 10, 64); err == nil {
			metrics[name] = intVal
		} else {
			metrics[name] = result
		}
	}

	return metrics, nil
}

// DetermineSystemStatus determines the overall system status based on metrics
func (c *Collector) DetermineSystemStatus(cpuPct, memPct, diskPct float64, containersHealthy bool) string {
	// Define thresholds
	const (
		cpuWarningThreshold   = 80.0
		cpuCriticalThreshold  = 95.0
		memWarningThreshold   = 80.0
		memCriticalThreshold  = 95.0
		diskWarningThreshold  = 85.0
		diskCriticalThreshold = 95.0
	)

	// Check for critical conditions
	if cpuPct >= cpuCriticalThreshold || memPct >= memCriticalThreshold || diskPct >= diskCriticalThreshold {
		return "degraded"
	}

	// Check if containers are unhealthy
	if !containersHealthy {
		return "degraded"
	}

	// Check for warning conditions
	if cpuPct >= cpuWarningThreshold || memPct >= memWarningThreshold || diskPct >= diskWarningThreshold {
		return "degraded"
	}

	return "normal"
}

// getCPUUsage gets the current CPU usage percentage using vmstat-style calculation
func (c *Collector) getCPUUsage() (float64, error) {
	// Read /proc/stat twice with a delay to calculate CPU usage (like vmstat)
	stat1, err := c.readCPUStat()
	if err != nil {
		return 0, err
	}

	// Wait 1 second like vmstat does
	time.Sleep(1 * time.Second)

	stat2, err := c.readCPUStat()
	if err != nil {
		return 0, err
	}

	// Calculate CPU usage percentage using vmstat formula
	// vmstat uses: 100 * (1 - (idle_diff / total_diff))
	totalDiff := stat2.total - stat1.total
	idleDiff := stat2.idle - stat1.idle

	if totalDiff == 0 {
		return 0, nil
	}

	// vmstat-style calculation: idle is just the idle field, not idle + iowait
	cpuUsage := 100.0 * (1.0 - float64(idleDiff)/float64(totalDiff))
	return cpuUsage, nil
}

// getCPUUsageSampled gets the average CPU usage over multiple samples (vmstat-style)
func (c *Collector) getCPUUsageSampled() (float64, error) {
	// For vmstat-style, we typically just take 2 samples with 1-second interval
	// The getCPUUsage() function already includes the 1-second delay
	if c.SampleCount == 2 {
		// Take two samples with the built-in delay
		usage1, err := c.getCPUUsage()
		if err != nil {
			return 0, err
		}

		usage2, err := c.getCPUUsage()
		if err != nil {
			return 0, err
		}

		// Return average of the two samples
		return (usage1 + usage2) / 2.0, nil
	}

	// Fallback to original sampling method for other configurations
	var totalUsage float64
	var validSamples int

	for i := 0; i < c.SampleCount; i++ {
		usage, err := c.getCPUUsage()
		if err != nil {
			// If we get an error on the first sample, return it
			if i == 0 {
				return 0, err
			}
			// For subsequent samples, just skip this sample
			continue
		}

		totalUsage += usage
		validSamples++

		// Don't sleep after the last sample
		if i < c.SampleCount-1 {
			time.Sleep(c.SampleInterval)
		}
	}

	if validSamples == 0 {
		return 0, fmt.Errorf("no valid CPU samples collected")
	}

	return totalUsage / float64(validSamples), nil
}

// getMemoryUsageSampled gets the average memory usage over multiple samples
func (c *Collector) getMemoryUsageSampled() (float64, error) {
	var totalUsage float64
	var validSamples int

	for i := 0; i < c.SampleCount; i++ {
		usage, err := c.getMemoryUsage()
		if err != nil {
			// If we get an error on the first sample, return it
			if i == 0 {
				return 0, err
			}
			// For subsequent samples, just skip this sample
			continue
		}

		totalUsage += usage
		validSamples++

		// Don't sleep after the last sample
		if i < c.SampleCount-1 {
			time.Sleep(c.SampleInterval)
		}
	}

	if validSamples == 0 {
		return 0, fmt.Errorf("no valid memory samples collected")
	}

	return totalUsage / float64(validSamples), nil
}

// cpuStat represents CPU statistics from /proc/stat (vmstat-style)
type cpuStat struct {
	total uint64 // Total CPU time (all fields)
	idle  uint64 // Just the idle field (not idle + iowait like before)
}

// readCPUStat reads CPU statistics from /proc/stat
func (c *Collector) readCPUStat() (*cpuStat, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read /proc/stat")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return nil, fmt.Errorf("invalid /proc/stat format")
	}

	// Parse CPU times: user, nice, system, idle, iowait, irq, softirq, steal
	// Note: idle and iowait are both considered "idle" time in Linux
	var times []uint64
	for i := 1; i < len(fields) && i <= 8; i++ {
		val, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CPU time: %w", err)
		}
		times = append(times, val)
	}

	if len(times) < 4 {
		return nil, fmt.Errorf("insufficient CPU time fields")
	}

	// Calculate total and idle time using vmstat approach
	// vmstat includes ALL fields in total, but only uses idle field for idle calculation
	user := times[0]   // user
	nice := times[1]   // nice
	system := times[2] // system
	idle := times[3]   // idle
	iowait := times[4] // iowait (5th field, index 4)

	// Calculate total time (sum of all available fields)
	total := user + nice + system + idle
	if len(times) > 4 {
		total += iowait // iowait
	}
	if len(times) > 5 {
		total += times[5] // irq
	}
	if len(times) > 6 {
		total += times[6] // softirq
	}
	if len(times) > 7 {
		total += times[7] // steal
	}
	if len(times) > 8 {
		total += times[8] // guest
	}
	if len(times) > 9 {
		total += times[9] // guest_nice
	}

	// vmstat uses just the idle field (not idle + iowait)
	return &cpuStat{
		total: total,
		idle:  idle,
	}, nil
}

// getMemoryUsage gets the current memory usage percentage
func (c *Collector) getMemoryUsage() (float64, error) {
	// First try to get container memory if we're in a container
	if containerMem, err := c.getContainerMemoryUsage(); err == nil {
		return containerMem, nil
	}

	// Fall back to host memory via /proc/meminfo
	return c.getHostMemoryUsage()
}

// getContainerMemoryUsage gets memory usage from cgroup v2 if available
func (c *Collector) getContainerMemoryUsage() (float64, error) {
	// Check if we're in a container by looking for cgroup v2 memory files
	memoryCurrentPath := "/sys/fs/cgroup/memory.current"
	memoryMaxPath := "/sys/fs/cgroup/memory.max"

	// Check if cgroup v2 memory files exist
	if _, err := os.Stat(memoryCurrentPath); os.IsNotExist(err) {
		return 0, fmt.Errorf("not in container or cgroup v2 not available")
	}
	if _, err := os.Stat(memoryMaxPath); os.IsNotExist(err) {
		return 0, fmt.Errorf("cgroup v2 memory.max not found")
	}

	// Read current memory usage
	currentBytes, err := c.readCgroupValue(memoryCurrentPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read memory.current: %w", err)
	}

	// Read memory limit
	maxBytes, err := c.readCgroupValue(memoryMaxPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read memory.max: %w", err)
	}

	// If max is "max" (no limit), we can't calculate percentage
	if maxBytes == 0 {
		return 0, fmt.Errorf("no memory limit set in container")
	}

	// Calculate percentage
	usagePercent := 100.0 * float64(currentBytes) / float64(maxBytes)
	return usagePercent, nil
}

// readCgroupValue reads a numeric value from a cgroup file
func (c *Collector) readCgroupValue(path string) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, fmt.Errorf("empty file")
	}

	value := strings.TrimSpace(scanner.Text())

	// Handle "max" value (no limit)
	if value == "max" {
		return 0, nil
	}

	// Parse as uint64
	val, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse value: %w", err)
	}

	return val, nil
}

// getHostMemoryUsage gets memory usage from /proc/meminfo with fallback support
func (c *Collector) getHostMemoryUsage() (float64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var memTotal, memAvailable uint64
	var memFree, buffers, cached, sReclaimable, shmem uint64
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "MemTotal:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				memTotal = val
			}
		case "MemAvailable:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				memAvailable = val
			}
		case "MemFree:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				memFree = val
			}
		case "Buffers:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				buffers = val
			}
		case "Cached:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				cached = val
			}
		case "SReclaimable:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				sReclaimable = val
			}
		case "Shmem:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				shmem = val
			}
		}
	}

	if memTotal == 0 {
		return 0, fmt.Errorf("failed to read memory total")
	}

	// Use modern MemAvailable if available (preferred method)
	if memAvailable > 0 {
		memUsed := memTotal - memAvailable
		memUsagePercent := 100.0 * float64(memUsed) / float64(memTotal)
		return memUsagePercent, nil
	}

	// Fallback for older kernels without MemAvailable
	// approxAvailable = MemFree + Buffers + Cached + SReclaimable - Shmem
	approxAvailable := memFree + buffers + cached + sReclaimable
	if shmem > approxAvailable {
		// Prevent underflow
		approxAvailable = 0
	} else {
		approxAvailable -= shmem
	}

	memUsed := memTotal - approxAvailable
	memUsagePercent := 100.0 * float64(memUsed) / float64(memTotal)

	return memUsagePercent, nil
}

// getSwapUsage gets the swap usage percentage
func (c *Collector) getSwapUsage() (float64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var swapTotal, swapFree uint64
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "SwapTotal:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				swapTotal = val
			}
		case "SwapFree:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				swapFree = val
			}
		}
	}

	// If no swap, return 0
	if swapTotal == 0 {
		return 0, nil
	}

	swapUsed := swapTotal - swapFree
	swapUsagePercent := 100.0 * float64(swapUsed) / float64(swapTotal)

	return swapUsagePercent, nil
}

// getDiskUsage gets the disk usage percentage for the specified path
func (c *Collector) getDiskUsage(path string) (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, fmt.Errorf("failed to get disk stats: %w", err)
	}

	// Calculate disk usage
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free

	if total == 0 {
		return 0, nil
	}

	usagePercent := 100.0 * float64(used) / float64(total)
	return usagePercent, nil
}
