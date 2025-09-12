package metrics

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

// Collector implements the MetricsCollector interface for full Go
type Collector struct{}

// NewCollector creates a new metrics collector
func NewCollector() types.MetricsCollector {
	return &Collector{}
}

// CollectSystemMetrics collects system metrics (CPU, memory, disk usage)
func (c *Collector) CollectSystemMetrics() (*types.SystemMetrics, error) {
	metrics := &types.SystemMetrics{
		Custom: make(map[string]interface{}),
	}

	// Collect CPU usage
	cpuPct, err := c.getCPUUsage()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU usage: %w", err)
	}
	metrics.CPUPercent = cpuPct

	// Collect memory usage
	memPct, err := c.getMemoryUsage()
	if err != nil {
		return nil, fmt.Errorf("failed to get memory usage: %w", err)
	}
	metrics.MemPercent = memPct

	// Collect disk usage
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

// getCPUUsage gets the current CPU usage percentage
func (c *Collector) getCPUUsage() (float64, error) {
	// Read /proc/stat twice with a small delay to calculate CPU usage
	stat1, err := c.readCPUStat()
	if err != nil {
		return 0, err
	}

	// Small delay
	// time.Sleep(100 * time.Millisecond)

	stat2, err := c.readCPUStat()
	if err != nil {
		return 0, err
	}

	// Calculate CPU usage percentage
	totalDiff := stat2.total - stat1.total
	idleDiff := stat2.idle - stat1.idle

	if totalDiff == 0 {
		return 0, nil
	}

	cpuUsage := 100.0 * (1.0 - float64(idleDiff)/float64(totalDiff))
	return cpuUsage, nil
}

// cpuStat represents CPU statistics from /proc/stat
type cpuStat struct {
	total uint64
	idle  uint64
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

	// Calculate total and idle time
	var total uint64
	for _, time := range times {
		total += time
	}

	idle := times[3] // idle time is the 4th field

	return &cpuStat{
		total: total,
		idle:  idle,
	}, nil
}

// getMemoryUsage gets the current memory usage percentage
func (c *Collector) getMemoryUsage() (float64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var memTotal, memAvailable uint64
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
		}
	}

	if memTotal == 0 {
		return 0, fmt.Errorf("failed to read memory total")
	}

	memUsed := memTotal - memAvailable
	memUsagePercent := 100.0 * float64(memUsed) / float64(memTotal)

	return memUsagePercent, nil
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
