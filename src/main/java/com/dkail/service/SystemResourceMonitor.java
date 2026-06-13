﻿﻿﻿// Developer: chenlong548
package com.dkail.service;

import com.dkail.model.Resources;
import com.dkail.model.SystemState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;

public class SystemResourceMonitor implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SystemResourceMonitor.class);

    private final SystemState state;
    private final OperatingSystemMXBean osBean;

    // 网络流量速率计算：记录上次采样值
    private long lastNetInBytes = -1;
    private long lastNetOutBytes = -1;
    private long lastSampleTime = -1;

    public SystemResourceMonitor(SystemState state) {
        this.state = state;
        this.osBean = ManagementFactory.getOperatingSystemMXBean();
    }

    @Override
    public void run() {
        log.info("Starting system resource monitor...");

        // Warm up CPU load measurement
        invokeMethod(osBean, "getSystemCpuLoad");

        while (state.getStatus().isMonitoring()) {
            try {
                double cpuUsage = calculateCpuUsage();
                double memoryUsage = calculateMemoryUsage();
                double diskUsage = calculateDiskUsage();

                // 计算网络速率 (bytes/s)
                long[] netRate = calculateNetworkRate();

                Resources resources = state.getResources();
                resources.setCpuUsage(cpuUsage);
                resources.setMemoryUsage(memoryUsage);
                resources.setDiskUsage(diskUsage);
                resources.setNetworkIn(netRate[0]);
                resources.setNetworkOut(netRate[1]);

                log.debug("Resources updated - CPU: {}%, Memory: {}%, Disk: {}%, NetIn: {} B/s, NetOut: {} B/s",
                        String.format("%.1f", cpuUsage),
                        String.format("%.1f", memoryUsage),
                        String.format("%.1f", diskUsage),
                        netRate[0], netRate[1]);

                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.info("System resource monitor interrupted");
                break;
            } catch (Exception e) {
                log.error("System resource monitor error: {}", e.getMessage());
            }
        }
    }

    /**
     * 通过WMI获取网络接口字节计数，计算两次采样间的速率
     * Win32_PerfRawData_Tcpip_NetworkInterface 的 BytesReceivedPersec/BytesSentPersec
     * 是累计原始计数器值，需要两次采样差值除以时间得到真实速率
     * 返回 [inBytesPerSec, outBytesPerSec]
     */
    private long[] calculateNetworkRate() {
        long[] result = {0, 0};
        try {
            // 获取活跃网络接口（非回环、已发送字节>0）的累计字节计数
            ProcessBuilder pb = new ProcessBuilder(
                    "powershell", "-NoProfile", "-Command",
                    "$nics = Get-CimInstance -ClassName Win32_PerfRawData_Tcpip_NetworkInterface | " +
                    "Where-Object { $_.BytesSentPersec -gt 0 -and $_.Name -notlike '*Loopback*' -and $_.Name -notlike '*Teredo*' }; " +
                    "$totalIn = ($nics | Measure-Object -Property BytesReceivedPersec -Sum).Sum; " +
                    "$totalOut = ($nics | Measure-Object -Property BytesSentPersec -Sum).Sum; " +
                    "Write-Output $totalIn; Write-Output $totalOut"
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();

            long bytesReceived = -1;
            long bytesSent = -1;

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                int lineNum = 0;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    try {
                        if (lineNum == 0) {
                            bytesReceived = Long.parseLong(line);
                        } else {
                            bytesSent = Long.parseLong(line);
                        }
                        lineNum++;
                    } catch (NumberFormatException ignored) {}
                }
            }
            process.waitFor();

            if (bytesReceived >= 0 && bytesSent >= 0) {
                long now = System.currentTimeMillis();

                if (lastNetInBytes >= 0 && lastSampleTime > 0) {
                    double elapsed = (now - lastSampleTime) / 1000.0;
                    if (elapsed > 0) {
                        result[0] = (long) ((bytesReceived - lastNetInBytes) / elapsed);
                        result[1] = (long) ((bytesSent - lastNetOutBytes) / elapsed);
                        // 速率不可能为负（计数器重置除外）
                        if (result[0] < 0) result[0] = 0;
                        if (result[1] < 0) result[1] = 0;
                    }
                }

                lastNetInBytes = bytesReceived;
                lastNetOutBytes = bytesSent;
                lastSampleTime = now;
            }
        } catch (Exception e) {
            log.debug("Failed to get network stats: {}", e.getMessage());
        }
        return result;
    }

    private double calculateCpuUsage() {
        Object load = invokeMethod(osBean, "getSystemCpuLoad");
        if (load instanceof Double d && d >= 0) {
            return d * 100.0;
        }
        return 0.0;
    }

    private double calculateMemoryUsage() {
        Object total = invokeMethod(osBean, "getTotalPhysicalMemorySize");
        Object free = invokeMethod(osBean, "getFreePhysicalMemorySize");
        if (total instanceof Long t && free instanceof Long f && t > 0) {
            return (double) (t - f) / t * 100.0;
        }
        return 0.0;
    }

    private double calculateDiskUsage() {
        try {
            File root = new File(System.getProperty("os.name").toLowerCase().contains("win") ? "C:\\" : "/");
            long total = root.getTotalSpace();
            long free = root.getFreeSpace();
            if (total <= 0) return 0.0;
            return (double) (total - free) / total * 100.0;
        } catch (Exception e) {
            return 0.0;
        }
    }

    private static Object invokeMethod(Object obj, String methodName) {
        try {
            var method = obj.getClass().getMethod(methodName);
            method.setAccessible(true);
            return method.invoke(obj);
        } catch (Exception e) {
            return null;
        }
    }
}
