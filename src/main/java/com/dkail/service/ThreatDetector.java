﻿﻿﻿// Developer: chenlong548
package com.dkail.service;

import com.dkail.model.Alert;
import com.dkail.model.AlertLevel;
import com.dkail.model.ProcessSummary;
import com.dkail.model.SystemState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;

public class ThreatDetector implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(ThreatDetector.class);

    private static final Map<String, String> SUSPICIOUS_SIGNATURES = new LinkedHashMap<>();

    static {
        SUSPICIOUS_SIGNATURES.put("mimikatz", "凭据窃取工具");
        SUSPICIOUS_SIGNATURES.put("nc.exe", "网络工具Netcat");
        SUSPICIOUS_SIGNATURES.put("nishang", "PowerShell攻击框架");
        SUSPICIOUS_SIGNATURES.put("cobaltstrike", "C2框架");
        SUSPICIOUS_SIGNATURES.put("metasploit", "渗透测试框架");
    }

    private final SystemState state;
    private final Set<String> alertedProcesses = Collections.synchronizedSet(new HashSet<>());

    public ThreatDetector(SystemState state) {
        this.state = state;
    }

    @Override
    public void run() {
        log.info("Starting threat detection...");

        while (state.getStatus().isMonitoring()) {
            try {
                checkProcessThreats();
                checkNetworkAnomalies();
                cleanupOldAlerts();
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.info("Threat detector interrupted");
                break;
            } catch (Exception e) {
                log.error("Threat detector error: {}", e.getMessage());
            }
        }
    }

    private void checkProcessThreats() {
        List<ProcessSummary> processesCopy;
        synchronized (state.getProcesses()) {
            processesCopy = new ArrayList<>(state.getProcesses());
        }

        for (ProcessSummary process : processesCopy) {
            if (process.getName() == null) continue;
            String lowerName = process.getName().toLowerCase();

            for (Map.Entry<String, String> entry : SUSPICIOUS_SIGNATURES.entrySet()) {
                if (lowerName.contains(entry.getKey().toLowerCase())) {
                    // 避免对同一进程重复告警
                    String alertKey = process.getPid() + ":" + entry.getKey();
                    if (alertedProcesses.contains(alertKey)) break;

                    Alert alert = new Alert(
                            UUID.randomUUID().toString(),
                            AlertLevel.HIGH,
                            String.format("检测到可疑进程: %s (PID: %d) - %s",
                                    process.getName(), process.getPid(), entry.getValue()),
                            LocalDateTime.now()
                    );
                    state.getAlerts().add(alert);
                    alertedProcesses.add(alertKey);
                    log.warn("THREAT DETECTED: {} (PID: {}) - {}", process.getName(), process.getPid(), entry.getValue());
                    break;
                }
            }
        }
    }

    private void checkNetworkAnomalies() {
        int connectionCount = state.getConnections().size();
        if (connectionCount > 1000) {
            Alert alert = new Alert(
                    UUID.randomUUID().toString(),
                    AlertLevel.MEDIUM,
                    String.format("网络连接数异常: %d 个连接", connectionCount),
                    LocalDateTime.now()
            );
            state.getAlerts().add(alert);
            log.warn("Anomaly detected: {} network connections", connectionCount);
        }

        long totalBytes = state.getByteCount();
        if (totalBytes > 100 * 1024 * 1024L) {
            Alert alert = new Alert(
                    UUID.randomUUID().toString(),
                    AlertLevel.MEDIUM,
                    String.format("网络流量异常: 已传输 %d MB 数据", totalBytes / (1024 * 1024)),
                    LocalDateTime.now()
            );
            state.getAlerts().add(alert);
            log.warn("Anomaly detected: high traffic volume {} MB", totalBytes / (1024 * 1024));
        }
    }

    private void cleanupOldAlerts() {
        synchronized (state.getAlerts()) {
            while (state.getAlerts().size() > 100) {
                state.getAlerts().remove(0);
            }
        }
    }
}
