// Developer: chenlong548
package com.dkail.controller;

import com.dkail.model.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@CrossOrigin(origins = "*")
public class ApiController {

    private final SystemState systemState;

    public ApiController(SystemState systemState) {
        this.systemState = systemState;
    }

    /**
     * GET /health - 健康检查
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    /**
     * GET /status - 系统状态
     * 前端期望: {network_monitor_active, process_monitor_active, threat_detection_active, alert_count, uptime}
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> response = new HashMap<>();
        response.put("network_monitor_active", true);
        response.put("process_monitor_active", true);
        response.put("threat_detection_active", true);
        response.put("alert_count", systemState.getAlerts().size());

        // uptime: 运行秒数
        LocalDateTime startTime = systemState.getStatus().getStartTime();
        if (startTime != null) {
            response.put("uptime", Duration.between(startTime, LocalDateTime.now()).getSeconds());
        } else {
            response.put("uptime", 0);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * GET /alerts - 告警列表
     * 前端期望: {alerts: [{id, timestamp, alert_type, severity, source, description, details}], count}
     */
    @GetMapping("/alerts")
    public ResponseEntity<Map<String, Object>> getAlerts() {
        List<Alert> alertsCopy;
        synchronized (systemState.getAlerts()) {
            alertsCopy = new ArrayList<>(systemState.getAlerts());
        }

        List<Map<String, Object>> alertList = new ArrayList<>();
        for (int i = 0; i < alertsCopy.size(); i++) {
            Alert a = alertsCopy.get(i);
            Map<String, Object> alertMap = new HashMap<>();
            alertMap.put("id", i + 1);
            alertMap.put("timestamp", a.getTimestamp() != null ? a.getTimestamp().toString() : "");
            alertMap.put("alert_type", mapAlertLevelToType(a.getLevel()));
            alertMap.put("severity", mapAlertLevelToSeverity(a.getLevel()));
            alertMap.put("source", "system");
            alertMap.put("description", a.getMessage() != null ? a.getMessage() : "");
            alertMap.put("details", new HashMap<String, Object>());
            alertList.add(alertMap);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("alerts", alertList);
        response.put("count", alertList.size());

        return ResponseEntity.ok(response);
    }

    /**
     * GET /processes - 进程列表
     * 前端期望: {processes: [{pid, name, path, cpu_usage, memory_usage}], count}
     */
    @GetMapping("/processes")
    public ResponseEntity<Map<String, Object>> getProcesses() {
        List<ProcessSummary> processesCopy;
        synchronized (systemState.getProcesses()) {
            processesCopy = new ArrayList<>(systemState.getProcesses());
        }

        List<Map<String, Object>> processList = processesCopy.stream()
                .limit(100)
                .map(p -> {
                    Map<String, Object> proc = new HashMap<>();
                    proc.put("pid", p.getPid());
                    proc.put("name", p.getName() != null ? p.getName() : "");
                    proc.put("path", "");
                    proc.put("cpu_usage", p.getCpuUsage());
                    proc.put("memory_usage", p.getMemoryUsageMb());
                    return proc;
                })
                .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("processes", processList);
        response.put("count", processList.size());

        return ResponseEntity.ok(response);
    }

    /**
     * GET /network - 网络连接和统计
     * 前端期望: {connections: [{local_addr, remote_addr, protocol, state}], packet_count, byte_count}
     */
    @GetMapping("/network")
    public ResponseEntity<Map<String, Object>> getNetwork() {
        List<ConnectionInfo> connectionsCopy;
        synchronized (systemState.getConnections()) {
            connectionsCopy = new ArrayList<>(systemState.getConnections());
        }

        List<Map<String, Object>> connList = connectionsCopy.stream()
                .limit(200)
                .map(c -> {
                    Map<String, Object> conn = new HashMap<>();
                    conn.put("local_addr", c.getLocalIp() + ":" + c.getLocalPort());
                    conn.put("remote_addr", c.getRemoteIp() + ":" + c.getRemotePort());
                    conn.put("protocol", c.getProtocol() != null ? c.getProtocol() : "");
                    conn.put("state", c.getState() != null ? c.getState() : "");
                    return conn;
                })
                .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("connections", connList);
        response.put("packet_count", systemState.getPacketCount());
        response.put("byte_count", systemState.getByteCount());

        return ResponseEntity.ok(response);
    }

    /**
     * GET /resources - 系统资源
     * 前端期望: {cpu_usage, memory_usage, disk_usage, network_in, network_out} (数值类型)
     */
    @GetMapping("/resources")
    public ResponseEntity<Map<String, Object>> getResources() {
        Resources res = systemState.getResources();

        Map<String, Object> response = new HashMap<>();
        response.put("cpu_usage", res.getCpuUsage());
        response.put("memory_usage", res.getMemoryUsage());
        response.put("disk_usage", res.getDiskUsage());
        response.put("network_in", res.getNetworkIn());
        response.put("network_out", res.getNetworkOut());

        return ResponseEntity.ok(response);
    }

    // ===== 辅助方法 =====

    private String mapAlertLevelToType(AlertLevel level) {
        if (level == null) return "SystemAnomaly";
        return switch (level) {
            case CRITICAL -> "MalwareDetected";
            case HIGH -> "SuspiciousActivity";
            case MEDIUM -> "NetworkAnomaly";
            case LOW -> "ProcessAnomaly";
            case INFO -> "SystemAnomaly";
        };
    }

    private String mapAlertLevelToSeverity(AlertLevel level) {
        if (level == null) return "Low";
        return switch (level) {
            case CRITICAL -> "Critical";
            case HIGH -> "High";
            case MEDIUM -> "Medium";
            case LOW, INFO -> "Low";
        };
    }
}
