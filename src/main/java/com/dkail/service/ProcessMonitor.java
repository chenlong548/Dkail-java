// Developer: chenlong548
package com.dkail.service;

import com.dkail.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ProcessMonitor implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(ProcessMonitor.class);

    private final SystemState state;
    private final Set<String> knownSuspicious = new HashSet<>();

    // PID -> {cpuTime, timestamp, name, memoryBytes}
    private final Map<Integer, Double> lastCpuTime = new ConcurrentHashMap<>();
    private final Map<Integer, Long> lastCpuTimestamp = new ConcurrentHashMap<>();
    private final Map<Integer, Double> cpuUsagePercent = new ConcurrentHashMap<>();
    private final Map<Integer, String> processNames = new ConcurrentHashMap<>();
    private final Map<Integer, Long> processMemory = new ConcurrentHashMap<>();

    public ProcessMonitor(SystemState state) {
        this.state = state;
        knownSuspicious.add("mimikatz.exe");
        knownSuspicious.add("nc.exe");
        knownSuspicious.add("cobaltstrike");
    }

    @Override
    public void run() {
        log.info("Starting process monitoring");

        while (state.getStatus().isMonitoring()) {
            try {
                sampleProcesses();
                syncToState();
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.info("Process monitor interrupted");
                break;
            } catch (Exception e) {
                log.error("Process monitor error: {}", e.getMessage());
            }
        }
    }

    /**
     * Sample process data via PowerShell.
     * CPU from Get-Process is total processor time in seconds (cumulative).
     * We compute CPU% = (delta_cpu_time / delta_wall_time) * 100
     */
    private void sampleProcesses() {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "powershell", "-NoProfile", "-Command",
                    "Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet64 | ConvertTo-Json -Compress"
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }
            process.waitFor();

            String json = output.toString().trim();
            if (json.isEmpty() || json.equals("[]") || json.equals("null")) return;

            long now = System.currentTimeMillis();
            Set<Integer> currentPids = new HashSet<>();

            // Parse JSON array
            String content = json;
            if (content.startsWith("[")) {
                content = content.substring(1, content.length() - 1);
            }

            String[] items = content.split("\\},\\s*\\{");
            for (String item : items) {
                try {
                    ParsedProc p = parseProcessJson(item);
                    if (p == null) continue;

                    currentPids.add(p.pid);
                    processNames.put(p.pid, p.name);
                    processMemory.put(p.pid, p.workingSet);

                    // Calculate CPU usage percentage
                    Double prevCpuTime = lastCpuTime.get(p.pid);
                    Long prevTimestamp = lastCpuTimestamp.get(p.pid);

                    if (prevCpuTime != null && prevTimestamp != null && p.cpuTime > prevCpuTime) {
                        double deltaCpu = p.cpuTime - prevCpuTime;
                        double deltaWall = (now - prevTimestamp) / 1000.0; // seconds
                        if (deltaWall > 0) {
                            // CPU% = (delta_cpu_time / delta_wall_time) / cpuCoreCount * 100
                            // Divide by core count so percentages represent share of total CPU,
                            // matching what Task Manager shows (all processes sum to total CPU%).
                            int cpuCores = Runtime.getRuntime().availableProcessors();
                            double usage = (deltaCpu / deltaWall) / cpuCores * 100.0;
                            cpuUsagePercent.put(p.pid, Math.min(usage, 100.0));
                        }
                    } else if (prevCpuTime == null) {
                        // First sample, no percentage yet
                        cpuUsagePercent.put(p.pid, 0.0);
                    }

                    lastCpuTime.put(p.pid, p.cpuTime);
                    lastCpuTimestamp.put(p.pid, now);

                    // Check threats
                    checkThreats(p.pid, p.name);

                } catch (Exception ignored) {}
            }

            // Clean up terminated processes
            lastCpuTime.keySet().retainAll(currentPids);
            lastCpuTimestamp.keySet().retainAll(currentPids);
            cpuUsagePercent.keySet().retainAll(currentPids);
            processNames.keySet().retainAll(currentPids);
            processMemory.keySet().retainAll(currentPids);

        } catch (Exception e) {
            log.error("Failed to sample processes: {}", e.getMessage());
        }
    }

    private ParsedProc parseProcessJson(String json) {
        try {
            String clean = json.replace("{", "").replace("}", "").trim();

            int pid = 0;
            String name = "";
            double cpuTime = 0.0;
            long workingSet = 0;

            String[] pairs = clean.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":", 2);
                if (kv.length != 2) continue;
                String key = kv[0].trim().replace("\"", "");
                String value = kv[1].trim();

                switch (key) {
                    case "Id" -> {
                        try { pid = Integer.parseInt(value); } catch (Exception ignored) {}
                    }
                    case "ProcessName" -> name = value.replace("\"", "");
                    case "CPU" -> {
                        // PowerShell returns null for system processes
                        if (!value.equals("null")) {
                            try { cpuTime = Double.parseDouble(value); } catch (Exception ignored) {}
                        }
                    }
                    case "WorkingSet64" -> {
                        if (!value.equals("null")) {
                            try { workingSet = Long.parseLong(value); } catch (Exception ignored) {}
                        }
                    }
                }
            }

            if (pid > 0 && !name.isEmpty()) {
                return new ParsedProc(pid, name, cpuTime, workingSet);
            }
        } catch (Exception ignored) {}
        return null;
    }

    private void checkThreats(int pid, String name) {
        String lowerName = name.toLowerCase();
        for (String suspicious : knownSuspicious) {
            if (lowerName.contains(suspicious.toLowerCase())) {
                Alert alert = new Alert(
                        UUID.randomUUID().toString(),
                        AlertLevel.HIGH,
                        String.format("Detected suspicious process: %s (PID: %d)", name, pid),
                        LocalDateTime.now()
                );
                state.getAlerts().add(alert);
                log.warn("THREAT DETECTED: suspicious process {} (PID: {})", name, pid);
                break;
            }
        }
    }

    private void syncToState() {
        List<ProcessSummary> summaries = new ArrayList<>();
        for (Map.Entry<Integer, String> entry : processNames.entrySet()) {
            int pid = entry.getKey();
            String name = entry.getValue();
            double cpu = cpuUsagePercent.getOrDefault(pid, 0.0);
            long mem = processMemory.getOrDefault(pid, 0L);

            summaries.add(new ProcessSummary(
                    pid,
                    name,
                    cpu,
                    mem / (1024.0 * 1024.0)
            ));
        }

        // Sort by CPU usage descending, take top 100
        summaries.sort((a, b) -> Double.compare(b.getCpuUsage(), a.getCpuUsage()));
        if (summaries.size() > 100) {
            summaries = summaries.subList(0, 100);
        }

        state.getProcesses().clear();
        state.getProcesses().addAll(summaries);
    }

    private static class ParsedProc {
        int pid;
        String name;
        double cpuTime;   // cumulative CPU seconds from PowerShell
        long workingSet;  // bytes

        ParsedProc(int pid, String name, double cpuTime, long workingSet) {
            this.pid = pid;
            this.name = name;
            this.cpuTime = cpuTime;
            this.workingSet = workingSet;
        }
    }
}
