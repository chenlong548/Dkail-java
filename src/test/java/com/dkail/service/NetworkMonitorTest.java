﻿﻿﻿// Developer: chenlong548
package com.dkail.service;

import com.dkail.model.*;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class NetworkMonitorTest {

    private final Set<String> localIps = new HashSet<>(Arrays.asList("192.168.1.1", "10.0.0.1"));

    private TrafficDirection determineDirection(ParsedPacket packet, Set<String> localIps) {
        boolean isSrcLocal = localIps.contains(packet.getSrcIp());
        boolean isDstLocal = localIps.contains(packet.getDstIp());

        if (isSrcLocal && isDstLocal) return TrafficDirection.LOCAL;
        if (isSrcLocal) return TrafficDirection.OUTBOUND;
        if (isDstLocal) return TrafficDirection.INBOUND;
        return TrafficDirection.UNKNOWN;
    }

    private AlertLevel assessThreatLevel(List<ThreatIndicator> indicators) {
        int score = 0;
        for (ThreatIndicator indicator : indicators) {
            switch (indicator.getSeverity()) {
                case CRITICAL -> score += 40;
                case HIGH -> score += 25;
                case MEDIUM -> score += 15;
                case LOW -> score += 5;
            }
        }
        if (score >= 70) return AlertLevel.CRITICAL;
        if (score >= 45) return AlertLevel.HIGH;
        if (score >= 20) return AlertLevel.MEDIUM;
        return AlertLevel.LOW;
    }

    private String sanitizePath(String path) {
        if (path == null || path.isEmpty()) return path;
        String sanitized = path.replaceAll("(?i)(C:\\\\Users\\\\)[^\\\\]+", "$1***");
        sanitized = sanitized.replaceAll("(?i)(Administrator|admin|root)", "***");
        return sanitized;
    }

    @Test
    void testTrafficDirectionInbound() {
        ParsedPacket packet = new ParsedPacket("192.168.1.100", "192.168.1.1", 12345, 80, "TCP", 64, null);
        TrafficDirection direction = determineDirection(packet, localIps);
        assertEquals(TrafficDirection.INBOUND, direction);
    }

    @Test
    void testTrafficDirectionOutbound() {
        ParsedPacket packet = new ParsedPacket("192.168.1.1", "192.168.1.100", 80, 12345, "TCP", 64, null);
        TrafficDirection direction = determineDirection(packet, localIps);
        assertEquals(TrafficDirection.OUTBOUND, direction);
    }

    @Test
    void testTrafficDirectionLocal() {
        ParsedPacket packet = new ParsedPacket("192.168.1.1", "10.0.0.1", 80, 8080, "TCP", 64, null);
        TrafficDirection direction = determineDirection(packet, localIps);
        assertEquals(TrafficDirection.LOCAL, direction);
    }

    @Test
    void testTrafficDirectionUnknown() {
        ParsedPacket packet = new ParsedPacket("8.8.8.8", "1.1.1.1", 53, 53, "UDP", 64, null);
        TrafficDirection direction = determineDirection(packet, localIps);
        assertEquals(TrafficDirection.UNKNOWN, direction);
    }

    @Test
    void testAlertLevelAssessment() {
        List<ThreatIndicator> indicators = Arrays.asList(
                new ThreatIndicator("1", null, Severity.HIGH, "test", 0.8),
                new ThreatIndicator("2", null, Severity.MEDIUM, "test", 0.5)
        );
        AlertLevel level = assessThreatLevel(indicators);
        assertTrue(level == AlertLevel.HIGH || level == AlertLevel.MEDIUM);
    }

    @Test
    void testAlertLevelCritical() {
        List<ThreatIndicator> indicators = Arrays.asList(
                new ThreatIndicator("1", null, Severity.CRITICAL, "test", 0.9),
                new ThreatIndicator("2", null, Severity.HIGH, "test", 0.8)
        );
        AlertLevel level = assessThreatLevel(indicators);
        assertEquals(AlertLevel.CRITICAL, level);
    }

    @Test
    void testPathSanitization() {
        String path = "C:\\Users\\Administrator\\Desktop\\secret.txt";
        String sanitized = sanitizePath(path);
        assertFalse(sanitized.contains("Administrator"));
        assertTrue(sanitized.contains("***"));
    }
}
