﻿﻿﻿// Developer: chenlong548
package com.dkail.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void testGetStatusEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity("/api/status", Map.class);
        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody());
        assertEquals("running", response.getBody().get("status"));
    }

    @Test
    void testGetResourcesEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity("/api/resources", Map.class);
        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody());
        double cpuUsage = Double.parseDouble((String) response.getBody().get("cpu_usage"));
        assertTrue(cpuUsage >= 0.0 && cpuUsage <= 100.0);
    }

    @Test
    void testGetProcessesEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity("/api/processes", Map.class);
        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody().get("processes"));
    }

    @Test
    void testGetAlertsEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity("/api/alerts", Map.class);
        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody().get("alerts"));
    }

    @Test
    void testGetConnectionsEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity("/api/connections", Map.class);
        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody().get("connections"));
    }

    @Test
    void testGetNetworkStatsEndpoint() {
        ResponseEntity<Map> response = restTemplate.getForEntity("/api/network/stats", Map.class);
        assertEquals(200, response.getStatusCodeValue());
        assertNotNull(response.getBody().get("packet_count"));
    }
}
