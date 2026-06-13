﻿﻿﻿// Developer: chenlong548
package com.dkail;

import com.dkail.model.SystemState;
import com.dkail.service.NetworkMonitor;
import com.dkail.service.ProcessMonitor;
import com.dkail.service.SystemResourceMonitor;
import com.dkail.service.ThreatDetector;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@SpringBootApplication
public class DkailApplication {

    private ExecutorService executor;

    public static void main(String[] args) {
        SpringApplication.run(DkailApplication.class, args);
    }

    @Bean
    public SystemState systemState() {
        return new SystemState();
    }

    @Bean
    public ApplicationListener<ApplicationReadyEvent> startMonitors(
            SystemState systemState) {
        return event -> {
            System.out.println("==========================================");
            System.out.println("  DKail Security Monitor v1.0.0");
            System.out.println("  :: Real-time Network Threat Detection ::");
            System.out.println("==========================================");

            executor = Executors.newFixedThreadPool(4);
            executor.submit(new NetworkMonitor(systemState));
            executor.submit(new ProcessMonitor(systemState));
            executor.submit(new SystemResourceMonitor(systemState));
            executor.submit(new ThreatDetector(systemState));

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                systemState.getStatus().setMonitoring(false);
                executor.shutdownNow();
                System.out.println("DKail Security Monitor stopped.");
            }));
        };
    }
}
