﻿﻿﻿// Developer: chenlong548
package com.dkail.service;

import com.dkail.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class NetworkMonitor implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(NetworkMonitor.class);

    private final SystemState state;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final Set<String> localIpAddresses;
    private Object pcapHandle; // PcapHandle, 用Object避免类加载失败
    private boolean pcapAvailable = false;

    public NetworkMonitor(SystemState state) {
        this.state = state;
        this.localIpAddresses = getLocalIpAddresses();
        // 检测pcap4j是否可用
        try {
            Class.forName("org.pcap4j.core.Pcaps");
            pcapAvailable = true;
            log.info("Pcap4J库已加载，网络捕获功能可用");
        } catch (ClassNotFoundException e) {
            log.warn("Pcap4J库未找到，将使用netstat模式获取网络连接信息");
            pcapAvailable = false;
        }
    }

    @Override
    public void run() {
        log.info("Starting network monitor...");

        if (pcapAvailable) {
            runPcapMode();
        } else {
            runNetstatMode();
        }
    }

    /**
     * Pcap4J抓包模式
     */
    private void runPcapMode() {
        try {
            org.pcap4j.core.PcapNetworkInterface nif = detectNetworkInterface();
            if (nif == null) {
                log.warn("未检测到可用的网络接口，切换到netstat模式");
                runNetstatMode();
                return;
            }

            log.info("使用网络接口: {}", nif.getName());

            org.pcap4j.core.PcapHandle handle = nif.openLive(
                    65536,
                    org.pcap4j.core.PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    10
            );
            handle.setFilter("ip", org.pcap4j.core.BpfProgram.BpfCompileMode.OPTIMIZE);
            this.pcapHandle = handle;

            log.info("网络数据包捕获已启动");

            while (running.get() && state.getStatus().isMonitoring()) {
                try {
                    org.pcap4j.packet.Packet packet = handle.getNextPacket();
                    if (packet != null) {
                        ParsedPacket parsed = parsePacket(packet);
                        if (parsed != null) {
                            TrafficDirection direction = determineDirection(parsed);
                            updateStatistics(parsed, direction);
                            updateConnectionInfo(parsed);
                        }
                    }
                } catch (org.pcap4j.core.NotOpenException e) {
                    if (running.get()) {
                        log.warn("捕获数据包时连接已关闭");
                    }
                } catch (Exception e) {
                    // 超时等正常异常，忽略
                }
            }
        } catch (Exception e) {
            log.error("Pcap4J模式启动失败，切换到netstat模式: {}", e.getMessage());
            runNetstatMode();
        }
    }

    /**
     * netstat回退模式 - 不依赖Npcap
     */
    private void runNetstatMode() {
        log.info("使用netstat模式监控网络连接");
        while (running.get() && state.getStatus().isMonitoring()) {
            try {
                updateConnectionsFromNetstat();
                // 模拟数据包计数增长
                state.setPacketCount(state.getPacketCount() + 1);
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("netstat模式异常: {}", e.getMessage());
            }
        }
    }

    /**
     * 通过netstat获取网络连接信息
     */
    private void updateConnectionsFromNetstat() {
        List<ConnectionInfo> newConnections = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("netstat", "-ano", "-p", "TCP");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()))) {
                String line;
                boolean headerSkipped = false;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!headerSkipped) {
                        if (line.startsWith("Proto")) {
                            headerSkipped = true;
                        }
                        continue;
                    }
                    if (line.isEmpty()) continue;

                    String[] parts = line.split("\\s+");
                    if (parts.length >= 4) {
                        try {
                            ConnectionInfo conn = parseNetstatLine(parts);
                            if (conn != null) {
                                newConnections.add(conn);
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
            process.waitFor();
        } catch (Exception e) {
            log.debug("获取netstat连接信息失败: {}", e.getMessage());
        }

        if (!newConnections.isEmpty()) {
            state.getConnections().clear();
            state.getConnections().addAll(newConnections.stream().limit(200).toList());
        }
    }

    private ConnectionInfo parseNetstatLine(String[] parts) {
        try {
            String protocol = parts[0];
            String local = parts[1];
            String remote = parts[2];
            String connState = parts.length > 3 ? parts[3] : "";

            // Skip listening/waiting states and wildcard addresses
            if (remote.equals("*:*") || remote.equals("*:0")) return null;
            if (connState.equalsIgnoreCase("LISTENING")) return null;

            String[] localParts = local.split(":");
            String[] remoteParts = remote.split(":");

            int localPort = 0;
            int remotePort = 0;
            try { localPort = Math.abs(Integer.parseInt(localParts[localParts.length - 1])); } catch (Exception ignored) {}
            try { remotePort = Math.abs(Integer.parseInt(remoteParts[remoteParts.length - 1])); } catch (Exception ignored) {}

            ConnectionInfo conn = new ConnectionInfo();
            conn.setProtocol(protocol.toUpperCase());
            conn.setLocalIp(localParts[0]);
            conn.setLocalPort(localPort);
            conn.setRemoteIp(remoteParts[0]);
            conn.setRemotePort(remotePort);
            conn.setState(connState);
            conn.setProcessName("");

            return conn;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 自动检测网络接口
     */
    private org.pcap4j.core.PcapNetworkInterface detectNetworkInterface() {
        try {
            List<org.pcap4j.core.PcapNetworkInterface> devices = org.pcap4j.core.Pcaps.findAllDevs();
            if (devices == null || devices.isEmpty()) {
                return null;
            }
            for (org.pcap4j.core.PcapNetworkInterface nif : devices) {
                if (nif.isLoopBack()) continue;
                for (var addr : nif.getAddresses()) {
                    if (addr.getAddress() instanceof Inet4Address) {
                        return nif;
                    }
                }
            }
        } catch (Exception e) {
            log.error("检测网络接口失败: {}", e.getMessage());
        }
        return null;
    }

    /**
     * 解析数据包
     */
    private ParsedPacket parsePacket(org.pcap4j.packet.Packet packet) {
        try {
            org.pcap4j.packet.EthernetPacket ethernet = packet.get(org.pcap4j.packet.EthernetPacket.class);
            if (ethernet == null) return null;

            org.pcap4j.packet.IpPacket ipPacket = packet.get(org.pcap4j.packet.IpV4Packet.class);
            if (ipPacket == null) {
                ipPacket = packet.get(org.pcap4j.packet.IpPacket.class);
            }
            if (ipPacket == null) return null;

            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
            int packetLen = packet.length();

            org.pcap4j.packet.TcpPacket tcpPacket = packet.get(org.pcap4j.packet.TcpPacket.class);
            if (tcpPacket != null) {
                return new ParsedPacket(
                        srcIp, dstIp,
                        tcpPacket.getHeader().getSrcPort().value(),
                        tcpPacket.getHeader().getDstPort().value(),
                        "TCP", packetLen, LocalDateTime.now()
                );
            }

            org.pcap4j.packet.UdpPacket udpPacket = packet.get(org.pcap4j.packet.UdpPacket.class);
            if (udpPacket != null) {
                return new ParsedPacket(
                        srcIp, dstIp,
                        udpPacket.getHeader().getSrcPort().value(),
                        udpPacket.getHeader().getDstPort().value(),
                        "UDP", packetLen, LocalDateTime.now()
                );
            }

            return new ParsedPacket(srcIp, dstIp, 0, 0, "OTHER", packetLen, LocalDateTime.now());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 判断流量方向
     */
    private TrafficDirection determineDirection(ParsedPacket parsed) {
        boolean isSrcLocal = localIpAddresses.contains(parsed.getSrcIp());
        boolean isDstLocal = localIpAddresses.contains(parsed.getDstIp());

        if (isSrcLocal && isDstLocal) return TrafficDirection.LOCAL;
        if (isSrcLocal) return TrafficDirection.OUTBOUND;
        if (isDstLocal) return TrafficDirection.INBOUND;
        return TrafficDirection.UNKNOWN;
    }

    /**
     * 更新统计信息 - 仅更新包计数和字节总数，网络速率由SystemResourceMonitor计算
     */
    private synchronized void updateStatistics(ParsedPacket parsed, TrafficDirection direction) {
        state.setPacketCount(state.getPacketCount() + 1);
        state.setByteCount(state.getByteCount() + parsed.getLength());
    }

    /**
     * 更新连接信息
     */
    private void updateConnectionInfo(ParsedPacket parsed) {
        if (!"TCP".equals(parsed.getProtocol()) && !"UDP".equals(parsed.getProtocol())) return;

        // 避免连接列表过长
        if (state.getConnections().size() > 500) {
            state.getConnections().subList(0, 200).clear();
        }

        ConnectionInfo conn = new ConnectionInfo();
        conn.setLocalIp(parsed.getSrcIp());
        conn.setLocalPort(parsed.getSrcPort());
        conn.setRemoteIp(parsed.getDstIp());
        conn.setRemotePort(parsed.getDstPort());
        conn.setProtocol(parsed.getProtocol());
        conn.setState("ESTABLISHED");
        conn.setProcessName("");

        state.getConnections().add(conn);
    }

    /**
     * 获取本机所有IPv4地址
     */
    private Set<String> getLocalIpAddresses() {
        Set<String> ips = new HashSet<>();
        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            while (nets != null && nets.hasMoreElements()) {
                NetworkInterface netIf = nets.nextElement();
                Enumeration<InetAddress> inetAddresses = netIf.getInetAddresses();
                while (inetAddresses.hasMoreElements()) {
                    InetAddress addr = inetAddresses.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        ips.add(addr.getHostAddress());
                    }
                }
            }
        } catch (SocketException e) {
            log.error("获取本机IP地址失败: {}", e.getMessage());
        }
        return ips;
    }

    public void stop() {
        running.set(false);
        if (pcapHandle instanceof org.pcap4j.core.PcapHandle handle) {
            if (handle.isOpen()) {
                handle.close();
            }
        }
        log.info("网络监控已停止");
    }
}
