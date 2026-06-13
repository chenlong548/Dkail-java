﻿// Developer: chenlong548
package com.dkail.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ConnectionInfo {
    private String localIp;
    private int localPort;
    private String remoteIp;
    private int remotePort;
    private String protocol;
    private String state;
    private String processName;
}
