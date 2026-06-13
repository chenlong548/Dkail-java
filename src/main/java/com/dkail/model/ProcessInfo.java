﻿﻿﻿// Developer: chenlong548
package com.dkail.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProcessInfo {
    private int pid;
    private String name;
    private long memoryUsageBytes;
    private double cpuUsage;
}
