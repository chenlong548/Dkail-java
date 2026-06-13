﻿﻿﻿// Developer: chenlong548
package com.dkail.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProcessSummary {
    private int pid;
    private String name;
    private double cpuUsage;
    private double memoryUsageMb;
}
