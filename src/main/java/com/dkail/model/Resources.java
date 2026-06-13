﻿﻿﻿// Developer: chenlong548
package com.dkail.model;

import lombok.Data;

@Data
public class Resources {
    private double cpuUsage;
    private double memoryUsage;
    private double diskUsage;
    private long networkIn;
    private long networkOut;
}
