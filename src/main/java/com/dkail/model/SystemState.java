﻿﻿﻿// Developer: chenlong548
package com.dkail.model;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

@Data
public class SystemState {
    private SystemStatus status = new SystemStatus(true, LocalDateTime.now());
    private Resources resources = new Resources();
    private List<ProcessSummary> processes = Collections.synchronizedList(new java.util.ArrayList<>());
    private List<ConnectionInfo> connections = Collections.synchronizedList(new java.util.ArrayList<>());
    private List<Alert> alerts = Collections.synchronizedList(new java.util.ArrayList<>());
    private long packetCount;
    private long byteCount;
}
