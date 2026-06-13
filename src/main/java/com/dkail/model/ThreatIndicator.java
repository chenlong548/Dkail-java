﻿﻿﻿// Developer: chenlong548
package com.dkail.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ThreatIndicator {
    private String id;
    private ThreatCategory category;
    private Severity severity;
    private String description;
    private double confidence;
}
