﻿﻿﻿// Developer: chenlong548
package com.dkail.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ParsedPacket {
    private String srcIp;
    private String dstIp;
    private int srcPort;
    private int dstPort;
    private String protocol;
    private int length;
    private LocalDateTime timestamp;
}
