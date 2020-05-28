package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain;

import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.ArrayList;

@NoArgsConstructor
public class Transfers extends ArrayList<Transfer> implements Serializable {
    public Transfers addTransfer(final Transfer transfer) {
        this.add(transfer);
        return this;
    }
}
