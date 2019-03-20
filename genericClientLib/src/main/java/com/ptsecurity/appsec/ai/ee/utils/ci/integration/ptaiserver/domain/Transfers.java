package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
public class Transfers extends ArrayList<Transfer> {
    public Transfers addTransfer(final Transfer transfer) {
        this.add(transfer);
        return this;
    }
}
