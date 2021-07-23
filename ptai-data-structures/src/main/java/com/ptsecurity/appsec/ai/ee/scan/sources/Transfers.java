package com.ptsecurity.appsec.ai.ee.scan.sources;

import lombok.NoArgsConstructor;
import lombok.NonNull;

import java.io.Serializable;
import java.util.ArrayList;

@NoArgsConstructor
public class Transfers extends ArrayList<Transfer> implements Serializable {
    public Transfers addTransfer(@NonNull final Transfer transfer) {
        this.add(transfer);
        return this;
    }
}
