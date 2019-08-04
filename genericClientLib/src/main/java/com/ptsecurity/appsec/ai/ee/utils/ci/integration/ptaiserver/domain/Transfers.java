package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils.FileCollector;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.compress.archivers.ArchiveException;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
public class Transfers extends ArrayList<Transfer> implements Serializable {
    public Transfers addTransfer(final Transfer transfer) {
        this.add(transfer);
        return this;
    }
}
