package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.utils;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfer;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.domain.Transfers;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.exceptions.PtaiClientException;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

class FileCollectorTest {

    @Test
    void collect() {
        try {
            Transfers transfers = new Transfers();
            // transfersJson.add(Transfer.builder().includes("**/*").build());
            transfers.add(Transfer.builder().includes("src/main/java/app01/**").build());
            transfers.add(Transfer.builder().includes("src/main/webapp/index.jsp").build());
            transfers.add(Transfer.builder().includes("pom.xml").build());
            FileCollector collector = new FileCollector(transfers, null);
            File srcFolder = new File("src\\test\\resources\\src\\app01");
            File destFile = File.createTempFile("PTAI_", ".zip");
            collector.collect(srcFolder, destFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}