package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations.LocalAstOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli.operations.LocalFileOperations;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.AstJob;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.nio.file.Path;

@Getter
@Setter
@SuperBuilder
public class CliAstJob extends AstJob {
    protected Path input;
    protected String includes;
    protected String excludes;
    protected Path output;

    @Override
    public void init() {
        super.init();
        astOps = LocalAstOperations.builder()
                .owner(this)
                .build();
        fileOps = LocalFileOperations.builder()
                .owner(this)
                .build();
    }
}
