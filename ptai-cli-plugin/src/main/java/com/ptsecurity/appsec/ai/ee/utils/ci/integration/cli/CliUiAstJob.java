package com.ptsecurity.appsec.ai.ee.utils.ci.integration.cli;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.operations.UiAstJobSetupOperationsImpl;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Setter
@SuperBuilder
public class CliUiAstJob extends GenericCliAstJob {
    @Override
    protected void init() throws GenericException {
        super.init();
        setupOps = UiAstJobSetupOperationsImpl.builder()
                .owner(this)
                .build();
    }
}
