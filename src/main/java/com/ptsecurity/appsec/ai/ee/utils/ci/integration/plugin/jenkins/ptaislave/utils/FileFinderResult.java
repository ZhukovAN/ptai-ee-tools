package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.ptaislave.utils;

import hudson.FilePath;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.Serializable;

@AllArgsConstructor
public class FileFinderResult implements Serializable {

    @Getter
    private final FilePath[] files;
    @Getter
    private final FilePath[] directories;

}
