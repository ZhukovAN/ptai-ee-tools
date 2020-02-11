package com.ptsecurity.appsec.ai.ee.utils.ci.integration.maven;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;

@Mojo(name = "ptaiSast")
public class SastMojo extends AbstractMojo {
    public void execute() throws MojoExecutionException {
        getLog().info("Hello, world");
    }
}