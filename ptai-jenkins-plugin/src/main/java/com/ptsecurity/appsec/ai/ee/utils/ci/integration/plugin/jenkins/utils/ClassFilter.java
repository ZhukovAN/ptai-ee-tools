package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.utils;

import hudson.Extension;
import jenkins.security.CustomClassFilter;

/**
 * Utility class thst supports Jenkins integration tests from IntelliJ IDEA IDE. Starting with 2.102 Jenkins
 * do support JEP-200. That means that Jenkins will reject (de)serialization of class instances that aren't
 * explicitly whitelisted. For HPI-packed plugin that's OK: its manifest file contains
 * Jenkins-ClassFilter-Whitelisted property
 * (see last item here: https://www.jenkins.io/blog/2018/01/13/jep-200/#making-plugins-compatible-with-jenkins-2-102-or-above).
 * For unit tests executed from command line shell that's OK too: ClassFilterImpl's isBlacklisted method
 * also calls isLocationWhitelisted that checks class names and where they are located. It supports unit testing
 * as one of the checks compares class file location with /target/classes/ folder so 'gradlew test' command
 * succeeds. But this fails during test execution from IntelliJ IDEA as that IDE outputs to out/production/classes
 * that aren't recognized by ClassFilterImpl. So we need to use @Extension annotation to debug Jenkins
 * unit tests from IDE.
 */
@Extension
public class ClassFilter implements CustomClassFilter {
    @Override
    public Boolean permits(Class<?> c) {
        return permits(c.getName());
    }

    @Override
    public Boolean permits(String name) {
        return name.startsWith("com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.") ? true : null;
    }
}