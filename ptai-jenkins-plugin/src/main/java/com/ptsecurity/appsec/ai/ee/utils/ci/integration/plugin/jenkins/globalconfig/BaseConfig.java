package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.globalconfig;

import hudson.model.AbstractDescribableImpl;
import lombok.Getter;

import java.io.Serializable;

public abstract class BaseConfig extends AbstractDescribableImpl<BaseConfig> implements Cloneable, Serializable {
    @Getter
    protected String configName;
}
