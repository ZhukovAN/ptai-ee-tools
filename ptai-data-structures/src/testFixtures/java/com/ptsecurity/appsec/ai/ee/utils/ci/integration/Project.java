package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.util.UUID;

@Getter
@Setter
@SuperBuilder
public class Project extends ProjectTemplate {
    protected UUID id;
}
