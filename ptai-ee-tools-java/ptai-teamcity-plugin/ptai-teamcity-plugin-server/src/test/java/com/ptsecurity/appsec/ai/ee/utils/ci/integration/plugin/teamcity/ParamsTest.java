package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

class ParamsTest {
    @Test
    void listAllParams() {
        Arrays.stream(Params.class.getDeclaredFields())
                .filter(f -> Modifier.isPublic(f.getModifiers()))
                .filter(f -> Modifier.isStatic(f.getModifiers()))
                .filter(f -> Modifier.isFinal(f.getModifiers()))
                .map(Field::getName).forEach(n -> System.out.println(Defaults.value(n)));
                // .collect(Collectors.toList());

        List<String> defaults = Arrays.stream(Defaults.class.getDeclaredFields())
                .filter(f -> Modifier.isPublic(f.getModifiers()))
                .filter(f -> Modifier.isStatic(f.getModifiers()))
                .filter(f -> Modifier.isFinal(f.getModifiers()))
                .map(Field::getName)
                .collect(Collectors.toList());
    }

}