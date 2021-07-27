package com.ptsecurity.appsec.ai.ee.utils.ci.integration.api;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface VersionRange {
    /**
     * @return Minimum supported PT AI API version. If empty than any version greater than this
     */
    int[] min() default {};

    /**
     * @return Maximum supported PT AI API version. If empty than any version less than this
     */
    int[] max() default {};
}
