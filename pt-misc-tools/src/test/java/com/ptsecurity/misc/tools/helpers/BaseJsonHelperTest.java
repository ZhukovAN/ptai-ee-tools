package com.ptsecurity.misc.tools.helpers;

import com.ptsecurity.misc.tools.BaseTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BaseJsonHelperTest extends BaseTest {
    @Test
    @DisplayName("JSON macro replacement")
    public void replaceMacro() {
        String json = BaseJsonHelper.minimize("{ \"field\": \"value\" }");
        json = BaseJsonHelper.replaceMacro(json, (s) -> { return "Modified " + s; });
        assertEquals(json, BaseJsonHelper.minimize("{ \"field\": \"Modified value\" }"));
    }
}