package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.jenkins.charts;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ptsecurity.appsec.ai.ee.scan.progress.Stage;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseIssue;
import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.VulnerabilityIssue;
import lombok.SneakyThrows;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.StringUtils;
import org.joor.Reflect;

import java.awt.*;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class BaseJsonChartDataModel {
    public static final Map<BaseIssue.Level, Integer> LEVEL_COLORS = new HashMap<>();
    public static final Map<BaseIssue.Type, Integer> TYPE_COLORS = new HashMap<>();
    public static final Map<BaseIssue.ApprovalState, Integer> APPROVAL_COLORS = new HashMap<>();
    public static final Map<Boolean, Integer> SUSPECTED_COLORS = new HashMap<>();
    public static final Map<VulnerabilityIssue.ScanMode, Integer> SCANMODE_COLORS = new HashMap<>();
    public static final Map<Stage, Integer> SCANSTAGE_COLORS = new HashMap<>();

    static {
        LEVEL_COLORS.put(BaseIssue.Level.HIGH, 0xf57962);
        LEVEL_COLORS.put(BaseIssue.Level.MEDIUM, 0xf9ad37);
        LEVEL_COLORS.put(BaseIssue.Level.LOW, 0x66cc99);
        LEVEL_COLORS.put(BaseIssue.Level.POTENTIAL, 0x8cb5e1);
        LEVEL_COLORS.put(BaseIssue.Level.NONE, 0xb0b0b0);

        TYPE_COLORS.put(BaseIssue.Type.BLACKBOX, 0x5c86af);
        TYPE_COLORS.put(BaseIssue.Type.CONFIGURATION, LEVEL_COLORS.get(BaseIssue.Level.LOW));
        TYPE_COLORS.put(BaseIssue.Type.SCA, LEVEL_COLORS.get(BaseIssue.Level.MEDIUM));
        TYPE_COLORS.put(BaseIssue.Type.UNKNOWN, LEVEL_COLORS.get(BaseIssue.Level.NONE));
        TYPE_COLORS.put(BaseIssue.Type.VULNERABILITY, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        TYPE_COLORS.put(BaseIssue.Type.WEAKNESS, LEVEL_COLORS.get(BaseIssue.Level.POTENTIAL));
        TYPE_COLORS.put(BaseIssue.Type.YARAMATCH, 0xd89011);

        APPROVAL_COLORS.put(BaseIssue.ApprovalState.APPROVAL, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        APPROVAL_COLORS.put(BaseIssue.ApprovalState.AUTO_APPROVAL, LEVEL_COLORS.get(BaseIssue.Level.MEDIUM));
        APPROVAL_COLORS.put(BaseIssue.ApprovalState.DISCARD, LEVEL_COLORS.get(BaseIssue.Level.LOW));
        APPROVAL_COLORS.put(BaseIssue.ApprovalState.NONE, LEVEL_COLORS.get(BaseIssue.Level.NONE));
        APPROVAL_COLORS.put(BaseIssue.ApprovalState.NOT_EXIST, 0x9b9b9b);

        SUSPECTED_COLORS.put(false, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        SUSPECTED_COLORS.put(true, LEVEL_COLORS.get(BaseIssue.Level.POTENTIAL));

        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.FROM_OTHER, LEVEL_COLORS.get(BaseIssue.Level.POTENTIAL));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.FROM_ENTRYPOINT, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.FROM_PUBLICPROTECTED, LEVEL_COLORS.get(BaseIssue.Level.MEDIUM));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.TAINT, LEVEL_COLORS.get(BaseIssue.Level.LOW));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.NONE, LEVEL_COLORS.get(BaseIssue.Level.NONE));
        SCANMODE_COLORS.put(VulnerabilityIssue.ScanMode.UNKNOWN, LEVEL_COLORS.get(BaseIssue.Level.NONE));

        /*
        SCANSTAGE_COLORS.put(Stage.SETUP, LEVEL_COLORS.get(BaseIssue.Level.LOW));
        SCANSTAGE_COLORS.put(Stage.ZIP, changeColorShade(LEVEL_COLORS.get(BaseIssue.Level.LOW), 0.8f, 0.8f));
        SCANSTAGE_COLORS.put(Stage.UPLOAD, changeColorShade(LEVEL_COLORS.get(BaseIssue.Level.LOW), 0.8f, 0.9f));
        SCANSTAGE_COLORS.put(Stage.ENQUEUED, LEVEL_COLORS.get(BaseIssue.Level.POTENTIAL));
        SCANSTAGE_COLORS.put(Stage.INITIALIZE, changeColorShade(LEVEL_COLORS.get(BaseIssue.Level.HIGH), 0.8f, 0.8f));
        SCANSTAGE_COLORS.put(Stage.VFSSETUP, changeColorShade(LEVEL_COLORS.get(BaseIssue.Level.HIGH), 0.8f, 0.9f));
        SCANSTAGE_COLORS.put(Stage.PRECHECK, changeColorShade(LEVEL_COLORS.get(BaseIssue.Level.HIGH), 0.8f, 1.0f));
        SCANSTAGE_COLORS.put(Stage.SCAN, LEVEL_COLORS.get(BaseIssue.Level.HIGH));
        SCANSTAGE_COLORS.put(Stage.FINALIZE, LEVEL_COLORS.get(BaseIssue.Level.MEDIUM));
        SCANSTAGE_COLORS.put(Stage.AUTOCHECK, changeColorShade(LEVEL_COLORS.get(BaseIssue.Level.MEDIUM), 0.8f, 0.9f));
        */
        SCANSTAGE_COLORS.put(Stage.SETUP, createShade(0, 10));
        SCANSTAGE_COLORS.put(Stage.ZIP, createShade(4, 10));
        SCANSTAGE_COLORS.put(Stage.UPLOAD, createShade(7, 10));
        SCANSTAGE_COLORS.put(Stage.ENQUEUED, createShade(1, 10));
        SCANSTAGE_COLORS.put(Stage.INITIALIZE, createShade(5, 10));
        SCANSTAGE_COLORS.put(Stage.VFSSETUP, createShade(8, 10));
        SCANSTAGE_COLORS.put(Stage.PRECHECK, createShade(2, 10));
        SCANSTAGE_COLORS.put(Stage.SCAN, createShade(6, 10));
        SCANSTAGE_COLORS.put(Stage.FINALIZE, createShade(9, 10));
        SCANSTAGE_COLORS.put(Stage.AUTOCHECK, createShade(3, 10));
        // These colors aren't supposed to appear, so keep them white
        SCANSTAGE_COLORS.put(Stage.DONE, 0xffffff);
        SCANSTAGE_COLORS.put(Stage.FAILED, 0xffffff);
        SCANSTAGE_COLORS.put(Stage.ABORTED, 0xffffff);
        SCANSTAGE_COLORS.put(Stage.UNKNOWN, 0xffffff);
    }

    public static int createShade(final float index, final float total) {
        float[] hsb = new float[3];
        hsb[0] = index / total; // * 255f;
        hsb[1] = 0.55f;
        hsb[2] = 0.8f;
        return Color.getHSBColor(hsb[0], hsb[1], hsb[2]).getRGB() & 0xFFFFFF;
    }

    public static int changeColorShade(final int c, final float s, final float b) {
        Color color = Color.decode("#" + Integer.toHexString(c));
        float[] hsb = new float[3];
        Color.RGBtoHSB(color.getRed(), color.getGreen(), color.getBlue(), hsb);
        hsb[1] *= s;
        if (1 < hsb[1]) hsb[1] = 1;
        hsb[2] *= b;
        if (1 < hsb[2]) hsb[2] = 1;
        return Color.getHSBColor(hsb[0], hsb[1], hsb[2]).getRGB() & 0xFFFFFF;
    }

    @SneakyThrows
    public static JSONObject convertObject(final Object object) {
        if (null == object) return null;
        JSONObject res = new JSONObject();
        Class<?> c = object.getClass();
        // Iterate through class hierarchy
        while (null != c) {
            // Add fields
            for (Field field : c.getDeclaredFields()) {
                if (!field.isAnnotationPresent(JsonProperty.class)) continue;
                JsonProperty jsonProperty = field.getAnnotation(JsonProperty.class);
                String jsonFieldName = StringUtils.isEmpty(jsonProperty.value())
                        ? field.getName() : jsonProperty.value();
                Object value = Reflect.on(object).field(field.getName()).get();
                if (null == value) continue;

                Object jsonValue = convertValue(value);
                if (null != jsonValue) res.put(jsonFieldName, jsonValue);
            }
            c = c.getSuperclass();
        }
        return res;
    }

    protected static Object convertValue(final Object value) {
        if (null == value) return null;
        Class<?> c = value.getClass();
        if (Collection.class.isAssignableFrom(c))
            return convertCollection(value);
        else if (c.isArray())
            return convertCollection(value);
        else if (c.equals(String.class))
            return value;
        else if (c.equals(UUID.class))
            return value.toString();
        else if (ClassUtils.isPrimitiveOrWrapper(c))
            return value;
        else if (c.isEnum())
            return value.toString();
        else
            return convertObject(value);
    }

    public static JSONArray convertCollection(final Object collection) {
        if (null == collection) return null;

        JSONArray res = new JSONArray();
        Class<?> c = collection.getClass();
        if (c.isArray()) {
            Object[] items = (Object[]) collection;
            for (Object item : items) res.add(convertValue(item));
        } else if (Collection.class.isAssignableFrom(c)) {
            Collection<?> items = (Collection<?>) collection;
            for (Object item : items) res.add(convertValue(item));
        }
        return res;
    }
}
