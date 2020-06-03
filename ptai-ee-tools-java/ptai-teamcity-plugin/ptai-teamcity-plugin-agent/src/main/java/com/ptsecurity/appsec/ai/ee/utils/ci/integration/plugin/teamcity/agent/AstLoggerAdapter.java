package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.agent;

import jetbrains.buildServer.agent.BuildProgressLogger;
import org.slf4j.helpers.FormattingTuple;
import org.slf4j.helpers.MarkerIgnoringBase;
import org.slf4j.helpers.MessageFormatter;

public class AstLoggerAdapter extends MarkerIgnoringBase {
    private BuildProgressLogger buildLogger;

    public AstLoggerAdapter(BuildProgressLogger log) {
        this.name = "Build Logger";
        this.buildLogger = log;
    }

    public boolean isTraceEnabled() {
        return false;
    }

    public void trace(String s) {

    }

    public void trace(String s, Object o) {
    }

    public void trace(String s, Object o, Object o1) {
    }

    public void trace(String s, Object... objects) {
    }

    public void trace(String s, Throwable throwable) {
    }

    public boolean isDebugEnabled() {
        return true;
    }

    public void debug(String s) {
        buildLogger.message(s);
    }

    public void debug(String s, Object o) {
        FormattingTuple ft = MessageFormatter.format(s, o);
        buildLogger.message(ft.getMessage());
    }

    public void debug(String s, Object o, Object o1) {
        FormattingTuple ft = MessageFormatter.format(s, o, o1);
        buildLogger.message(ft.getMessage());
    }

    public void debug(String s, Object... objects) {
        FormattingTuple ft = MessageFormatter.format(s, objects);
        buildLogger.message(ft.getMessage());
    }

    public void debug(String s, Throwable throwable) {
        buildLogger.message(s);
    }

    public boolean isInfoEnabled() {
        return true;
    }

    public void info(String s) {
        buildLogger.message(s);
    }

    public void info(String s, Object o) {
        FormattingTuple ft = MessageFormatter.format(s, o);
        buildLogger.message(ft.getMessage());
    }

    public void info(String s, Object o, Object o1) {
        FormattingTuple ft = MessageFormatter.format(s, o, o1);
        buildLogger.message(ft.getMessage());
    }

    public void info(String s, Object... objects) {
        FormattingTuple ft = MessageFormatter.format(s, objects);
        buildLogger.message(ft.getMessage());
    }

    public void info(String s, Throwable throwable) {
        buildLogger.message(s);
    }


    public boolean isWarnEnabled() {
        return true;
    }

    public void warn(String s) {
        buildLogger.warning(s);
    }

    public void warn(String s, Object o) {
        FormattingTuple ft = MessageFormatter.format(s, o);
        buildLogger.warning(ft.getMessage());
    }

    public void warn(String s, Object... objects) {
        FormattingTuple ft = MessageFormatter.format(s, objects);
        buildLogger.warning(ft.getMessage());
    }

    public void warn(String s, Object o, Object o1) {
        FormattingTuple ft = MessageFormatter.format(s, o, o1);
        buildLogger.warning(ft.getMessage());
    }

    public void warn(String s, Throwable throwable) {
        buildLogger.warning(s);
    }

    public boolean isErrorEnabled() {
        return true;
    }

    public void error(String s) {
        buildLogger.error(s);
    }

    public void error(String s, Object o) {
        FormattingTuple ft = MessageFormatter.format(s, o);
        buildLogger.error(ft.getMessage());
        buildLogger.exception(ft.getThrowable());
    }

    public void error(String s, Object o, Object o1) {
        FormattingTuple ft = MessageFormatter.format(s, o, o1);
        buildLogger.error(ft.getMessage());
        buildLogger.exception(ft.getThrowable());
    }

    public void error(String s, Object... objects) {
        FormattingTuple ft = MessageFormatter.format(s, objects);
        buildLogger.error(ft.getMessage());
        buildLogger.exception(ft.getThrowable());
    }

    public void error(String s, Throwable throwable) {
        buildLogger.error(s);
        buildLogger.exception(throwable);
    }
}
