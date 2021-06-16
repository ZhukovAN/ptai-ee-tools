package com.ptsecurity.appsec.ai.ee.utils.ci.integration.ptaiserver.v36.utils;

import com.ptsecurity.appsec.ai.ee.ptai.server.v36.projectmanagement.model.ProgrammingLanguage;

import java.util.HashMap;
import java.util.Map;

public class ProgrammingLanguageHelper {
    public static final Map<ProgrammingLanguage, String> LANGUAGES = new HashMap<>();

    static {
        LANGUAGES.put(ProgrammingLanguage.None, "None");
        LANGUAGES.put(ProgrammingLanguage.DotNet, ".NET");
        LANGUAGES.put(ProgrammingLanguage.Php, "PHP");
        LANGUAGES.put(ProgrammingLanguage.Java, "Java");
        LANGUAGES.put(ProgrammingLanguage.Html, "HTML");
        LANGUAGES.put(ProgrammingLanguage.JavaScript, "JavaScript");
        LANGUAGES.put(ProgrammingLanguage.All, "All");
        LANGUAGES.put(ProgrammingLanguage.SandBox, "SandBox");
        LANGUAGES.put(ProgrammingLanguage.Binary, "Binary");
        LANGUAGES.put(ProgrammingLanguage.PlSql, "PL/SQL");
        LANGUAGES.put(ProgrammingLanguage.TSql, "T-SQL");
        LANGUAGES.put(ProgrammingLanguage.MySql, "MySQL");
        LANGUAGES.put(ProgrammingLanguage.Aspx, "ASP.NET");
        LANGUAGES.put(ProgrammingLanguage.C, "C");
        LANGUAGES.put(ProgrammingLanguage.CPlusPlus, "C++");
        LANGUAGES.put(ProgrammingLanguage.ObjectiveC, "ObjectiveC");
        LANGUAGES.put(ProgrammingLanguage.Swift, "Swift");
        LANGUAGES.put(ProgrammingLanguage.Python, "Python");
        LANGUAGES.put(ProgrammingLanguage.CSharp, "C#");
        LANGUAGES.put(ProgrammingLanguage.VB, "VB.NET");
        LANGUAGES.put(ProgrammingLanguage.Go, "Go");
        LANGUAGES.put(ProgrammingLanguage.Kotlin, "Kotlin");
    }
}
