package com.ptsecurity.appsec.ai.ee.utils.json.metadata;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.Description;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.description.LocalizedDescription;
import com.ptsecurity.appsec.ai.ee.utils.json.metadata.issue.GenericIssueMetadata;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Metadata {
    public static Map<String, GenericIssueMetadata> ISSUES;
    public static Map<String, Description> DESCRIPTIONS;

    static {
        load();
    }

    static void load() {
        try {
            ISSUES = new HashMap<>();
            InputStream is = Metadata.class.getResourceAsStream("/json/metadata/api.configs.getIssueMetadatas.json");
            String json = IOUtils.toString(is, StandardCharsets.UTF_8);
            ObjectMapper jsonMapper = new ObjectMapper();
            jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            List<GenericIssueMetadata> issues = new ArrayList<>();
            issues.addAll(jsonMapper.readValue(json, jsonMapper.getTypeFactory().constructCollectionType(List.class, GenericIssueMetadata.class)));
            for (GenericIssueMetadata issue : issues)
                ISSUES.put(issue.getKey(), issue);

            loadDescriptions();
        } catch (IOException | SAXException e) {
            throw new RuntimeException(e);
        }
    }

    static void loadDescriptions() throws IOException, SAXException {
        DESCRIPTIONS = new HashMap<>();
        InputStream is = Metadata.class.getResourceAsStream("/json/metadata/api.configs.getIssueDescriptions.json");
        String json = IOUtils.toString(is, StandardCharsets.UTF_8);
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        List<Description> descriptions = new ArrayList<>();
        descriptions.addAll(jsonMapper.readValue(json, jsonMapper.getTypeFactory().constructCollectionType(List.class, Description.class)));

        for (Description description : descriptions) {
            for (Map.Entry<String, LocalizedDescription> localizedDescription : description.getValues().entrySet()) {
                String html = localizedDescription.getValue().getHtml();
                if (StringUtils.isEmpty(html)) continue;
                html = html.replaceAll("<stdio.h>", "&lt;stdio.h&gt;");
                Document doc = Jsoup.parse(html);
                Elements nodeList = doc.select("html > body > main");
                if (null == nodeList) continue;
                html = "";
                for (Element node : nodeList)
                    html += node.html();
                localizedDescription.getValue().setHtml(html);
            }

            DESCRIPTIONS.put(description.getKey(), description);
        }
    }
}
