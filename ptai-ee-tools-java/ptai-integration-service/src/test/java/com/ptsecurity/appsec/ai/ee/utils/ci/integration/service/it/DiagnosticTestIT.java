package com.ptsecurity.appsec.ai.ee.utils.ci.integration.service.it;

import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.Node;
import com.ptsecurity.appsec.ai.ee.ptai.integration.rest.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

@DisplayName("Test PT AI EE integration service diagnostic functions")
public class DiagnosticTestIT extends BaseTestIT {
    @Test
    @DisplayName("List PT AI EE integration service nodes and tags")
    public void listNodes() throws Exception {
        List<Node> nodes = client[1].getDiagnosticApi().getAstNodes();
        for (Node node : nodes)
            System.out.println(node.getName() + " : " + node.getType());
    }
}
