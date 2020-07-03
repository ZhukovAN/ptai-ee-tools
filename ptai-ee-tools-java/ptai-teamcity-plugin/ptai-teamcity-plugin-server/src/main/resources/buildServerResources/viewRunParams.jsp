<%@ include file="common.jsp" %>
<%@ include file="constants.jsp" %>

<jsp:useBean id="propertiesBean" scope="request" type="jetbrains.buildServer.controllers.BasePropertiesBean"/>

<div class="parameter">General AST settings:</div>

<c:choose>
    <c:when test="${propertiesBean.properties[AST_SETTINGS] == AST_SETTINGS_UI}">
        <div class="nestedParameter">
            ${LABEL_AST_SETTINGS}: <strong>${HINT_AST_SETTINGS_UI}</strong>
        </div>
        <div class="nestedParameter">
            ${LABEL_PROJECT_NAME}:
            <props:displayValue name="${PROJECT_NAME}" emptyValue=""/>
        </div>
    </c:when>
    <c:otherwise>
        <div class="nestedParameter">
            ${LABEL_AST_SETTINGS}: <strong>${HINT_AST_SETTINGS_JSON}</strong>
        </div>
    </c:otherwise>
</c:choose>

<div class="nestedParameter">
    ${LABEL_FAIL_IF_FAILED}:
    <props:displayValue name="${FAIL_IF_FAILED}" emptyValue="false"/>
</div>

<div class="nestedParameter">
    ${LABEL_FAIL_IF_UNSTABLE}:
    <props:displayValue name="${FAIL_IF_UNSTABLE}" emptyValue="false"/>
</div>

<div class="parameter">Scan scope:</div>

<div class="nestedParameter">
    ${LABEL_INCLUDES}:
    <props:displayValue name="${INCLUDES}" emptyValue=""/>
</div>

<div class="nestedParameter">
    ${LABEL_EXCLUDES}:
    <props:displayValue name="${EXCLUDES}" emptyValue=""/>
</div>

<div class="nestedParameter">
    ${LABEL_REMOVE_PREFIX}:
    <props:displayValue name="${REMOVE_PREFIX}" emptyValue="false"/>
</div>

<div class="nestedParameter">
    ${LABEL_PATTERN_SEPARATOR}:
    <props:displayValue name="${PATTERN_SEPARATOR}" emptyValue=""/>
</div>

<div class="nestedParameter">
    ${LABEL_USE_DEFAULT_EXCLUDES}:
    <props:displayValue name="${USE_DEFAULT_EXCLUDES}" emptyValue="false"/>
</div>

<div class="nestedParameter">
    ${LABEL_FLATTEN}:
    <props:displayValue name="${FLATTEN}" emptyValue="false"/>
</div>
