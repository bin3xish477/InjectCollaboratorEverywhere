package com.bin3xish477;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class InjectCollaboratorMenuItemsProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private String collaborator = "";
    private final ExecutorService executorService = Executors.newFixedThreadPool(5);
    private HttpRequest request;

    public InjectCollaboratorMenuItemsProvider(final MontoyaApi api, String collaborator) {
        this.api = api;
        this.collaborator = collaborator;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.isFromTool(ToolType.PROXY, ToolType.LOGGER, ToolType.TARGET, ToolType.REPEATER)) {

            JMenuItem injectHostHeader = new JMenuItem("Inject in Host Header");
            JMenuItem injectRefererHeader = new JMenuItem("Inject in Referer Header");
            JMenuItem injectOriginHeader = new JMenuItem("Inject in Origin Header");
            JMenuItem injectXLikeHeader = new JMenuItem("Inject in X-* Headers");
            JMenuItem injectQueryParams = new JMenuItem("Inject in Query Params");
            JMenuItem injectJSON = new JMenuItem("Inject in JSON");
            JMenuItem injectEverywhere = new JMenuItem("Inject Everywhere");

            HttpRequestResponse requestResponse = event.messageEditorRequestResponse().isPresent() ?
                    event.messageEditorRequestResponse().get().requestResponse() : event.selectedRequestResponses().get(0);

            this.request = requestResponse.request();

            injectHostHeader.addActionListener(l -> {
                this.injectCollaboratorInHeaders(List.of("Host"));
                HttpResponse response = this.sendRequest().response();
                this.checkResponseForCollaboratorPayload(response);
            });

            injectRefererHeader.addActionListener(l -> {
                this.injectCollaboratorInHeaders(List.of("Referer"));
                HttpResponse response = this.sendRequest().response();
                this.checkResponseForCollaboratorPayload(response);
            });

            injectOriginHeader.addActionListener(l -> {
                this.injectCollaboratorInHeaders(List.of("Origin"));
                HttpResponse response = this.sendRequest().response();
                this.checkResponseForCollaboratorPayload(response);
            });

            injectXLikeHeader.addActionListener(l -> {
                this.injectCollaboratorInHeaders(
                        Arrays.asList("X-Forwarded-Host", "X-Server",
                                "X-Host", "X-Origin-Url", "X-Rewrite-Url", "X-Original-Host"));
                HttpResponse response = this.sendRequest().response();
                this.checkResponseForCollaboratorPayload(response);
            });

            injectQueryParams.addActionListener(l -> {
                this.injectTargetQueryParams();
                HttpResponse response = this.sendRequest().response();
                this.checkResponseForCollaboratorPayload(response);
            });

            injectJSON.addActionListener(l -> {
                this.injectTargetJSON();
                HttpResponse response = this.sendRequest().response();
                this.checkResponseForCollaboratorPayload(response);
            });

            injectEverywhere.addActionListener(l -> {
                this.injectCollaboratorInHeaders(
                        Arrays.asList(
                                "Host", "Referer", "Origin", "X-Forwarded-Host",
                                "X-Server", "X-Host", "X-Origin-Url", "X-Rewrite-Url", "X-Original-Host"));

                if (this.request.contentType() == ContentType.JSON) {
                    this.injectTargetJSON();
                }

                if (this.request.hasParameters()) {
                    this.injectTargetQueryParams();
                }

                HttpResponse response = this.sendRequest().response();
                this.checkResponseForCollaboratorPayload(response);
            });

            return new ArrayList<>(
                Arrays.asList(
                        injectHostHeader,
                        injectRefererHeader,
                        injectOriginHeader,
                        injectXLikeHeader,
                        injectQueryParams,
                        injectJSON,
                        injectEverywhere
                )
            );
        }
        return null;
    }

    private void injectCollaboratorInHeaders(List<String> headers) {
        for (String header : headers) {
            this.request = this.request.withRemovedHeader(header);
            if (
                header.equalsIgnoreCase("Origin")
                || header.equalsIgnoreCase("X-Origin-Url")
                || header.equalsIgnoreCase("X-Rewrite-Url")
            ) {
                this.request = this.request.withAddedHeader(header, String.format("https://%s", this.collaborator));
            } else {
                this.request = this.request.withAddedHeader(header, this.collaborator);
            }
        }
    }

    private final List<String> targetParams = Arrays.asList(
            "redirect_uri",
            "redirectUri",
            "callback",
            "next",
            "continue",
            "return_to",
            "returnTo"
    );

    private void injectTargetQueryParams() {
        if (this.request.hasParameters()) {
            for (ParsedHttpParameter param  : this.request.parameters()) {
                String paramName = param.name();
                if (
                    targetParams.contains(paramName)
                    || paramName.matches("(?i).*url.*")
                ) {
                    this.api.logging().logToOutput(
                            String.format("[+] found injectable query parameter: %s", paramName));
                    this.request = this.request.withUpdatedParameters(
                            HttpParameter.urlParameter(
                                    paramName,
                                    this.api.utilities().urlUtils().encode(
                                            String.format("https://%s", this.collaborator))));
                }
            }
        }
    }

    private void injectTargetJSON() {
        if (this.request.hasHeader("Content-Type") && this.request.contentType() == ContentType.JSON) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                JsonNode json = mapper.readTree(this.request.bodyToString());
                JsonNode updatedJson = this.updateJsonNode(json);
                this.request = this.request.withBody(updatedJson.toString());
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public JsonNode updateJsonNode(JsonNode node) {
        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (field.getValue().asText().matches("(?i)^https?://.+")) {
                    this.api.logging().logToOutput(
                            String.format("[+] found inject parameter in JSON body: %s", field.getKey()));
                    objectNode.put(field.getKey(), String.format("https://%s", this.collaborator));
                }
                updateJsonNode(field.getValue());
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                updateJsonNode(node.get(i));
            }
        }
        return node;
    }

    private HttpRequestResponse sendRequest() {
        Future<HttpRequestResponse> future = this.executorService.submit(new DoRequest(this.api, this.request));
        try {
            return future.get();
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    private void checkResponseForCollaboratorPayload(HttpResponse response) {
        String regex = "(href|src)=[\"']*" + Pattern.quote(this.collaborator) + "*[\"']";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(response.bodyToString());
        if (matcher.find()) {
            this.api.logging().logToOutput("[+] found href/src with Collaborator payload -> " + matcher.group());
            this.createIssue(response);
        } else if (response.hasHeader("Location")) {
            if (response.headerValue("Location").contains(this.collaborator)) {
                this.createIssue(response);
            }
        } else if (response.hasHeader("Access-Control-Allow-Origin")) {
            if (response.headerValue("Access-Control-Allow-Origin").contains(this.collaborator)) {
                this.createIssue(response);
            }
        }
    }

    private void createIssue(HttpResponse response) {
        HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(this.request, response);
        AuditIssue auditIssue = AuditIssue.auditIssue(
                "Collaborator Payload Reflected in Response",
                "A Collaborate payload was reflected in the HTTP response in one of the following places: 1) "
                + "as a href/src attribute value, 2) in the HTTP Location header, or 3) in the "
                + " HTTP Access-Control-Allow-Origin header.",
                "When accepting user input that will be included as a source URL in an HTML element context,"
                + " control the redirection of the browser window, or used to define cross-origin access via the "
                + "Access-Control-Allow-Origin header, a URL allowlist should be used to validate the specified URL.",
                requestResponse.request().url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "https://cwe.mitre.org/data/definitions/601.html, https://portswigger.net/web-security/ssrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
                AuditIssueSeverity.HIGH,
                requestResponse
        );
        this.api.siteMap().add(auditIssue);
    }
}
