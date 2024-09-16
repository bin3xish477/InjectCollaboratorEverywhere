package com.bin3xish477;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class InjectCollaboratorMenuItemsProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final String collaborator;
    private final ExecutorService executorService = Executors.newFixedThreadPool(5);
    private HttpRequest request;

    public InjectCollaboratorMenuItemsProvider(final MontoyaApi api, String collaborator) {
        this.api = api;
        this.collaborator = collaborator;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.isFromTool(ToolType.PROXY, ToolType.LOGGER, ToolType.TARGET)) {

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
                this.sendRequest();
            });

            injectRefererHeader.addActionListener(l -> {
                this.injectCollaboratorInHeaders(List.of("Referer"));
                this.sendRequest();
            });

            injectOriginHeader.addActionListener(l -> {
                this.injectCollaboratorInHeaders(List.of("Origin"));
                this.sendRequest();
            });

            injectXLikeHeader.addActionListener(l -> {
                this.injectCollaboratorInHeaders(
                        Arrays.asList("X-Forwarded-Host", "X-Server",
                                "X-Host", "X-Origin-Url", "X-Rewrite-Url", "X-Original-Host"));
                this.sendRequest();
            });

            injectQueryParams.addActionListener(l -> {
                this.injectTargetQueryParams();
                this.sendRequest();
            });

            injectJSON.addActionListener(l -> {
                // TODO: check if request contains JSON body and is valid JSON.
                this.injectTargetJSON();
                this.sendRequest();
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

                this.sendRequest();
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

    /*
    * TODO: add logic to the two functions that will replace the values for common
    *   params used to identify a URL. Use a case-insensitive
    *   regex to identify applicable parameters that contain the word url.
    *   `sendRequest` will be called multiple times from this
    *  */

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

    private void sendRequest() {
        this.executorService.execute(new DoRequest(this.api, this.request));
    }

    public JsonNode updateJsonNode(JsonNode node) {
        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (field.getValue().asText().matches("(?i)^https?://.+")) {
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
}
