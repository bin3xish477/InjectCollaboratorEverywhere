package com.bin3xish477;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class InjectCollaboratorMenuItemsProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final String collaborator;
    private final ExecutorService executorService = Executors.newFixedThreadPool(5);

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

            HttpRequest request = requestResponse.request();

            injectHostHeader.addActionListener(l -> {
                HttpRequest modifiedRequest = injectCollaboratorInHeaders(request, List.of("Host"));
                this.sendRequest(modifiedRequest);
            });

            injectRefererHeader.addActionListener(l -> {
                HttpRequest modifiedRequest = injectCollaboratorInHeaders(request, List.of("Referer"));
                this.sendRequest(modifiedRequest);
            });

            injectOriginHeader.addActionListener(l -> {
                HttpRequest modifiedRequest = injectCollaboratorInHeaders(request, List.of("Origin"));
                this.sendRequest(modifiedRequest);
            });

            injectXLikeHeader.addActionListener(l -> {
                HttpRequest modifiedRequest = injectCollaboratorInHeaders(request,
                        Arrays.asList("X-Forwarded-Host", "X-Server",
                                "X-Host", "X-Origin-Url", "X-Rewrite-Url", "X-Original-Host"));
                this.sendRequest(modifiedRequest);
            });

            injectQueryParams.addActionListener(l -> {
                this.injectTargetQueryParams(request);
            });

            injectJSON.addActionListener(l -> {
                // TODO: check if request contains JSON body and is valid JSON.
                this.injectTargetJSONValues(request);
            });

            injectEverywhere.addActionListener(l -> {
                HttpRequest modifiedRequest = injectCollaboratorInHeaders(
                        request,
                        Arrays.asList(
                                "Host", "Referer", "Origin", "X-Forwarded-Host",
                                "X-Server", "X-Host", "X-Origin-Url", "X-Rewrite-Url", "X-Original-Host"));
                this.sendRequest(modifiedRequest);
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

    private HttpRequest injectCollaboratorInHeaders(HttpRequest request, List<String> headers) {
        for (String header : headers) {
            request = request.withRemovedHeader(header);
            if (
                header.equalsIgnoreCase("Origin")
                || header.equalsIgnoreCase("X-Origin-Url")
                || header.equalsIgnoreCase("X-Rewrite-Url")
            ) {
                request = request.withAddedHeader(header, String.format("https://%s", this.collaborator));
            } else {
                request = request.withAddedHeader(header, this.collaborator);
            }
        }
        return request;
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

    private HttpRequest injectTargetQueryParams(HttpRequest request) {
        return request;
    }

    private HttpRequest injectTargetJSONValues(HttpRequest request) {
        return request;
    }

    private void sendRequest(HttpRequest modifiedRequest) {
        this.executorService.execute(new DoRequest(this.api, modifiedRequest));
    }
}
