package com.bin3xish477;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class InjectCollaboratorEverywhere implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("InjectCollaboratorEverywhere");
        api.logging().logToOutput(
                "This extension automatically injects a collaborator payload to the Host"
                + ", Referer, and Origin headers, and/or other non-standard headers. It also allows"
                + " injecting a collaborator payload into applicable query and JSON parameters."
        );

        String collaborator = api.collaborator().defaultPayloadGenerator().generatePayload().toString();
        api.logging().logToOutput(String.format("[+] Generated Burp Collaborator endpoint: %s", collaborator));
        api.userInterface().registerContextMenuItemsProvider(
                new InjectCollaboratorMenuItemsProvider(api, collaborator)
        );
    }
}