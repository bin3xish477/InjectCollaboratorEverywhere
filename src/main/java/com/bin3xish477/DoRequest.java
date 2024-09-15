package com.bin3xish477;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

class DoRequest implements Runnable {
    private final MontoyaApi api;
    private final HttpRequest request;

    public DoRequest(MontoyaApi api, HttpRequest request) {
        this.api = api;
        this.request = request;
    }

    @Override
    public void run() {
        this.api.http().sendRequest(this.request);
    }
}