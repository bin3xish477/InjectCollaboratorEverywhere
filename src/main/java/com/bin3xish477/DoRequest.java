package com.bin3xish477;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.concurrent.Callable;

class DoRequest implements Callable<HttpRequestResponse> {
    private final MontoyaApi api;
    private final HttpRequest request;

    public DoRequest(MontoyaApi api, HttpRequest request) {
        this.api = api;
        this.request = request;
    }

    @Override
    public HttpRequestResponse call() {
        return this.api.http().sendRequest(this.request);
    }
}