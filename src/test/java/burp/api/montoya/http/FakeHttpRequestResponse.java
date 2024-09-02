/*
Author : Dolph Flynn

Copyright 2023 Dolph Flynn

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package burp.api.montoya.http;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.FakeByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

public class FakeHttpRequestResponse implements HttpRequestResponse {
    private final HttpRequest httpRequest;

    private FakeHttpRequestResponse(HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    @Override
    public HttpRequest request() {
        return httpRequest;
    }

    @Override
    public HttpResponse response() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Annotations annotations() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<TimingData> timingData() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String url() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean hasResponse() {
        throw new UnsupportedOperationException();
    }

    @Override
    public HttpService httpService() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ContentType contentType() {
        throw new UnsupportedOperationException();
    }

    @Override
    public short statusCode() {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<Marker> requestMarkers() {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<Marker> responseMarkers() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean contains(String searchTerm, boolean caseSensitive) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean contains(Pattern pattern) {
        throw new UnsupportedOperationException();
    }

    @Override
    public HttpRequestResponse copyToTempFile() {
        throw new UnsupportedOperationException();
    }

    @Override
    public HttpRequestResponse withAnnotations(Annotations annotations) {
        throw new UnsupportedOperationException();
    }

    @Override
    public HttpRequestResponse withRequestMarkers(List<Marker> requestMarkers) {
        throw new UnsupportedOperationException();
    }

    @Override
    public HttpRequestResponse withRequestMarkers(Marker... requestMarkers) {
        throw new UnsupportedOperationException();
    }

    @Override
    public HttpRequestResponse withResponseMarkers(List<Marker> responseMarkers) {
        throw new UnsupportedOperationException();
    }

    @Override
    public HttpRequestResponse withResponseMarkers(Marker... responseMarkers) {
        throw new UnsupportedOperationException();
    }

    public static HttpRequestResponseBuilder requestResponse() {
        return new HttpRequestResponseBuilder();
    }

    public static class HttpRequestResponseBuilder {
        private ByteArray request;

        private HttpRequestResponseBuilder() {
        }

        public HttpRequestResponseBuilder withRequest(String request) {
            this.request = new FakeByteArray(request);
            return this;
        }

        public HttpRequestResponse build() {
            HttpRequest httpRequest = new FakeHttpRequest(request);

            return new FakeHttpRequestResponse(httpRequest);
        }
    }
}
