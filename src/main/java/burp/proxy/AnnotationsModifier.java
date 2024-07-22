/*
Author : Dolph Flynn

Copyright 2022 Dolph Flynn

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

package burp.proxy;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.utilities.ByteUtils;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.MutableJOSEObject;

import static com.blackberry.jwteditor.model.jose.JOSEObjectFinder.extractJOSEObjects;

class AnnotationsModifier {
    private final ByteUtils byteUtils;
    private final ProxyConfig proxyConfig;

    AnnotationsModifier(ProxyConfig proxyConfig, ByteUtils byteUtils) {
        this.byteUtils = byteUtils;
        this.proxyConfig = proxyConfig;
    }

    void updateAnnotationsIfApplicable(Annotations annotations, ByteArray data) {
        if (proxyConfig.highlightJWT()) {
            String message = byteUtils.convertToString(data.getBytes());
            updateAnnotationsIfApplicable(annotations, message);
        }
    }

    void updateAnnotationsIfApplicable(Annotations annotations, String message) {
        if (proxyConfig.highlightJWT()) {
            updateAnnotations(annotations, message);
        }
    }

    private void updateAnnotations(Annotations annotations, String messageString) {
        Counts counts = countJOSEObjects(messageString);

        if (!counts.isZero()) {
            annotations.setHighlightColor(proxyConfig.highlightColor().burpColor);
            annotations.setNotes(counts.comment());
        }
    }

    private Counts countJOSEObjects(String messageString) {
        int jwsCount = 0;
        int jweCount = 0;

        for (MutableJOSEObject mutableJoseObject : extractJOSEObjects(messageString)) {
            if (mutableJoseObject.getModified() instanceof JWS) {
                jwsCount++;
            } else {
                jweCount++;
            }
        }

        return new Counts(proxyConfig, jweCount, jwsCount);
    }

    private record Counts(ProxyConfig proxyConfig, int jweCount, int jwsCount) {
        boolean isZero() {
            return jweCount == 0 && jwsCount == 0;
        }

        String comment() {
            return proxyConfig.comment(jwsCount, jweCount);
        }
    }
}
