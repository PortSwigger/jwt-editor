/*
Author : Dolph Flynn

Copyright 2024 Dolph Flynn

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
import burp.api.montoya.core.FakeAnnotations;
import burp.api.montoya.core.FakeByteArray;
import burp.api.montoya.utilities.ByteUtils;
import burp.api.montoya.utilities.FakeByteUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static burp.proxy.HighlightColor.GREEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class AnnotationsModifierTest {
    private final ProxyConfig config = new ProxyConfig();
    private final ByteUtils byteUtils = new FakeByteUtils();
    private final AnnotationsModifier annotationsModifier = new AnnotationsModifier(config, byteUtils);

    private static Stream<Arguments> data() {
        return Stream.of(
                arguments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZXN0In0.Nabf3xakZubPnCzHT-fx0vG1iuNPeJKuSzHxUiQKf-8", "1 JWTs, 0 JWEs"),
                arguments("eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.H3X6mT5HLgcFfzLoe4ku6Knhh9Ofv1eL.qF5-N_7K8VQ4yMSz.WXUNY6eg5fR4tc8Hqf5XDRM9ALGwcQyYG4IYwwg8Ctkx1UuxoV7t6UnemjzCj2sOYUqi3KYpDzrKVJpzokz0vcIem4lFe5N_ds8FAMpW0GSF9ePA8qvV99WaP0N2ECVPmgihvL6qwNhdptlLKtxcOpE41U5LnU22voPK55VF4_1j0WmTgWgZ7DwLDysp6EIDjrrt-DY.febBmP71KADmKRVfeSnv_g", "0 JWTs, 1 JWEs")
        );
    }

    @MethodSource("data")
    @ParameterizedTest
    void givenJWTStrings_whenHighlightJWTTrue_thenCommentAndHighlightUpdated(String data, String expectedComment) {
        Annotations annotations = new FakeAnnotations();
        config.setHighlightColor(GREEN);
        config.setHighlightJWT(true);

        annotationsModifier.updateAnnotationsIfApplicable(annotations, data);

        assertThat(annotations.highlightColor()).isEqualTo(GREEN.burpColor);
        assertThat(annotations.notes()).isEqualTo(expectedComment);
    }

    @MethodSource("data")
    @ParameterizedTest
    void givenJWTBytes_whenHighlightJWTTrue_thenCommentAndHighlightUpdated(String data, String expectedComment) {
        Annotations annotations = new FakeAnnotations();
        config.setHighlightColor(GREEN);
        config.setHighlightJWT(true);

        annotationsModifier.updateAnnotationsIfApplicable(annotations, new FakeByteArray(data));

        assertThat(annotations.highlightColor()).isEqualTo(GREEN.burpColor);
        assertThat(annotations.notes()).isEqualTo(expectedComment);
    }

    @MethodSource("data")
    @ParameterizedTest
    void givenJWTStrings_whenHighlightJWTFalse_thenCommentAndHighlightNotSet(String data, String expectedComment) {
        Annotations annotations = new FakeAnnotations();
        config.setHighlightColor(GREEN);
        config.setHighlightJWT(false);

        annotationsModifier.updateAnnotationsIfApplicable(annotations, data);

        assertThat(annotations.highlightColor()).isNull();
        assertThat(annotations.notes()).isNull();
    }

    @MethodSource("data")
    @ParameterizedTest
    void givenJWTBytes_whenHighlightJWTFalse_thenCommentAndHighlightNotSet(String data, String expectedComment) {
        Annotations annotations = new FakeAnnotations();
        config.setHighlightColor(GREEN);
        config.setHighlightJWT(false);

        annotationsModifier.updateAnnotationsIfApplicable(annotations, new FakeByteArray(data));

        assertThat(annotations.highlightColor()).isNull();
        assertThat(annotations.notes()).isNull();
    }
}