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

package attack;

import burp.api.montoya.MontoyaExtension;
import com.blackberry.jwteditor.model.jose.JWS;
import com.blackberry.jwteditor.model.jose.JWSFactory;
import com.blackberry.jwteditor.operations.Attacks;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static com.nimbusds.jose.HeaderParameterNames.JWK_SET_URL;
import static com.nimbusds.jose.HeaderParameterNames.X_509_CERT_URL;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MontoyaExtension.class)
class EmbeddedCollaboratorPayloadAttackTest {
    private static final String TEST_JWS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static final String COLLABORATOR_PAYLOAD = "moe2qvf747knlg81qkcu0kz6vx1oped3.oastify.com";

    @Test
    void canEmbedCollaboratorPayloadWithinX5uHeader() throws Exception {
        JWS jws = JWSFactory.parse(TEST_JWS);

        JWS attackJws = Attacks.embedCollaboratorPayload(jws, X_509_CERT_URL, COLLABORATOR_PAYLOAD);

        assertThat(attackJws.serialize()).isEqualTo("eyJ4NXUiOiJodHRwczovL21vZTJxdmY3NDdrbmxnODFxa2N1MGt6NnZ4MW9wZWQzLm9hc3RpZnkuY29tL2NlcnQucGVtIiwidHlwIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }

    @Test
    void canEmbedCollaboratorPayloadWithinJkuHeader() throws Exception {
        JWS jws = JWSFactory.parse(TEST_JWS);

        JWS attackJws = Attacks.embedCollaboratorPayload(jws, JWK_SET_URL, COLLABORATOR_PAYLOAD);
        assertThat(attackJws.serialize()).isEqualTo("eyJqa3UiOiJodHRwczovL21vZTJxdmY3NDdrbmxnODFxa2N1MGt6NnZ4MW9wZWQzLm9hc3RpZnkuY29tL2p3a3MuanNvbiIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }

    @Test
    void canEmbedCollaboratorPayloadWithinUnknownHeader() throws Exception {
        JWS jws = JWSFactory.parse(TEST_JWS);

        JWS attackJws = Attacks.embedCollaboratorPayload(jws, "mayne", COLLABORATOR_PAYLOAD);

        assertThat(attackJws.serialize()).isEqualTo("eyJtYXluZSI6Im1vZTJxdmY3NDdrbmxnODFxa2N1MGt6NnZ4MW9wZWQzLm9hc3RpZnkuY29tIiwidHlwIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }
}
