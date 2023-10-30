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

package com.blackberry.jwteditor;

import com.blackberry.jwteditor.model.keys.KeysModel;
import com.blackberry.jwteditor.model.keys.KeysModelListener.InertKeyModelListener;
import com.blackberry.jwteditor.model.keys.PasswordKey;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static com.blackberry.jwteditor.KeysModelBuilder.keysModel;
import static data.PemData.*;
import static org.assertj.core.api.Assertions.assertThat;

class KeysModelTest {

    @Test
    void emptyKeyModel() {
        KeysModel model = new KeysModel();

        String json = model.serialize();

        assertThat(json).isEqualTo("[]");
    }

    @Test
    void keyModelWithEcKeys() {
        KeysModel model = keysModel()
                .withECKey(PRIME256v1PrivateSEC1)
                .withECKey(PRIME256v1Public)
                .build();

        String json = model.serialize();

        assertThat(json).isEqualTo("[{\"kty\":\"EC\",\"d\":\"R7xUBrtHikGBXsJkDekdUxWWC2YhYMKTDXILREc4_7s\",\"crv\":\"P-256\",\"kid\":\"1\",\"x\":\"Kxyedi_DE6wZdC1shMeYVx9IvSXl14RRp_Z5tZjBodo\",\"y\":\"UXtt70JCve0c_puZsjyTHtLD6xfBvoI3fVoh9WzhH-M\"},{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"2\",\"x\":\"Kxyedi_DE6wZdC1shMeYVx9IvSXl14RRp_Z5tZjBodo\",\"y\":\"UXtt70JCve0c_puZsjyTHtLD6xfBvoI3fVoh9WzhH-M\"}]");
    }

    @Test
    void keyModelWithRsaKeys() {
        KeysModel model = keysModel()
                .withRSAKey(RSA1024Private)
                .withRSAKey(RSA1024Public)
                .build();

        String json = model.serialize();

        assertThat(json).isEqualTo("[{\"p\":\"7J4T2x9Akhn4NGzv46EeA5fyISly7nY3cLnMTwE53l3K9_g5-ckszNcRypfj9N9P7HAzTicIm6I6D5JtPXWq3Q\",\"kty\":\"RSA\",\"q\":\"zwsNqfmn9PpUHhIB2cymLGUKX4lW6Q_nkq4omaqSPUqxd8fIPhRnnqClYUGR49dqyqOn2qeLVaVYiIc0D-EJNQ\",\"d\":\"NMpdNO1f7WcaN_FUmEhrC9XVD1xiyNgrP2UNTqKUkTW68F2rAcBJt4cyPZcTeMuEF9q_r1BEoimLs-A59ydhi9ND3CmYtmDqVgswHpKXjJf0I5zVuFQR2nvmgudyDAZDhS8xHpmBbLzaWq0X0RIXPcMAdBCVsaQVCKVW-tYBHVE\",\"e\":\"AQAB\",\"kid\":\"1\",\"qi\":\"WmLfQEnw5lDgdZZwuEBrrAhj7EZs5or7-Z-c44SQqcV8Sk-vHfigwzUxYFSl_XwKhPzX0Um0Vq_cvO2rEJfMUg\",\"dp\":\"Wb6nN1AGNKPm8TN0VTjx4lkKPCu1bN6nrni6FikX4tBeQGkEzEnSVSspk1bC3kiozrvLqdPCPw1ryiY2ir4LfQ\",\"dq\":\"dtuamYTIJfv7hFPEGjvA_eV3ggb_DMbjozI1_pmMYIFbxi67xt_B6K_CoUWaMhl9ph0zhHQAqkdEvwQXIDKJLQ\",\"n\":\"v14JeirNyQRQPuvF2m76J81gUc8fGUoLWabUbM3uzoPGmK65-F80bqGl7LuNEzNthO67evOGM30S88AixLPXx-ovq_9sppCTn_zF6USlIodsQ6R_8SIUS8_yw982IjvoideP1UhyhNVfRMADZ6DmMRxo_MalWNIt8GVRGPubJME\"},{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"2\",\"n\":\"v14JeirNyQRQPuvF2m76J81gUc8fGUoLWabUbM3uzoPGmK65-F80bqGl7LuNEzNthO67evOGM30S88AixLPXx-ovq_9sppCTn_zF6USlIodsQ6R_8SIUS8_yw982IjvoideP1UhyhNVfRMADZ6DmMRxo_MalWNIt8GVRGPubJME\"}]");
    }

    @Test
    void keyModelWithOkpKeys() {
        KeysModel model = keysModel()
                .withOKPKey(X25519Private)
                .withOKPKey(X25519Public)
                .build();

        String json = model.serialize();

        assertThat(json).isEqualTo("[{\"kty\":\"OKP\",\"d\":\"-BE8qqBr76x_Co4gGNnscUQ9snTfCpr_FtshnbtPoEw\",\"crv\":\"X25519\",\"kid\":\"1\",\"x\":\"wkCeJq_OWjW7jEXyLFnFOz_ZMfEcTssin8MPvl4PEyI\"},{\"kty\":\"OKP\",\"crv\":\"X25519\",\"kid\":\"2\",\"x\":\"wkCeJq_OWjW7jEXyLFnFOz_ZMfEcTssin8MPvl4PEyI\"}]");
    }

    @Test
    void keyModelWithPasswordKeys() {
        KeysModel model = keysModel()
                .withKey(new PasswordKey("testKeyId", "secret", 8, 1337))
                .withKey(new PasswordKey("another", "shrubbery", 8, 1337))
                .build();

        String json = model.serialize();

        assertThat(json).isEqualTo("[{\"password\":\"secret\",\"key_id\":\"testKeyId\",\"salt_length\":8,\"iterations\":1337},{\"password\":\"shrubbery\",\"key_id\":\"another\",\"salt_length\":8,\"iterations\":1337}]");
    }

    @Test
    void deleteMultipleKeys() {
        KeysModel model = keysModel()
                .withRSAKey(RSA1024Private)
                .withRSAKey(RSA1024Public)
                .withKey(new PasswordKey("testKeyId", "secret", 8, 1337))
                .withKey(new PasswordKey("another", "shrubbery", 8, 1337))
                .build();

        model.deleteKeys(new int[]{0, 3, 1, 2});

        assertThat(model.keys()).isEmpty();
    }

    @Test
    void deleteMultipleKeys_listenerOnlyFiresOncePerKey() {
        AtomicInteger noOfListenerInvocations = new AtomicInteger();
        KeysModel model = keysModel()
                .withRSAKey(RSA1024Private)
                .withRSAKey(RSA1024Public)
                .withKey(new PasswordKey("testKeyId", "secret", 8, 1337))
                .withKey(new PasswordKey("another", "shrubbery", 8, 1337))
                .build();
        model.addKeyModelListener(new InertKeyModelListener() {
            @Override
            public void notifyKeyDeleted(int rowIndex) {
                noOfListenerInvocations.incrementAndGet();
            }
        });

        model.deleteKeys(new int[]{0, 3, 1, 2});

        assertThat(noOfListenerInvocations.get()).isEqualTo(4);
    }
}