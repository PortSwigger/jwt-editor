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

package burp.intruder;

import static burp.intruder.FuzzLocation.PAYLOAD;

public class IntruderConfig {
    private String fuzzParameter;
    private FuzzLocation fuzzLocation;
    private String signingKeyId;
    private boolean resign;

    public IntruderConfig() {
        this.fuzzParameter = "name";
        this.fuzzLocation = PAYLOAD;
    }

    public String fuzzParameter() {
        return fuzzParameter;
    }

    public void setFuzzParameter(String fuzzParameter) {
        this.fuzzParameter = fuzzParameter;
    }

    public FuzzLocation fuzzLocation() {
        return fuzzLocation;
    }

    public void setFuzzLocation(FuzzLocation fuzzLocation) {
        this.fuzzLocation = fuzzLocation;
    }

    public String signingKeyId() {
        return signingKeyId;
    }

    public void setSigningKeyId(String signingKeyId) {
        this.signingKeyId = signingKeyId;
    }

    public boolean resign() {
        return resign;
    }

    public void setResign(boolean resign) {
        this.resign = resign;
    }
}
