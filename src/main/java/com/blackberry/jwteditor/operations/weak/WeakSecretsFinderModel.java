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

package com.blackberry.jwteditor.operations.weak;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.blackberry.jwteditor.operations.weak.WeakSecretsFinderStatus.RUNNING;

public class WeakSecretsFinderModel {
    private final AtomicInteger percentageComplete;
    private final AtomicReference<WeakSecretsFinderStatus> status;
    private final AtomicReference<String> secret;

    public WeakSecretsFinderModel() {
        this.percentageComplete = new AtomicInteger();
        this.status = new AtomicReference<>(RUNNING);
        this.secret = new AtomicReference<>();
    }

    void setProgress(int percentageComplete) {
        this.percentageComplete.set(percentageComplete);
    }

    public int progress() {
        return percentageComplete.get();
    }

    void setSecret(String secret) {
        this.secret.set(secret);
    }

    public String secret() {
        return secret.get();
    }

    public void setStatus(WeakSecretsFinderStatus status) {
        this.status.set(status);
    }

    public WeakSecretsFinderStatus status() {
        return status.get();
    }
}
