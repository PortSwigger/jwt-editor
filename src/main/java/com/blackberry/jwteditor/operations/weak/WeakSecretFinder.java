/*
Author : Dolph Flynn

Copyright 2025 Dolph Flynn

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

import burp.api.montoya.logging.Logging;
import com.blackberry.jwteditor.model.jose.JWS;

import java.io.Closeable;
import java.util.concurrent.ExecutorService;

import static com.blackberry.jwteditor.operations.weak.WeakSecretsFinderStatus.*;
import static java.util.concurrent.Executors.newSingleThreadExecutor;

public class WeakSecretFinder implements Closeable {
    private final ExecutorService executorService;
    private final WeakSecretsFinderModel model;
    private final Logging logging;

    public WeakSecretFinder(WeakSecretsFinderModel model, Logging logging) {
        this.model = model;
        this.logging = logging;
        this.executorService = newSingleThreadExecutor();
    }

    public void bruteForce(JWS jws) {
        executorService.submit(new ErrorLoggingRunnable(logging, new Worker(model, jws)));
    }

    @Override
    public void close() {
        executorService.shutdown();
    }

    private static class Worker implements ErrorLoggingRunnable.Task {
        private final WeakSecrets weakSecrets;
        private final WeakSecretsFinderModel model;
        private final WeakSecretTester tester;

        private Worker(WeakSecretsFinderModel model, JWS jws) {
            this.model = model;
            this.weakSecrets = new WeakSecrets();
            this.tester = new WeakSecretTester(jws);
        }

        @Override
        public void action() throws Exception {
            String secret;

            while (model.status() == RUNNING && (secret = weakSecrets.next()) != null) {
                model.setProgress(weakSecrets.progress());

                if (tester.isSecretCorrect(secret)) {
                    model.setStatus(SUCCESS);
                    model.setSecret(secret);
                }
            }

            if (model.status() == RUNNING) {
                model.setStatus(FAILED);
            }
        }
    }
}
