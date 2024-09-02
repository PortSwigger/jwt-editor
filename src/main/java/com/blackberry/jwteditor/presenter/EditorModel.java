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

package com.blackberry.jwteditor.presenter;

import com.blackberry.jwteditor.model.jose.MutableJOSEObject;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static com.blackberry.jwteditor.model.jose.JOSEObjectFinder.extractJOSEObjects;

class EditorModel {
    private static final String JOSE_OBJECT_FORMAT_STRING = "%d - %s";

    private final List<MutableJOSEObject> mutableJoseObjects = new ArrayList<>();
    private final Object lock = new Object();

    private String message;

    void setMessage(String content) {
        synchronized (lock) {
            message = content;
            mutableJoseObjects.clear();
            mutableJoseObjects.addAll(extractJOSEObjects(content));
        }
    }

    List<String> getJOSEObjectStrings() {
        synchronized (lock) {
            AtomicInteger counter = new AtomicInteger();

            return mutableJoseObjects.stream()
                    .map(MutableJOSEObject::getOriginal)
                    .map(serializedJWT -> JOSE_OBJECT_FORMAT_STRING.formatted(counter.incrementAndGet(), serializedJWT))
                    .toList();
        }
    }

    String getMessage() {
        synchronized (lock) {
            for (MutableJOSEObject mutableJoseObject : mutableJoseObjects) {
                if (mutableJoseObject.changed()) {
                    message = message.replace(mutableJoseObject.getOriginal(), mutableJoseObject.getModified().serialize());
                }
            }

            return message;
        }
    }

    boolean isModified() {
        synchronized (lock) {
            return mutableJoseObjects.stream().anyMatch(MutableJOSEObject::changed);
        }
    }

    MutableJOSEObject getJOSEObject(int index) {
        synchronized (lock) {
            return mutableJoseObjects.get(index);
        }
    }
}
