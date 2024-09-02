/*
Author : Fraser Winterborn

Copyright 2021 BlackBerry Limited

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

package com.blackberry.jwteditor.model.jose;

import java.util.List;

/**
 * Class for a JOSE object change set
 */
public class MutableJOSEObject {
    private final String original;
    private JOSEObject modified;

    /**
     * Construct a change set from the original compact serialization and the parsed object
     *
     * @param original the original compact serialized JOSE object
     * @param modified the parsed and updated JOSEObject
     */
    public MutableJOSEObject(String original, JOSEObject modified) {
        this.original = original;
        this.modified = modified;
    }

    /**
     * Has the JOSEObject changed from its original serialized version
     *
     * @return true if the JOSEObject has changed
     */
    public boolean changed() {
        return !original.equals(modified.serialize());
    }

    /**
     * Update the parsed object
     *
     * @param joseObject parsed JOSEObject
     */
    public void setModified(JOSEObject joseObject) {
        modified = joseObject;
    }

    /**
     * Get the updated JOSEObject
     *
     * @return updated JOSEObject
     */
    public JOSEObject getModified() {
        return modified;
    }

    /**
     * Get the original serialized JOSE Object
     *
     * @return JOSE object string
     */
    public String getOriginal() {
        return original;
    }

    public List<TimeClaim> timeClaims() {
        return modified.timeClaims();
    }
}
