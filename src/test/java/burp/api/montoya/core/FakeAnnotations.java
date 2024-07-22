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

package burp.api.montoya.core;

public class FakeAnnotations implements Annotations {
    private String notes;
    private HighlightColor highlightColor;

    @Override
    public String notes() {
        return notes;
    }

    @Override
    public void setNotes(String notes) {
        this.notes = notes;
    }

    @Override
    public HighlightColor highlightColor() {
        return highlightColor;
    }

    @Override
    public void setHighlightColor(HighlightColor highlightColor) {
        this.highlightColor = highlightColor;
    }

    @Override
    public Annotations withNotes(String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Annotations withHighlightColor(HighlightColor highlightColor) {
        throw new UnsupportedOperationException();
    }
}
