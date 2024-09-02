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

package burp.api.montoya.core;

import java.util.Objects;

public class FakeRange implements Range {
    private final int start;
    private final int end;

    public FakeRange(int start, int end) {
        this.start = start;
        this.end = end;
    }

    @Override
    public int startIndexInclusive() {
        return start;
    }

    @Override
    public int endIndexExclusive() {
        return end;
    }

    @Override
    public boolean contains(int i) {
        return i >= start && i < end;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        return o instanceof Range range && startIndexInclusive() == range.startIndexInclusive() && endIndexExclusive() == range.endIndexExclusive();
    }

    @Override
    public int hashCode() {
        return Objects.hash(start, end);
    }

    @Override
    public String toString() {
        return "Range{" +
                "start=" + start +
                ", end=" + end +
                '}';
    }
}
