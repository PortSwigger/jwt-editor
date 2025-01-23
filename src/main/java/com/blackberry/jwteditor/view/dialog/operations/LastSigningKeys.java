package com.blackberry.jwteditor.view.dialog.operations;

import com.blackberry.jwteditor.model.keys.Key;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class LastSigningKeys {
    enum Signer { NORMAL, EMBED_JWK, KEY_CONFUSION }

    private final Map<Signer, Key> lastKeyMap = new HashMap<>();

    Optional<Key> lastKeyFor(Signer mode) {
        return Optional.ofNullable(lastKeyMap.get(mode));
    }

    void recordKeyUse(Signer mode, Key key) {
        lastKeyMap.put(mode, key);
    }
}
