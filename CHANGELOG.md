# Changelog
## [2.6](https://github.com/DolphFlynn/jwt-editor/releases/tag/2.6) 2025-04-05
- Add Tokens view and ability to store interesting JWS within project file.
- Display JWS TimeClaims in default time zone (Thanks again to [@Nirusu](https://github.com/Nirusu)).
- Remember last used signing key within Attack dialogs.

## [2.5](https://github.com/DolphFlynn/jwt-editor/releases/tag/2.5) 2025-01-13
- Add ability to test for HMAC signatures using [weak secrets](https://github.com/wallarm/jwt-secrets).
- Add import capability for JWK data.
- Add support for decimal TimeClaims (Thanks to [@Nirusu](https://github.com/Nirusu)).
- Remember last used key within signing dialogs.

## [2.4](https://github.com/DolphFlynn/jwt-editor/releases/tag/2.4) 2024-12-24
- Add support for non-JSON claims within JWS (Thanks to [@Hannah-PortSwigger](https://github.com/Hannah-PortSwigger) for suggesting this).

## [2.3](https://github.com/DolphFlynn/jwt-editor/releases/tag/2.3) 2024-08-05
- Add Information panel to JWS view showing decoded *iat*, *nbf* and *exp* values (Thanks to [@exploide](https://github.com/exploide) for collaborating on this).
- Add support for WebSocket messages containing JWT's.
- Preserve JWT order when message has multiple JWT's.
- Remove use of commons-lang3.

## [2.2.2](https://github.com/DolphFlynn/jwt-editor/releases/tag/2.2.2) 2024-07-12
- Fix issue where JWT's highlighted in Proxy regardless of config setting (Thanks to [@serate-actual](https://github.com/serate-actual) for reporting this).

## [2.2.1](https://github.com/DolphFlynn/jwt-editor/releases/tag/2.2.1) 2024-05-06
- Fix issue where an invalid Intruder signing key could prevent the extension from loading (Thanks to [@sebastianosrt](https://github.com/sebastianosrt) for reporting this).

## 2.2 2024-02-29
- Allow resigning of JWS tokens during fuzzing (Thanks to [@BafDyce](https://github.com/BafDyce)).

## 2.1.1 2024-01-22
- Use split panes to improve JWT editor with small screens or large font sizes (Thanks to [@eldstal](https://github.com/eldstal)).

## 2.1 2024-01-01
- Allow key IDs to be set before keys generated.
- Make symmetric and asymmetric key dialogs consistent.
- Fix bug allowing keys with duplicate IDs.


## 2.0.2 2023-12-13
- Fix memory leaks when deleting tabs containing JWTs.


## 2.0.1  2023-10-30
- Generate valid URL's when embedding Collaborator payloads within *x5u* and *jku* headers.


## 2.0  2023-07-08

Forked from [Fraser Winterborn](https://uk.linkedin.com/in/fraser-winterborn-198b8a129)'s version (original [repository](https://github.com/blackberry/jwt-editor)).
* Payload processing rule to support fuzzing within JWS.
* Insertion point provider for JWS header parameters.
* JWT highlighting within WebSocket messages.
* Update to Java 17 and PortSwigger's new Montoya API.
* Add ability to enable/disable JWT highlighting within proxied messages and to change highlight color.
* Add ability to inject Collaborator payloads into x5u and jku headers.
* Fix issue where invalid JWS's not recognised.
* Add ability to export keys as a JWK set.
* Add ability to sign with empty keys (CVE-2019-20933).
* Add ability to sign with psychic signatures (CVE-2022-21449).
* Color sections of serialized JWT differently. 
* Remove standalone mode.
* Minor bug fixes and enhancements.
