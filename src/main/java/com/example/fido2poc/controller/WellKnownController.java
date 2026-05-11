package com.example.fido2poc.controller;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the {@code /.well-known} association documents required for passkey
 * (WebAuthn) credential sharing between this relying party and native apps.
 *
 * <ul>
 *   <li>{@code /.well-known/webauthn} &mdash; WebAuthn related-origin file.
 *       Allows the browser to verify that this RP ID is authorized
 *       for the given origin when the RP ID is not a registrable domain suffix.</li>
 *   <li>{@code /.well-known/apple-app-site-association} &mdash; Apple App Site
 *       Association (AASA) document. See
 *       <a href="https://developer.apple.com/documentation/xcode/supporting-associated-domains">
 *       Apple Associated Domains</a>.</li>
 *   <li>{@code /.well-known/assetlinks.json} &mdash; Google Digital Asset Links
 *       document used by Android Credential Manager. See
 *       <a href="https://developers.google.com/digital-asset-links/v1/getting-started">
 *       Digital Asset Links</a>.</li>
 * </ul>
 *
 * Production associated domain: {@code https://webauthn-passkey-production.up.railway.app/}.
 * Override the defaults via environment variables.
 */
@RestController
public class WellKnownController {

    private final List<String> aasaApps;
    private final String androidPackage;
    private final List<String> androidSha256Fingerprints;
    private final String rpOrigin;

    public WellKnownController(
            @Value("${webauthn.aasa.apps}") List<String> aasaApps,
            @Value("${webauthn.assetlinks.package}") String androidPackage,
            @Value("${webauthn.assetlinks.sha256}") List<String> androidSha256Fingerprints,
            @Value("${webauthn.rp.origin}") String rpOrigin) {
        this.aasaApps = aasaApps;
        this.androidPackage = androidPackage;
        this.androidSha256Fingerprints = androidSha256Fingerprints;
        this.rpOrigin = rpOrigin;
    }

    /**
     * WebAuthn Related Origin File (draft spec).
     * Returns the list of origins that are authorized to use this RP ID.
     * The browser fetches {@code https://<rpId>/.well-known/webauthn} to validate
     * cross-origin RP ID claims.
     */
    @GetMapping(value = "/.well-known/webauthn",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> webAuthnRelatedOrigins() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("origins", List.of(rpOrigin));
        return ResponseEntity.ok(body);
    }

    @GetMapping(value = "/.well-known/apple-app-site-association",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> appleAppSiteAssociation() {
        Map<String, Object> webcredentials = new LinkedHashMap<>();
        webcredentials.put("apps", aasaApps);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("webcredentials", webcredentials);
        body.put("details", List.of(Map.of("appID", this.aasaApps.get(0), "paths", List.of("*"))));
        body.put("webauthn", Map.of("apps", aasaApps));
        return ResponseEntity.ok(body);
    }

    @GetMapping(value = "/.well-known/assetlinks.json",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>> assetLinks() {
        Map<String, Object> target = new LinkedHashMap<>();
        target.put("namespace", "android_app");
        target.put("package_name", androidPackage);
        target.put("sha256_cert_fingerprints", androidSha256Fingerprints);

        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("relation", List.of("delegate_permission/common.get_login_creds"));
        entry.put("target", target);

        return ResponseEntity.ok(List.of(entry));
    }
}

