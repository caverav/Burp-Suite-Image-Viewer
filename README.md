# Burp Image Viewer

Lightweight Burp Suite extension that renders image responses inline, similar to the PDF Reader extension but focused on common image formats (PNG, JPEG, GIF, BMP, WebP). Built on the Montoya API.

## Features
- Adds an `Images` tab in message viewers for responses with `image/*` content types or recognizable embedded image payloads.
- Extracts and previews multiple images from a single response body.
- Detects embedded images in JSON/HTML payloads, including:
  - `data:image/...;base64,...` URIs
  - `data:image/...,...` (percent-encoded/raw data URIs)
  - Standalone base64 blobs that decode to known image formats
- Decompresses gzip/deflate before rendering.
- Does image decode/rendering on a worker thread to keep the UI responsive.
- Uses native Swing rendering (no external dependencies beyond Burp’s Montoya API).

## Building
With Nix:
```bash
nix develop # optional: drops you in a shell with JDK + Gradle
bash scripts/build.sh # uses the Gradle wrapper
# or: nix build
ls result/share/java/burp-image-viewer.jar
```

Without Nix:
1. Ensure JDK 17+ is available.
2. Run `./gradlew clean jar` (or `bash scripts/build.sh`).

The jar is written to `dist/burp-image-viewer.jar`.

## Installing in Burp Suite
1. Open Burp → Extender → Extensions → Add.
2. Select `Extension type: Java`.
3. Choose `dist/burp-image-viewer.jar`.
4. Open any HTTP response: if it contains one or more images, an `Images` tab will render them.

## Notes
- The tab auto-enables on `image/*` content types, known image magic bytes, and common embedded image markers in textual payloads.
- Unsupported or malformed images fall back to a short status message instead of throwing errors.
- A background worker is shut down via the Montoya unloading handler for clean extension unloads.

## BApp submission notes
- Uses the Montoya API artifact (`net.portswigger.burp.extensions:montoya-api`) via Gradle.
- All decoding/rendering happens off the EDT to keep Burp responsive.
- Image extraction is bounded (scan and payload limits) to avoid runaway processing on large responses.
- No outbound network calls or external dependencies beyond Burp itself.
- No long-lived references to project data; only the currently viewed message is held.
