# Burp Image Viewer

Lightweight Burp Suite extension that renders image responses inline, similar to the PDF Reader extension but focused on common image formats (PNG, JPEG, GIF, BMP, WebP).

## Features
- Adds an `Image` tab in message viewers for responses with `image/*` content types or recognizable magic numbers.
- Supports gzip/deflate decoding before rendering.
- Uses native Swing rendering (no external dependencies) so it works anywhere Burp runs.

## Building
With Nix:
```bash
nix develop # optional: drops you in a shell with a JDK and CLASSPATH ready
bash scripts/build.sh
# or nix build
ls result/share/java/burp-image-viewer.jar
```

Without Nix:
1. Ensure a JDK is available.
2. Run `bash scripts/build.sh`.

The jar is written to `dist/burp-image-viewer.jar`.

## Installing in Burp Suite
1. Open Burp → Extender → Extensions → Add.
2. Select `Extension type: Java`.
3. Choose `dist/burp-image-viewer.jar`.
4. Open any HTTP response: if it contains an image, an `Image` tab will render it.

## Notes
- The tab auto-enables on `image/*` content types and when magic bytes for PNG/JPEG/GIF/BMP/WebP are present.
- Unsupported or malformed images fall back to a short status message instead of throwing errors.
