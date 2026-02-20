package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import javax.imageio.ImageIO;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

/**
 * Image Viewer extension for Burp Suite using the Montoya API.
 * Renders image responses and embedded image payloads in JSON/HTML without blocking the UI thread.
 */
public class BurpExtender implements BurpExtension, HttpResponseEditorProvider, ExtensionUnloadingHandler {

    private MontoyaApi api;
    private ExecutorService worker;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.worker = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "image-viewer-worker");
            t.setDaemon(true);
            return t;
        });

        api.extension().setName("Image Viewer");
        api.extension().registerUnloadingHandler(this);
        api.userInterface().registerHttpResponseEditorProvider(this);
        api.logging().logToOutput("Image Viewer: renders image responses and embedded image payloads.");
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context) {
        return new ImageResponseEditor(api, worker);
    }

    @Override
    public void extensionUnloaded() {
        if (worker != null) {
            worker.shutdownNow();
        }
    }

    private static final class ImageResponseEditor implements ExtensionProvidedHttpResponseEditor {
        private static final int MAX_EXTRACTED_IMAGES = 24;

        private final Logging log;
        private final ExecutorService worker;
        private final JPanel panel;
        private final JLabel statusLabel;
        private final JLabel previewLabel;
        private final DefaultListModel<ImageEntry> imageListModel;
        private final JList<ImageEntry> imageList;
        private final AtomicLong renderVersion;

        private Future<?> currentTask;
        private HttpRequestResponse current;

        ImageResponseEditor(MontoyaApi api, ExecutorService worker) {
            this.worker = worker;
            this.log = api.logging();
            this.renderVersion = new AtomicLong(0);

            this.panel = new JPanel(new BorderLayout(8, 8));

            this.statusLabel = new JLabel("No response to render.");
            this.statusLabel.setForeground(Color.GRAY);
            panel.add(statusLabel, BorderLayout.NORTH);

            this.imageListModel = new DefaultListModel<>();
            this.imageList = new JList<>(imageListModel);
            this.imageList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            JScrollPane listScroll = new JScrollPane(imageList);
            listScroll.setPreferredSize(new Dimension(280, 300));

            this.previewLabel = new JLabel("", SwingConstants.CENTER);
            this.previewLabel.setVerticalAlignment(SwingConstants.TOP);
            this.previewLabel.setForeground(Color.GRAY);
            JScrollPane previewScroll = new JScrollPane(previewLabel);

            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listScroll, previewScroll);
            splitPane.setResizeWeight(0.25);
            panel.add(splitPane, BorderLayout.CENTER);

            this.imageList.addListSelectionListener(event -> {
                if (!event.getValueIsAdjusting()) {
                    updatePreviewFromSelection();
                }
            });
        }

        @Override
        public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
            this.current = httpRequestResponse;
            cancelCurrentTask();

            long version = renderVersion.incrementAndGet();
            clearUi("No response to render.");

            if (httpRequestResponse == null || httpRequestResponse.response() == null) {
                return;
            }

            showStatus("Rendering images...");
            currentTask = worker.submit(() -> renderAsync(httpRequestResponse.response(), version));
        }

        @Override
        public HttpResponse getResponse() {
            return current != null ? current.response() : null;
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (requestResponse == null || requestResponse.response() == null) {
                return false;
            }

            HttpResponse response = requestResponse.response();
            String contentType = response.headerValue("Content-Type");
            if (contentType != null && contentType.toLowerCase(Locale.ROOT).startsWith("image/")) {
                return true;
            }

            byte[] body = response.body().getBytes();
            try {
                byte[] decoded = decodeBody(body, response.headerValue("Content-Encoding"));
                return MagicSniffer.looksLikeImage(decoded, 0)
                        || ImageExtractor.looksLikeEmbeddedImagePayload(decoded, contentType);
            } catch (IOException e) {
                return MagicSniffer.looksLikeImage(body, 0);
            }
        }

        @Override
        public String caption() {
            return "Images";
        }

        @Override
        public Component uiComponent() {
            return panel;
        }

        @Override
        public Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }

        private void renderAsync(HttpResponse response, long version) {
            try {
                byte[] body = decodeBody(response.body().getBytes(), response.headerValue("Content-Encoding"));
                List<ImageEntry> images = ImageExtractor.extract(body, response.headerValue("Content-Type"), MAX_EXTRACTED_IMAGES);

                if (isStale(version)) {
                    return;
                }

                if (images.isEmpty()) {
                    clearUiOnEdt(version, "No supported image found in response body.");
                    return;
                }

                updateGalleryOnEdt(version, images);
            } catch (Exception e) {
                logException("Unable to render images", e);
                clearUiOnEdt(version, "Unable to render images: " + e.getMessage());
            }
        }

        private boolean isStale(long version) {
            return version != renderVersion.get();
        }

        private void updateGalleryOnEdt(long version, List<ImageEntry> images) {
            SwingUtilities.invokeLater(() -> {
                if (isStale(version)) {
                    return;
                }
                imageListModel.clear();
                for (ImageEntry entry : images) {
                    imageListModel.addElement(entry);
                }
                statusLabel.setText("Found " + imageListModel.size() + " image(s).");
                statusLabel.setForeground(Color.GRAY);
                if (!imageListModel.isEmpty()) {
                    imageList.setSelectedIndex(0);
                }
            });
        }

        private void clearUiOnEdt(long version, String message) {
            SwingUtilities.invokeLater(() -> {
                if (isStale(version)) {
                    return;
                }
                clearUi(message);
            });
        }

        private void updatePreviewFromSelection() {
            ImageEntry selected = imageList.getSelectedValue();
            if (selected == null) {
                previewLabel.setText("Select an image.");
                previewLabel.setIcon(null);
                return;
            }

            previewLabel.setText("");
            previewLabel.setIcon(selected.icon);
            statusLabel.setText(selected.details);
            statusLabel.setForeground(Color.GRAY);
        }

        private void showStatus(String message) {
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText(message);
                statusLabel.setForeground(Color.GRAY);
            });
        }

        private void clearUi(String message) {
            Runnable runnable = () -> {
                imageListModel.clear();
                previewLabel.setIcon(null);
                previewLabel.setText(message);
                statusLabel.setText(message);
                statusLabel.setForeground(Color.GRAY);
            };
            if (SwingUtilities.isEventDispatchThread()) {
                runnable.run();
            } else {
                SwingUtilities.invokeLater(runnable);
            }
        }

        private void cancelCurrentTask() {
            if (currentTask != null) {
                currentTask.cancel(true);
                currentTask = null;
            }
        }

        private void logException(String message, Exception e) {
            log.logToError(message + ": " + e.getMessage());
            if (log.error() != null) {
                e.printStackTrace(log.error());
            }
        }

        private byte[] decodeBody(byte[] body, String encodingHeader) throws IOException {
            if (body == null) {
                return null;
            }

            if (encodingHeader == null) {
                return body;
            }

            String lowered = encodingHeader.toLowerCase(Locale.ROOT);
            if (lowered.contains("gzip")) {
                try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(body))) {
                    return readAll(gis);
                }
            }

            if (lowered.contains("deflate")) {
                try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(body))) {
                    return readAll(iis);
                }
            }

            return body;
        }

        private byte[] readAll(InputStream in) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }

        private static final class ImageEntry {
            private final String label;
            private final String details;
            private final ImageIcon icon;

            private ImageEntry(String label, String details, ImageIcon icon) {
                this.label = label;
                this.details = details;
                this.icon = icon;
            }

            @Override
            public String toString() {
                return label;
            }
        }

        private static final class ImageExtractor {
            private static final int MAX_TEXT_SCAN_BYTES = 2 * 1024 * 1024;
            private static final int MIN_BASE64_LENGTH = 96;
            private static final int MAX_DECODED_IMAGE_BYTES = 8 * 1024 * 1024;
            private static final Pattern DATA_URI_BASE64_PATTERN = Pattern.compile(
                    "data:image/([a-zA-Z0-9.+-]+);base64,([A-Za-z0-9+/=_%\\\\\\s-]{32,})",
                    Pattern.CASE_INSENSITIVE);
            private static final Pattern DATA_URI_RAW_PATTERN = Pattern.compile(
                    "data:image/([a-zA-Z0-9.+-]+),([A-Za-z0-9%._~!$&'()*+,;=:@/?-]{16,})",
                    Pattern.CASE_INSENSITIVE);
            private static final Pattern EMBEDDED_BASE64_PATTERN = Pattern.compile(
                    "(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{" + MIN_BASE64_LENGTH + ",}={0,2})(?![A-Za-z0-9+/=_-])");

            private ImageExtractor() {
            }

            static boolean looksLikeEmbeddedImagePayload(byte[] body, String contentType) {
                if (body == null || body.length == 0 || !isLikelyText(contentType, body)) {
                    return false;
                }

                int scanLen = Math.min(body.length, 256 * 1024);
                String sample = new String(body, 0, scanLen, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
                return sample.contains("data:image/")
                        || sample.contains("ivborw0kggo")
                        || sample.contains("/9j/")
                        || sample.contains("r0lgod");
            }

            static List<ImageEntry> extract(byte[] body, String contentType, int maxImages) {
                List<ImageEntry> images = new ArrayList<>();
                if (body == null || body.length == 0) {
                    return images;
                }

                Set<String> seenFingerprints = new LinkedHashSet<>();
                addDecodedImage(images, seenFingerprints, "Body image", contentType, body, maxImages);

                if (images.size() >= maxImages || !isLikelyText(contentType, body)) {
                    return images;
                }

                int scanLen = Math.min(body.length, MAX_TEXT_SCAN_BYTES);
                String text = new String(body, 0, scanLen, StandardCharsets.ISO_8859_1);

                extractDataUriBase64(text, images, seenFingerprints, maxImages);
                if (images.size() >= maxImages) {
                    return images;
                }

                extractDataUriRaw(text, images, seenFingerprints, maxImages);
                if (images.size() >= maxImages) {
                    return images;
                }

                extractEmbeddedBase64(text, images, seenFingerprints, maxImages);
                return images;
            }

            private static void extractDataUriBase64(
                    String text, List<ImageEntry> images, Set<String> seenFingerprints, int maxImages) {
                Matcher matcher = DATA_URI_BASE64_PATTERN.matcher(text);
                int index = 1;
                while (matcher.find() && images.size() < maxImages) {
                    String imageType = matcher.group(1).toLowerCase(Locale.ROOT);
                    byte[] decoded = decodeBase64(matcher.group(2));
                    if (decoded == null) {
                        continue;
                    }
                    String title = "Data URI #" + index;
                    addDecodedImage(images, seenFingerprints, title, "image/" + imageType, decoded, maxImages);
                    index++;
                }
            }

            private static void extractDataUriRaw(
                    String text, List<ImageEntry> images, Set<String> seenFingerprints, int maxImages) {
                Matcher matcher = DATA_URI_RAW_PATTERN.matcher(text);
                int index = 1;
                while (matcher.find() && images.size() < maxImages) {
                    String imageType = matcher.group(1).toLowerCase(Locale.ROOT);
                    byte[] decoded = percentDecode(matcher.group(2));
                    if (decoded == null) {
                        continue;
                    }
                    String title = "Data URI (raw) #" + index;
                    addDecodedImage(images, seenFingerprints, title, "image/" + imageType, decoded, maxImages);
                    index++;
                }
            }

            private static void extractEmbeddedBase64(
                    String text, List<ImageEntry> images, Set<String> seenFingerprints, int maxImages) {
                Matcher matcher = EMBEDDED_BASE64_PATTERN.matcher(text);
                int index = 1;
                while (matcher.find() && images.size() < maxImages) {
                    byte[] decoded = decodeBase64(matcher.group(1));
                    if (decoded == null || !MagicSniffer.looksLikeImage(decoded, 0)) {
                        continue;
                    }
                    String title = "Embedded base64 #" + index;
                    addDecodedImage(images, seenFingerprints, title, null, decoded, maxImages);
                    index++;
                }
            }

            private static boolean addDecodedImage(
                    List<ImageEntry> images,
                    Set<String> seenFingerprints,
                    String source,
                    String contentType,
                    byte[] raw,
                    int maxImages) {
                if (raw == null || raw.length == 0 || raw.length > MAX_DECODED_IMAGE_BYTES || images.size() >= maxImages) {
                    return false;
                }

                String fingerprint = fingerprint(raw);
                if (!seenFingerprints.add(fingerprint)) {
                    return false;
                }

                BufferedImage image = readImage(raw);
                if (image == null) {
                    return false;
                }

                String label = source + " (" + image.getWidth() + "x" + image.getHeight() + ")";
                String details = source
                        + " | "
                        + (contentType != null ? contentType : "unknown type")
                        + " | "
                        + image.getWidth()
                        + "x"
                        + image.getHeight()
                        + " | "
                        + raw.length
                        + " bytes";
                images.add(new ImageEntry(label, details, new ImageIcon(image)));
                return true;
            }

            private static String fingerprint(byte[] bytes) {
                CRC32 crc = new CRC32();
                crc.update(bytes, 0, bytes.length);
                return bytes.length + ":" + crc.getValue();
            }

            private static boolean isLikelyText(String contentType, byte[] body) {
                if (contentType != null) {
                    String lowered = contentType.toLowerCase(Locale.ROOT);
                    if (lowered.contains("json")
                            || lowered.contains("html")
                            || lowered.contains("xml")
                            || lowered.contains("javascript")
                            || lowered.contains("x-www-form-urlencoded")
                            || lowered.startsWith("text/")) {
                        return true;
                    }
                }

                int sample = Math.min(body.length, 1024);
                int suspicious = 0;
                for (int i = 0; i < sample; i++) {
                    int b = body[i] & 0xFF;
                    if (b == 0) {
                        return false;
                    }
                    if (b < 0x09 || (b > 0x0D && b < 0x20)) {
                        suspicious++;
                    }
                }
                return suspicious < sample / 8;
            }

            private static byte[] decodeBase64(String payload) {
                if (payload == null) {
                    return null;
                }

                String normalized = payload
                        .replace("\\/", "/")
                        .replace("\\n", "")
                        .replace("\\r", "")
                        .replace("\\t", "")
                        .replace("\r", "")
                        .replace("\n", "")
                        .replace("\t", "")
                        .replace(" ", "");

                if (normalized.indexOf('%') >= 0) {
                    byte[] percentDecoded = percentDecode(normalized);
                    if (percentDecoded != null) {
                        normalized = new String(percentDecoded, StandardCharsets.ISO_8859_1);
                    }
                }

                if (normalized.length() < MIN_BASE64_LENGTH || normalized.length() > (MAX_DECODED_IMAGE_BYTES * 2)) {
                    return null;
                }

                int padding = normalized.length() % 4;
                if (padding != 0) {
                    normalized = normalized + "=".repeat(4 - padding);
                }

                try {
                    byte[] decoded;
                    if (normalized.indexOf('-') >= 0 || normalized.indexOf('_') >= 0) {
                        decoded = Base64.getUrlDecoder().decode(normalized);
                    } else {
                        decoded = Base64.getDecoder().decode(normalized);
                    }
                    if (decoded.length == 0 || decoded.length > MAX_DECODED_IMAGE_BYTES) {
                        return null;
                    }
                    return decoded;
                } catch (IllegalArgumentException e) {
                    return null;
                }
            }

            private static byte[] percentDecode(String value) {
                if (value == null) {
                    return null;
                }

                ByteArrayOutputStream out = new ByteArrayOutputStream(value.length());
                for (int i = 0; i < value.length(); i++) {
                    char ch = value.charAt(i);
                    if (ch != '%') {
                        out.write((byte) ch);
                        continue;
                    }
                    if (i + 2 >= value.length()) {
                        return null;
                    }
                    int hi = Character.digit(value.charAt(i + 1), 16);
                    int lo = Character.digit(value.charAt(i + 2), 16);
                    if (hi < 0 || lo < 0) {
                        return null;
                    }
                    out.write((hi << 4) + lo);
                    i += 2;
                }
                return out.toByteArray();
            }

            private static BufferedImage readImage(byte[] body) {
                try (ByteArrayInputStream in = new ByteArrayInputStream(body)) {
                    return ImageIO.read(in);
                } catch (IOException e) {
                    return null;
                }
            }
        }
    }

    /**
     * Lightweight magic-number sniffing so the tab enables even when content-type
     * headers are missing.
     */
    private static final class MagicSniffer {
        private static final byte[] PNG = {(byte) 0x89, 0x50, 0x4E, 0x47};

        private MagicSniffer() {
        }

        static boolean looksLikeImage(byte[] content, int offset) {
            if (content == null || offset < 0 || offset >= content.length) {
                return false;
            }

            int available = content.length - offset;
            int maxProbe = Math.min(available, 12);
            byte[] probe = Arrays.copyOfRange(content, offset, offset + maxProbe);

            if (matches(probe, PNG)) {
                return true; // PNG
            }

            if (available >= 3 && (probe[0] & 0xFF) == 0xFF && (probe[1] & 0xFF) == 0xD8 && (probe[2] & 0xFF) == 0xFF) {
                return true; // JPEG
            }

            if (available >= 3 && probe[0] == 'G' && probe[1] == 'I' && probe[2] == 'F') {
                return true; // GIF
            }

            if (available >= 2 && probe[0] == 'B' && probe[1] == 'M') {
                return true; // BMP
            }

            if (available >= 12
                    && probe[0] == 'R' && probe[1] == 'I' && probe[2] == 'F' && probe[3] == 'F'
                    && probe[8] == 'W' && probe[9] == 'E' && probe[10] == 'B' && probe[11] == 'P') {
                return true; // WebP
            }

            return false;
        }

        private static boolean matches(byte[] data, byte[] magic) {
            if (data.length < magic.length) {
                return false;
            }
            for (int i = 0; i < magic.length; i++) {
                if (data[i] != magic[i]) {
                    return false;
                }
            }
            return true;
        }
    }
}
