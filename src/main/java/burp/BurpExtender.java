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
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

/**
 * Image Viewer extension for Burp Suite using the Montoya API.
 * Renders common image responses in a dedicated "Image" tab without
 * blocking the UI thread.
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
        api.logging().logToOutput("Image Viewer: renders image responses.");
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
        private final MontoyaApi api;
        private final Logging log;
        private final ExecutorService worker;
        private final JPanel panel;
        private final JLabel imageLabel;

        private Future<?> currentTask;
        private HttpRequestResponse current;

        ImageResponseEditor(MontoyaApi api, ExecutorService worker) {
            this.api = api;
            this.worker = worker;
            this.log = api.logging();

            this.panel = new JPanel(new BorderLayout());
            this.imageLabel = new JLabel("", SwingConstants.CENTER);
            this.imageLabel.setVerticalAlignment(SwingConstants.TOP);
            this.imageLabel.setForeground(Color.GRAY);

            JScrollPane scrollPane = new JScrollPane(imageLabel);
            panel.add(scrollPane, BorderLayout.CENTER);
        }

        @Override
        public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
            this.current = httpRequestResponse;
            cancelCurrentTask();

            if (httpRequestResponse == null || httpRequestResponse.response() == null) {
                showInfo("No response to render.");
                return;
            }

            showInfo("Rendering image...");
            currentTask = worker.submit(() -> renderAsync(httpRequestResponse.response()));
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

            return MagicSniffer.looksLikeImage(response.body().getBytes(), 0);
        }

        @Override
        public String caption() {
            return "Image";
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

        private void renderAsync(HttpResponse response) {
            try {
                byte[] body = decodeBody(response.body().getBytes(), response.headerValue("Content-Encoding"));
                BufferedImage image = readImage(body);

                if (image == null) {
                    updateLabel("Response is not a supported image.", null);
                } else {
                    ImageIcon icon = new ImageIcon(image);
                    updateLabel("", icon);
                }
            } catch (Exception e) {
                logException("Unable to render image", e);
                updateLabel("Unable to render image: " + e.getMessage(), null);
            }
        }

        private void updateLabel(String text, ImageIcon icon) {
            SwingUtilities.invokeLater(() -> {
                imageLabel.setText(text);
                imageLabel.setIcon(icon);
            });
        }

        private void showInfo(String text) {
            updateLabel(text, null);
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

        private BufferedImage readImage(byte[] body) throws IOException {
            if (body == null || body.length == 0) {
                return null;
            }

            try (ByteArrayInputStream in = new ByteArrayInputStream(body)) {
                return ImageIO.read(in);
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
            if (content == null || offset >= content.length) {
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
