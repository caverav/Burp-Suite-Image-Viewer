package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;

/**
 * Image Viewer extension for Burp Suite. Renders common image responses inline,
 * similar to the PDF Reader extension but focused on image formats.
 */
public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Image Viewer");
        callbacks.registerMessageEditorTabFactory(this);
        callbacks.printOutput("Image Viewer: renders images from responses.");
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new ImageViewerTab(controller, helpers);
    }

    private static final class ImageViewerTab implements IMessageEditorTab {
        private final IMessageEditorController controller;
        private final IExtensionHelpers helpers;
        private final JPanel panel;
        private final JLabel imageLabel;
        private final JScrollPane scrollPane;
        private byte[] currentMessage;

        ImageViewerTab(IMessageEditorController controller, IExtensionHelpers helpers) {
            this.controller = controller;
            this.helpers = helpers;
            this.panel = new JPanel(new BorderLayout());

            this.imageLabel = new JLabel("", SwingConstants.CENTER);
            this.imageLabel.setVerticalAlignment(SwingConstants.TOP);
            this.imageLabel.setForeground(Color.GRAY);

            this.scrollPane = new JScrollPane(imageLabel);
            panel.add(scrollPane, BorderLayout.CENTER);
        }

        @Override
        public String getTabCaption() {
            return "Image";
        }

        @Override
        public Component getUiComponent() {
            return panel;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            if (content == null || isRequest) {
                return false;
            }

            IResponseInfo info = helpers.analyzeResponse(content);
            if (info == null) {
                return false;
            }

            List<String> headers = info.getHeaders();
            String contentType = headerValue(headers, "Content-Type");
            if (contentType != null && contentType.toLowerCase(Locale.ROOT).startsWith("image/")) {
                return true;
            }

            int bodyOffset = info.getBodyOffset();
            return MagicSniffer.looksLikeImage(content, bodyOffset);
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            this.currentMessage = content;

            if (content == null || isRequest) {
                showInfo("No response to render.");
                return;
            }

            try {
                IResponseInfo info = helpers.analyzeResponse(content);
                int bodyOffset = info.getBodyOffset();
                byte[] body = Arrays.copyOfRange(content, bodyOffset, content.length);
                byte[] decodedBody = decodeBody(body, info.getHeaders());
                renderImage(decodedBody);
            } catch (Exception e) {
                showInfo("Unable to render image: " + e.getMessage());
            }
        }

        @Override
        public byte[] getMessage() {
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public byte[] getSelectedData() {
            return null;
        }

        private void renderImage(byte[] body) throws IOException {
            if (body == null || body.length == 0) {
                showInfo("Empty response body.");
                return;
            }

            BufferedImage bufferedImage;
            try (ByteArrayInputStream in = new ByteArrayInputStream(body)) {
                bufferedImage = ImageIO.read(in);
            }

            if (bufferedImage == null) {
                showInfo("Response is not a supported image.");
                return;
            }

            imageLabel.setIcon(new ImageIcon(bufferedImage));
            imageLabel.setText("");
        }

        private void showInfo(String text) {
            imageLabel.setIcon(null);
            imageLabel.setText(text);
        }

        private String headerValue(List<String> headers, String headerName) {
            String lowered = headerName.toLowerCase(Locale.ROOT);
            for (String header : headers) {
                int idx = header.indexOf(':');
                if (idx > 0 && header.substring(0, idx).trim().toLowerCase(Locale.ROOT).equals(lowered)) {
                    return header.substring(idx + 1).trim();
                }
            }
            return null;
        }

        private byte[] decodeBody(byte[] body, List<String> headers) throws IOException {
            String encoding = headerValue(headers, "Content-Encoding");
            if (encoding == null) {
                return body;
            }

            String lowered = encoding.toLowerCase(Locale.ROOT);
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
