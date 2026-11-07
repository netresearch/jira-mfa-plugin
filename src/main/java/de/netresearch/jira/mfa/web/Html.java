package de.netresearch.jira.mfa.web;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/** Minimal HTML rendering for the plugin's standalone pages. */
public final class Html {
    private Html() {
    }

    public static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '&': b.append("&amp;"); break;
                case '<': b.append("&lt;"); break;
                case '>': b.append("&gt;"); break;
                case '"': b.append("&quot;"); break;
                case '\'': b.append("&#39;"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }

    private static final String CSS = String.join("\n",
            ":root{--fg:#172b4d;--muted:#5e6c84;--bg:#f4f5f7;--card:#fff;--line:#dfe1e6;--accent:#0052cc;--accent-fg:#fff;--err:#bf2600;--ok:#006644;--warn-bg:#fffae6}",
            "@media (prefers-color-scheme: dark){:root{--fg:#e6edf3;--muted:#9fadbc;--bg:#1d2125;--card:#22272b;--line:#3b444c;--accent:#579dff;--accent-fg:#1d2125;--err:#ff8f73;--ok:#7ee2b8;--warn-bg:#533f04}}",
            "*{box-sizing:border-box}body{margin:0;font:16px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:var(--fg);background:var(--bg)}",
            "main{max-width:40rem;margin:2rem auto;padding:0 1rem}",
            ".card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:1.5rem;margin-bottom:1rem}",
            "h1{font-size:1.5rem;margin:0 0 1rem}h2{font-size:1.15rem;margin:0 0 .75rem}",
            "label{display:block;font-weight:600;margin:.75rem 0 .25rem}",
            "input[type=text],input[type=number],textarea,select{width:100%;padding:.5rem;font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:4px}",
            "input:focus-visible,button:focus-visible,a:focus-visible,textarea:focus-visible{outline:3px solid var(--accent);outline-offset:2px}",
            "button{font:inherit;padding:.5rem 1rem;border-radius:4px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);cursor:pointer;margin-top:1rem}",
            "button.secondary{background:transparent;color:var(--accent)}",
            "a{color:var(--accent)}.muted{color:var(--muted)}",
            ".error{color:var(--err);font-weight:600}.ok{color:var(--ok);font-weight:600}",
            ".notice{background:var(--warn-bg);border:1px solid var(--line);border-radius:4px;padding:.75rem;margin-bottom:1rem}",
            ".codes{font-family:ui-monospace,monospace;font-size:1.1rem;columns:2;list-style:none;padding:0}",
            "code{font-family:ui-monospace,monospace;word-break:break-all}",
            ".qr{background:#fff;padding:8px;display:inline-block;border-radius:4px}",
            "table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.4rem;border-bottom:1px solid var(--line)}",
            ".inline{display:inline}.inline button{margin-top:0}",
            ".topbar{background:var(--card);border-bottom:1px solid var(--line)}",
            ".topbar nav{max-width:40rem;margin:0 auto;padding:.6rem 1rem;display:flex;flex-wrap:wrap;gap:.5rem 1.25rem;align-items:center}",
            ".topbar .home{font-weight:600;margin-right:auto}.topbar .who{color:var(--muted)}");

    public static void page(HttpServletResponse resp, String title, String header, String body, String scriptUrl) throws IOException {
        resp.setContentType("text/html;charset=UTF-8");
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("X-Frame-Options", "DENY");
        resp.setHeader("Referrer-Policy", "no-referrer");
        StringBuilder b = new StringBuilder(4096);
        b.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
                .append("<meta name=\"decorator\" content=\"none\">")
                .append("<title>").append(esc(title)).append("</title><style>").append(CSS).append("</style></head><body>")
                .append(header == null ? "" : header).append("<main>")
                .append(body).append("</main>");
        if (scriptUrl != null) {
            b.append("<script src=\"").append(esc(scriptUrl)).append("\"></script>");
        }
        b.append("</body></html>");
        resp.getWriter().write(b.toString());
    }

    public static String hidden(String name, String value) {
        return "<input type=\"hidden\" name=\"" + esc(name) + "\" value=\"" + esc(value) + "\">";
    }

    public static String dataAttrs(Map<String, String> attrs) {
        StringBuilder b = new StringBuilder();
        attrs.forEach((k, v) -> b.append(" data-").append(esc(k)).append("=\"").append(esc(v)).append('"'));
        return b.toString();
    }

    /** Renders a QR code as inline SVG. */
    public static String qrSvg(String content, String label) {
        try {
            BitMatrix m = new QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 0, 0,
                    Map.of(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M, EncodeHintType.MARGIN, 2));
            int w = m.getWidth();
            int h = m.getHeight();
            StringBuilder path = new StringBuilder();
            for (int y = 0; y < h; y++) {
                for (int x = 0; x < w; x++) {
                    if (m.get(x, y)) {
                        path.append('M').append(x).append(' ').append(y).append("h1v1h-1z");
                    }
                }
            }
            return "<svg xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"" + esc(label) + "\" viewBox=\"0 0 "
                    + w + " " + h + "\" width=\"" + (w * 5) + "\" height=\"" + (h * 5)
                    + "\" shape-rendering=\"crispEdges\"><path fill=\"#000\" d=\"" + path + "\"/></svg>";
        } catch (WriterException e) {
            throw new IllegalStateException("QR encoding failed", e);
        }
    }
}
