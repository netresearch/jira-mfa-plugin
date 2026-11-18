package de.netresearch.jira.mfa.web;

import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.util.I18nHelper;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.function.UnaryOperator;

/**
 * Texts of the plugin's pages in the language of the logged-in user (Jira profile
 * language, else Jira's default language), from {@code i18n/mfa*.properties}.
 *
 * <p>The templates carry no markup; {@link #html} escapes the template and its
 * arguments, {@link #htmlWith} takes arguments that are already HTML.
 */
final class Messages {
    static final String PREFIX = "de.netresearch.jira.mfa.ui.";

    private final UnaryOperator<String> templates;
    private final Locale locale;

    Messages(UnaryOperator<String> templates, Locale locale) {
        this.templates = templates;
        this.locale = locale == null ? Locale.ENGLISH : locale;
    }

    static Messages forCurrentUser() {
        I18nHelper i18n = ComponentAccessor.getJiraAuthenticationContext().getI18nHelper();
        return new Messages(k -> i18n.isKeyDefined(k) ? i18n.getUnescapedText(k) : null, i18n.getLocale());
    }

    /** The language tag for the html lang attribute, for example "de" or "en". */
    String lang() {
        String l = locale.getLanguage();
        return l.isEmpty() ? "en" : l;
    }

    /** Plain text of {@code PREFIX + key}, arguments inserted; the key itself if it is missing. */
    String text(String key, Object... args) {
        String t = templates.apply(PREFIX + key);
        if (t == null) {
            return PREFIX + key;
        }
        return args.length == 0 ? t : new MessageFormat(t, locale).format(args);
    }

    /** HTML-escaped text; arguments are escaped too. */
    String html(String key, Object... args) {
        Object[] escaped = new Object[args.length];
        for (int i = 0; i < args.length; i++) {
            escaped[i] = Html.esc(String.valueOf(args[i]));
        }
        return htmlWith(key, escaped);
    }

    /** HTML-escaped template with arguments that the caller has already rendered as HTML. */
    String htmlWith(String key, Object... htmlArgs) {
        String t = templates.apply(PREFIX + key);
        if (t == null) {
            return Html.esc(PREFIX + key);
        }
        String escaped = Html.esc(t);
        return htmlArgs.length == 0 ? escaped : new MessageFormat(escaped, locale).format(htmlArgs);
    }
}
