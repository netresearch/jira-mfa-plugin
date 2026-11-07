package de.netresearch.jira.mfa.service;

import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.config.properties.APKeys;
import com.atlassian.jira.config.util.JiraHome;
import com.atlassian.jira.permission.GlobalPermissionKey;
import com.atlassian.jira.user.ApplicationUser;

import javax.inject.Named;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

/** Thin access to Jira core components, resolved lazily through ComponentAccessor. */
@Named
public class JiraEnvironment {
    public static final String RECOVERY_ADMIN = "recovery_admin";

    public ApplicationUser currentUser() {
        return ComponentAccessor.getJiraAuthenticationContext().getLoggedInUser();
    }

    public String baseUrl() {
        String url = ComponentAccessor.getApplicationProperties().getString(APKeys.JIRA_BASEURL);
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public Collection<String> groups(ApplicationUser user) {
        if (user == null) {
            return List.of();
        }
        return ComponentAccessor.getGroupManager().getGroupNamesForUser(user);
    }

    public ApplicationUser userByName(String username) {
        return ComponentAccessor.getUserManager().getUserByName(username);
    }

    public ApplicationUser userByKey(String key) {
        return ComponentAccessor.getUserManager().getUserByKey(key);
    }

    /** Every user in every directory, active or not. */
    public Collection<ApplicationUser> allUsers() {
        return ComponentAccessor.getUserManager().getAllApplicationUsers();
    }

    public boolean isSysAdmin(ApplicationUser user) {
        return user != null && ComponentAccessor.getGlobalPermissionManager()
                .hasPermission(GlobalPermissionKey.SYSTEM_ADMIN, user);
    }

    public Path keyFile() {
        JiraHome home = ComponentAccessor.getComponent(JiraHome.class);
        return home.getDataDirectory().toPath().resolve("mfa").resolve("secret.key");
    }

    /**
     * The built-in recovery account exists only while Jira runs with
     * {@code -Datlassian.recovery.password}; it is never challenged, so the
     * documented recovery procedure keeps working.
     */
    public boolean isRecoveryAdmin(ApplicationUser user) {
        return user != null && RECOVERY_ADMIN.equals(user.getUsername())
                && System.getProperty("atlassian.recovery.password") != null;
    }
}
