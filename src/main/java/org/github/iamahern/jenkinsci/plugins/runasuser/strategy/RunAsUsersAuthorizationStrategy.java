/*
 * The MIT License
 * 
 * Copyright (c) 2013 IKEDA Yasuyuki
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.github.iamahern.jenkinsci.plugins.runasuser.strategy;

import hudson.Extension;
import hudson.model.*;
import hudson.model.Cause.UpstreamCause;
import hudson.model.Cause.UserIdCause;
import hudson.security.AccessControlled;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Run builds as a user who triggered the build.
 */
public class RunAsUsersAuthorizationStrategy extends AuthorizeProjectStrategy {
    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(RunAsUsersAuthorizationStrategy.class.getName());
    /**
     * Our constructor.
     */
    @DataBoundConstructor
    public RunAsUsersAuthorizationStrategy() {
        // No actions.
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
        Cause.UserIdCause cause = getRootUserIdCause(item);
        if (cause != null) {
            User u = User.get(cause.getUserId(), false, Collections.emptyMap());
            if (u == null) {
                return Jenkins.ANONYMOUS;
            }
            try {
                return u.impersonate();
            } catch (UsernameNotFoundException e) {
                LOGGER.log(Level.WARNING, String.format("Invalid User %s. Falls back to anonymous.", cause.getUserId()), e);
                return Jenkins.ANONYMOUS;
            }
        }
        return null;
    }
    
    /**
     * Returns a cause who triggered this build.
     * 
     * If this is a downstream build, search upstream builds.
     * 
     * @param item the item to query the triggering user of.
     * @return the {@link UserIdCause} or {@code null} if none could be found.
     */
    private UserIdCause getRootUserIdCause(Queue.Item item) {
        if (breakCredentialPluginRunAsSandbox && item instanceof Queue.WaitingItem && item.getCauses().isEmpty()) {
            LOGGER.log(Level.FINE, "Using work around for Credential Plugin security sandbox - create UserIdCause and inherit thread security context.");
            return new UserIdCause();
        }

        Run<?,?> upstream = null;
        for (Cause c: item.getCauses()) {
            if (c instanceof UserIdCause) {
                return (UserIdCause)c;
            } else if (c instanceof UpstreamCause) {
                upstream = ((UpstreamCause)c).getUpstreamRun();
            }
        }
        
        while (upstream != null) {
            UserIdCause cause = upstream.getCause(UserIdCause.class);
            if (cause != null) {
                return cause;
            }
            UpstreamCause upstreamCause = upstream.getCause(UpstreamCause.class);
            upstream = (upstreamCause != null)?upstreamCause.getUpstreamRun():null;
        }
        
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasJobConfigurePermission(AccessControlled context) {
        return context.hasPermission(Item.BUILD);
    }

    /**
     * Workaround for issue with {@link Queue.WaitingItem#getCauses()}.
     *
     * @see #getRootUserIdCause(Queue.Item)
     */
    private boolean breakCredentialPluginRunAsSandbox;

    /**
     * @return whether not to restrict job configuration
     * @see #getRootUserIdCause(Queue.Item)
     * @since 1.3.1
     */
    public boolean isBreakCredentialPluginRunAsSandbox() {
        return breakCredentialPluginRunAsSandbox;
    }

    /**
     * @param breakCredentialPluginRunAsSandbox whether not allow the
     * @see #getRootUserIdCause(Queue.Item)
     * @since 1.3.1
     */
    @DataBoundSetter
    public void setBreakCredentialPluginRunAsSandbox(boolean breakCredentialPluginRunAsSandbox) {
        this.breakCredentialPluginRunAsSandbox = breakCredentialPluginRunAsSandbox;
    }

    /**
     * Our descriptor.
     */
    @Extension
    public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {
        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return Messages.RunAsUsersAuthorizationStrategy_DisplayName();
        }

        /**
         * Display warnings for {@code breakCredentialPluginRunAsSandbox}.
         *
         * "This feature is a security risk; use with caution. For security reasons, the Credential Plugin will
         * not grant access to the credentials of the user running the job without explicit permission. By selecting
         * this option you are assuming the security risks posed by this feature. Use this feature only with great
         * care."
         *
         * @param breakCredentialPluginRunAsSandbox whether not to restrict job configuration
         * @return a warning message for {@code breakCredentialPluginRunAsSandbox} if it is {@code true}
         * @see RunAsUsersAuthorizationStrategy#setBreakCredentialPluginRunAsSandbox(boolean)
         */
        public FormValidation doCheckBreakCredentialPluginRunAsSandbox(@QueryParameter boolean breakCredentialPluginRunAsSandbox) {
            if (breakCredentialPluginRunAsSandbox) {
                return FormValidation.warning(Messages.RunAsUsersAuthorizationStrategy_breakCredentialPluginRunAsSandbox_usage());
            }
            return FormValidation.ok();
        }
    }
}
