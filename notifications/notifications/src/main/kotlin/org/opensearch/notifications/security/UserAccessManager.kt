/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.notifications.security

import org.opensearch.OpenSearchStatusException
import org.opensearch.commons.authuser.User
import org.opensearch.core.rest.RestStatus
import org.opensearch.notifications.ResourceSharingClientAccessor
import org.opensearch.notifications.settings.PluginSettings

/**
 * Class for checking/filtering user access.
 */
internal object UserAccessManager : UserAccess {
    const val ADMIN_ROLE = "all_access"

    private fun isResourceSharingEnabled(): Boolean {
        val client = ResourceSharingClientAccessor.getResourceSharingClient()
        return client != null && client.isFeatureEnabledForType("notification_config")
    }

    /**
     * {@inheritDoc}
     */
    override fun validateUser(user: User?) {
        if (isResourceSharingEnabled()) return
        if (PluginSettings.isRbacEnabled() && user?.backendRoles.isNullOrEmpty()) {
            throw OpenSearchStatusException(
                "User doesn't have backend roles configured. Contact administrator.",
                RestStatus.FORBIDDEN
            )
        }
    }

    /**
     * {@inheritDoc}
     */
    override fun getAllAccessInfo(user: User?): List<String> {
        if (isResourceSharingEnabled() || user == null) {
            return listOf()
        }
        return user.backendRoles
    }

    /**
     * {@inheritDoc}
     */
    override fun getSearchAccessInfo(user: User?): List<String> {
        if (isResourceSharingEnabled() || user == null || !PluginSettings.isRbacEnabled() || user.roles.contains(ADMIN_ROLE)) {
            return listOf()
        }
        return user.backendRoles
    }

    /**
     * {@inheritDoc}
     */
    override fun doesUserHaveAccess(user: User?, access: List<String>): Boolean {
        if (isResourceSharingEnabled() || user == null || !PluginSettings.isRbacEnabled()) {
            return true
        }
        return access.isEmpty() || user.roles.contains(ADMIN_ROLE) || user.backendRoles.any { it in access }
    }
}
