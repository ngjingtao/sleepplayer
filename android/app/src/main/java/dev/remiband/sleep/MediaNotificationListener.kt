package dev.remiband.sleep

import android.service.notification.NotificationListenerService

/**
 * Exists only to unlock [MediaGate.playingController].
 *
 * `MediaSessionManager.getActiveSessions` requires an enabled notification
 * listener component. This service never reads a notification -- it has no
 * callbacks implemented at all -- but the grant is the framework's gate for
 * being allowed to pause another app's media, so the user must enable it once in
 * Settings.
 *
 * Declared in AndroidManifest.xml with BIND_NOTIFICATION_LISTENER_SERVICE.
 */
class MediaNotificationListener : NotificationListenerService()
