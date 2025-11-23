<?php
/*
Plugin Name: IPBan WordPress Integration
Plugin URI: https://ipban.com/
Description: Sends WordPress login success and failure events to IPBan using the IPBan custom log format.
Version: 1.0.0
Author: DigitalRuby (IPBan)
License: MIT

INSTRUCTIONS:
- Drop this file into wp-content/plugins/IPBan/IPBanWordpress.php (create the IPBan folder if it does not exist) and activate the plugin in wp-admin.
- IPBan will detect these lines automatically on Windows (C:/IPBanCustomLogs) and Linux (/var/log) using existing ipban.config entries.
- On Linux, if the web server cannot write to /var/log, the plugin falls back to wp-content/plugins/IPBan/ipbancustom_wordpress.log.
  In that case add that fallback path to <PathAndMask> in ipban.config (e.g. /var/www/html/wp-content/plugins/IPBan/ipbancustom_wordpress.log).
- Log line format examples generated:
  2024-10-10 12:00:00, ipban failed login, ip address: 1.2.3.4, source: WordPress, user: admin
  2024-10-10 12:00:10, ipban success login, ip address: 1.2.3.4, source: WordPress, user: admin
*/

if (!defined('ABSPATH')) {
    exit; // Prevent direct access
}

/**
 * Get remote IP address, considering possible proxy headers.
 */
function ipban_wp_get_remote_ip(): string {
    $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
    foreach ($keys as $k) {
        if (!empty($_SERVER[$k])) {
            // X_FORWARDED_FOR may contain a list, take first
            $parts = explode(',', $_SERVER[$k]);
            $ip = trim($parts[0]);
            if ($ip !== '') {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

/**
 * Write a line to IPBan custom log.
 * @param string $type 'failed' or 'success'
 * @param string $username Username (may be empty for failed attempts)
 */
function ipban_wp_write_line(string $type, string $username): void {
    $ip = ipban_wp_get_remote_ip();
    $source = 'WordPress';
    $timestamp = gmdate('Y-m-d H:i:s'); // UTC
    $user = ($username === '' ? '-' : $username);
    $line = $timestamp . ', ipban ' . $type . ' login, ip address: ' . $ip . ', source: ' . $source . ', user: ' . $user . "\n";

    if (strtoupper(PHP_OS_FAMILY) === 'WINDOWS') {
        $dir = 'C:/IPBanCustomLogs';
        if (!is_dir($dir)) { @mkdir($dir, 0777, true); }
        $file = $dir . '/ipban_wordpress.log';
    } else {
        // Preferred path (already monitored by ipban.config)
        $preferred = '/var/log/ipbancustom_wordpress.log';
        $preferredDir = dirname($preferred);
        if (@is_dir($preferredDir) && @is_writable($preferredDir)) {
            $file = $preferred;
        } else {
            // Fallback path inside plugin directory - requires ipban.config update
            $fallbackDir = WP_CONTENT_DIR . '/plugins/IPBan';
            if (!is_dir($fallbackDir)) { @mkdir($fallbackDir, 0777, true); }
            $file = $fallbackDir . '/ipbancustom_wordpress.log';
        }
    }

    @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
}

/**
 * Failed login hook.
 * @param string $username The attempted username.
 */
function ipban_wp_login_failed(string $username): void {
    ipban_wp_write_line('failed', $username);
}
add_action('wp_login_failed', 'ipban_wp_login_failed');

/**
 * Successful login hook.
 * @param string   $user_login Username.
 * @param WP_User  $user       User object.
 */
function ipban_wp_login_success(string $user_login, $user): void {
    ipban_wp_write_line('success', $user_login);
}
add_action('wp_login', 'ipban_wp_login_success', 10, 2);

/**
 * Optional: Detect XML-RPC authentication failures (common brute force vector).
 * This simplistic approach hooks into the authentication filter; if auth returns a WP_Error we log failed.
 */
function ipban_wp_authenticate($user, $username) {
    if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
        if (is_wp_error($user)) {
            ipban_wp_write_line('failed', (string)$username);
        } elseif ($user instanceof WP_User) {
            ipban_wp_write_line('success', (string)$username);
        }
    }
    return $user;
}
add_filter('authenticate', 'ipban_wp_authenticate', 99, 2);

/**
 * Optional: REST API login attempts (e.g. via /wp-json/jwt-auth/v1/token). You can extend by adding specific action hooks here.
 */
// add_action('jwt_auth_failed', function($error){ ipban_wp_write_line('failed', '-'); });
// add_action('jwt_auth_valid_token_response', function($response){ if(isset($response['user'])) ipban_wp_write_line('success', $response['user']->user_login); });

/* End of IPBan WordPress Integration */
