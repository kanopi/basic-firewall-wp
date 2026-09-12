<?php
/**
 * Plugin Name: Basic Firewall (loader)
 * Description: Runs Basic Firewall as early as a plugin can run. Installed and removed automatically by the Basic Firewall plugin; not intended to be edited.
 * Version:     1.0.0
 * Author:      Kanopi Studios
 *
 * @package Kanopi\BasicFirewall
 */

/*
 * The normal evaluation path.
 *
 * WordPress loads mu-plugins before ordinary plugins, before the theme, and
 * before `init` -- which makes this the earliest point a *plugin* can own. On a
 * site with no page cache that is early enough, and it needs no configuration,
 * which is why it is the default.
 *
 * It is NOT early enough on a site that has a page cache. The order is:
 *
 *     host edge cache (Varnish/CDN)  <- no PHP runs at all
 *       wp-config.php                <- the early path, see bootstrap.php
 *         advanced-cache.php         <- Batcache, W3TC, WP Super Cache: serve and exit
 *           mu-plugins               <- this file
 *             plugins
 *
 * `advanced-cache.php` serves a cached response and calls exit() without ever
 * reaching this file. So on exactly the busy, cached site that most needs a
 * firewall, this loader never runs. Site Health detects that case and points at
 * the wp-config.php deployment.
 *
 * This file is deliberately trivial. It is copied into mu-plugins, where it
 * survives the plugin being deactivated or deleted, so it must do nothing that
 * assumes the plugin is still there.
 */

define( 'BASIC_FIREWALL_MU_LOADER', true );

add_action(
	'muplugins_loaded',
	static function (): void {
		if ( defined( 'BASIC_FIREWALL_EVALUATED' ) ) {
			// The wp-config.php path already evaluated this request.
			return;
		}

		$plugin = WP_PLUGIN_DIR . '/basic-firewall/basic-firewall.php';

		if ( ! is_readable( $plugin ) ) {
			// Plugin deleted, mu-loader left behind. Do nothing at all.
			return;
		}

		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if ( ! is_plugin_active( 'basic-firewall/basic-firewall.php' ) ) {
			// Deactivated in the admin. Respect that.
			return;
		}

		/*
		 * Load the plugin here rather than signalling it.
		 *
		 * The whole point of this file is to run before WordPress would have
		 * loaded the plugin, so at this moment nothing of the plugin exists and
		 * there is nothing listening to an action. Requiring the main file
		 * registers the runtime, and only then is there a listener to fire.
		 *
		 * WordPress includes active plugins with include_once, so its own later
		 * include of this same file is a no-op and nothing loads twice.
		 */
		require_once $plugin;

		/**
		 * Fires once the firewall is loaded early enough to evaluate a request.
		 *
		 * Also fired by the wp-config.php bootstrap. A listener must tolerate
		 * being called on either path and must not assume WordPress is loaded.
		 */
		do_action( 'basic_firewall_early_evaluate' );
	},
	0
);
