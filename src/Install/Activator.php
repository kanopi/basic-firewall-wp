<?php
/**
 * Activation and deactivation.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Install;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Sources\Refresher;
use Kanopi\BasicFirewall\Support\Schema;

/**
 * What happens when the plugin is switched on and off.
 *
 * Activation deliberately does not enable anything. The settings it writes are
 * the schema's defaults, which means log-only mode and no rules -- a freshly
 * activated firewall observes traffic and blocks nothing until an administrator
 * says otherwise. A security plugin that starts blocking on activation is one
 * support ticket away from being the reason a site is unreachable.
 */
final class Activator {

	/**
	 * Option recording that the mu-plugin could not be installed.
	 */
	public const MU_FAILURE_OPTION = 'basic_firewall_mu_plugin_error';

	/**
	 * Run on activation.
	 */
	public static function activate(): void {
		Capabilities::grant();

		$plugin = Plugin::instance();

		// Write the defaults only on a genuinely new install. Re-activating a
		// configured site must not reset its rule set.
		if ( ! $plugin->settings()->is_installed() ) {
			$plugin->settings()->replace( Schema::defaults() );
		}

		$plugin->paths()->ensure();

		Challenge_Secret::ensure();

		self::install_mu_plugin();

		/*
		 * Mark the schema current so the upgrade routines do not run against a
		 * fresh install. A new install is already at the latest shape by
		 * definition, and running migrations over it would exercise code paths
		 * that only make sense against older data.
		 */
		update_option( Schema::VERSION_OPTION, Schema::VERSION, false );

		/*
		 * Scheduled here as well as on every settings save, because a rule can
		 * reference a list before the settings screen is ever opened -- an
		 * imported configuration, or one deployed as code.
		 */
		Refresher::reschedule();

		/**
		 * Fires at the end of activation.
		 *
		 * The compiler listens, so that a site has a compiled configuration
		 * before its first request rather than on it.
		 */
		do_action( 'basic_firewall_activated' );
	}

	/**
	 * Run on deactivation.
	 *
	 * Removes the runtime, leaves the configuration. Deactivating is how an
	 * administrator turns the firewall off, and it has to be reversible without
	 * losing the rule set -- so nothing here touches settings, the block list,
	 * the log table or the capabilities. Uninstall is where data goes.
	 */
	public static function deactivate(): void {
		self::remove_mu_plugin();

		wp_clear_scheduled_hook( 'basic_firewall_refresh_sources' );
		wp_clear_scheduled_hook( 'basic_firewall_prune_logs' );
		wp_clear_scheduled_hook( 'basic_firewall_warm_cache' );

		// The compiled file is a cache of settings that are no longer being
		// enforced. Leaving it would let the early wp-config.php path go on
		// evaluating requests after the plugin was switched off in the admin,
		// which is the single most confusing state this plugin could be in.
		$compiled = Plugin::instance()->paths()->compiled_file();

		if ( is_readable( $compiled ) ) {
			wp_delete_file( $compiled );
		}
	}

	/**
	 * Copy the loader into mu-plugins.
	 *
	 * The normal evaluation path. An mu-plugin is the earliest hook a plugin can
	 * own, and on a site with no page cache it is early enough -- see
	 * DECISIONS.md section 6 for why it is not early enough on a site that has
	 * one, and what Site Health does about that. Mu_Loader keeps the copy
	 * current afterwards; this is the only place that creates it.
	 *
	 * A failure here is recorded rather than thrown. The plugin still works
	 * through its ordinary hooks; it just runs later than it could, and Site
	 * Health says so.
	 */
	private static function install_mu_plugin(): void {
		delete_option( self::MU_FAILURE_OPTION );

		$error = Mu_Loader::instance()->install();

		if ( null !== $error ) {
			update_option( self::MU_FAILURE_OPTION, $error, false );
		}
	}

	/**
	 * Remove the mu-plugin loader. See Mu_Loader::remove().
	 */
	private static function remove_mu_plugin(): void {
		Mu_Loader::instance()->remove();
	}
}
