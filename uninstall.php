<?php
/**
 * Removes everything the plugin created.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

/*
 * WP_UNINSTALL_PLUGIN is defined only by WordPress's own uninstall runner. Its
 * absence means this file was reached some other way, and this file deletes
 * data.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) || ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * Uninstall runs on whatever PHP the site has, and this file is reached before
 * anything checks the version. Bail rather than fatal -- a plugin that fatals
 * while being removed leaves the site in a worse state than one that leaves a
 * few options behind.
 */
if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
	return;
}

/*
 * Function declarations are guarded so this file can be included more than
 * once in a process. WordPress's uninstall_plugin() defines WP_UNINSTALL_PLUGIN
 * and therefore only works once, so the test suite includes this file directly
 * to exercise it repeatedly -- and a redeclaration would be a fatal in the
 * middle of a destructive operation.
 */
if ( ! function_exists( 'basic_firewall_uninstall_site' ) ) {

	/**
	 * Delete this site's firewall data.
	 *
	 * Everything here is deliberate and destructive. Deactivation is the reversible
	 * operation; uninstall is where the block list, the logs and the rule set
	 * actually go. It runs per site because the plugin's configuration is per site:
	 * on a network, uninstalling has to visit every site or it leaves orphaned
	 * tables behind on all of them but one.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_site() {
		global $wpdb;

		/*
		 * Deleted by PREFIX, not from a list.
		 *
		 * The first version of this named the options it knew about. Two were added
		 * to the plugin afterwards -- the compiled-file metadata and the private
		 * directory's random suffix -- and nobody updated the list, so a real
		 * uninstall left them behind. That is the failure mode of any file that
		 * duplicates knowledge it cannot import: uninstall.php runs without the
		 * plugin's autoloader, so it cannot ask Schema or Paths what they are
		 * called, and a hand-maintained copy rots silently.
		 *
		 * A prefix match cannot rot. Every option this plugin writes is named
		 * `basic_firewall_*` and nothing else on a site has any business using that
		 * prefix -- it is the prefix the coding standards require us to own.
		 */
		$like = $wpdb->esc_like( 'basic_firewall_' ) . '%';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$option_names = $wpdb->get_col(
			$wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $like )
		);

		foreach ( (array) $option_names as $option_name ) {
			delete_option( (string) $option_name );
		}

		/*
		 * Transients are options too, but under their own prefixes, and they are
		 * per user -- the admin notice queue and a held import are keyed by user id.
		 */
		foreach ( array( '_transient_basic_firewall_', '_transient_timeout_basic_firewall_' ) as $transient_prefix ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$transients = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
					$wpdb->esc_like( $transient_prefix ) . '%'
				)
			);

			foreach ( (array) $transients as $transient ) {
				delete_option( (string) $transient );
			}
		}

		wp_clear_scheduled_hook( 'basic_firewall_refresh_sources' );
		wp_clear_scheduled_hook( 'basic_firewall_prune_logs' );

		/*
		 * The plugin's own tables. Named with the site's prefix, which is what keeps
		 * one site in a network from dropping another's.
		 *
		 * Table names are assembled from a fixed list and the prefix rather than
		 * from anything stored, so a tampered option cannot direct a DROP somewhere
		 * else. They cannot be parameterised -- an identifier is not a value -- so
		 * the safety has to come from never letting user input reach this line.
		 */
		$tables = array( 'basic_firewall_blocked', 'basic_firewall_offenses', 'basic_firewall_log' );

		foreach ( $tables as $table ) {
			$name = $wpdb->prefix . $table;

			/*
			 * A table name is an identifier, and an identifier cannot be a bound
			 * parameter -- $wpdb->prepare() has nothing to offer here. The safety
			 * comes from the name never containing user input: it is one of three
			 * literals above joined to $wpdb->prefix, with backticks stripped.
			 */
			// phpcs:ignore WordPress.DB.PreparedSQL, WordPress.DB.DirectDatabaseQuery
			$wpdb->query( 'DROP TABLE IF EXISTS `' . str_replace( '`', '', $name ) . '`' );
		}

		basic_firewall_uninstall_private_dir();
	}

	/**
	 * Delete the private directory and its contents.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_private_dir() {
		$uploads = wp_upload_dir( null, false );

		if ( empty( $uploads['basedir'] ) ) {
			return;
		}

		$base = rtrim( $uploads['basedir'], '/\\' );

		/*
		 * The directory name carries a random per-site suffix, so it cannot be
		 * spelled literally here.
		 *
		 * The first version of this looked for `basic-firewall-private` exactly.
		 * The suffix was added to the plugin later and this was not updated, so a
		 * real uninstall dropped the tables, revoked the capabilities, removed the
		 * mu-plugin -- and left the block list, the firewall logs and the compiled
		 * configuration sitting in a directory that, on nginx, is readable over the
		 * web. Uninstalling is exactly when nobody is watching for that.
		 *
		 * Matched by glob rather than read from the option, because the options are
		 * deleted above and because a site that has been through more than one
		 * install cycle can have more than one of these.
		 *
		 * Still recomputed from wp_upload_dir() and never from the
		 * `basic_firewall_private_path` filter: a filter pointing at a shared or
		 * hand-chosen location is exactly the case where recursively deleting
		 * whatever is there would be unrecoverable. A leftover directory somebody
		 * chose is a tidiness problem; deleting the wrong tree is not.
		 */
		$found = glob( $base . '/basic-firewall-private-*', GLOB_ONLYDIR );

		// The pre-suffix name, for a site installed before that existed.
		if ( is_dir( $base . '/basic-firewall-private' ) ) {
			$found[] = $base . '/basic-firewall-private';
		}

		foreach ( (array) $found as $dir ) {
			if ( is_string( $dir ) && is_dir( $dir ) ) {
				basic_firewall_uninstall_rmdir( $dir, 0 );
			}
		}
	}

	/**
	 * Recursively delete a directory.
	 *
	 * @param string $dir   Directory to remove.
	 * @param int    $depth Current recursion depth.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_rmdir( $dir, $depth ) {
		// The tree is shallow and known. A deep one means something unexpected is
		// in there, and stopping is better than continuing to delete.
		if ( $depth > 4 ) {
			return;
		}

		$entries = glob( rtrim( $dir, '/' ) . '/{,.}[!.,!..]*', GLOB_BRACE );

		if ( false === $entries ) {
			return;
		}

		foreach ( $entries as $entry ) {
			if ( is_link( $entry ) ) {
				// Never follow a symlink out of the tree being deleted.
				wp_delete_file( $entry );
				continue;
			}

			if ( is_dir( $entry ) ) {
				basic_firewall_uninstall_rmdir( $entry, $depth + 1 );
				continue;
			}

			wp_delete_file( $entry );
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions -- uninstall runs without WP_Filesystem, and a directory that will not go is not worth failing an uninstall over.
		@rmdir( $dir );
	}

}

if ( is_multisite() ) {
	/*
	 * Per-site configuration means per-site removal. The loop is capped: a
	 * network large enough to exceed it will time out mid-uninstall and leave a
	 * mess, so beyond that size the documented route is
	 * `wp site list --field=url | xargs -n1 wp --url=... plugin uninstall`.
	 */
	$basic_firewall_sites = get_sites(
		array(
			'number' => 500,
			'fields' => 'ids',
		)
	);

	foreach ( $basic_firewall_sites as $basic_firewall_site_id ) {
		switch_to_blog( (int) $basic_firewall_site_id );
		basic_firewall_uninstall_site();
		restore_current_blog();
	}
} else {
	basic_firewall_uninstall_site();
}

/*
 * The mu-plugin loader is network-wide and outside any site, so it is removed
 * once, at the end, rather than inside the per-site loop.
 */
$basic_firewall_mu = WPMU_PLUGIN_DIR . '/basic-firewall-loader.php';

if ( is_readable( $basic_firewall_mu ) ) {
	// phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, not a remote URL.
	$basic_firewall_mu_contents = file_get_contents( $basic_firewall_mu );

	if ( is_string( $basic_firewall_mu_contents ) && false !== strpos( $basic_firewall_mu_contents, 'BASIC_FIREWALL_MU_LOADER' ) ) {
		wp_delete_file( $basic_firewall_mu );
	}
}

/*
 * Capabilities are network-wide on a network install and role changes are not
 * per site, so this also happens once.
 */
$basic_firewall_role = get_role( 'administrator' );

if ( null !== $basic_firewall_role ) {
	foreach ( array( 'manage_basic_firewall', 'view_basic_firewall_reports', 'unblock_basic_firewall_clients' ) as $basic_firewall_cap ) {
		$basic_firewall_role->remove_cap( $basic_firewall_cap );
	}
}
