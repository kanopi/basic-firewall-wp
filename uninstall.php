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

	$options = array(
		'basic_firewall_settings',
		'basic_firewall_schema_version',
		'basic_firewall_mu_plugin_error',
		'basic_firewall_upgrade_error',
		'basic_firewall_library_probe',
		'basic_firewall_source_state',
	);

	foreach ( $options as $option ) {
		delete_option( $option );
	}

	delete_transient( 'basic_firewall_status' );

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

	$dir = rtrim( $uploads['basedir'], '/\\' ) . '/basic-firewall-private';

	/*
	 * Recomputed from wp_upload_dir() rather than read from settings or from
	 * the `basic_firewall_private_path` filter.
	 *
	 * A site that moved the directory keeps it, and that is the right trade: a
	 * filter pointing at a shared or hand-chosen location is exactly the case
	 * where recursively deleting whatever is there would be unrecoverable. A
	 * leftover directory is a tidiness problem; deleting the wrong tree is not.
	 */
	if ( ! is_dir( $dir ) ) {
		return;
	}

	basic_firewall_uninstall_rmdir( $dir, 0 );
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
