<?php
/**
 * The mu-plugin loader: installing it, keeping it current, removing it.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Install;

/**
 * The copy of `mu-plugin/basic-firewall-loader.php` that lives in mu-plugins.
 *
 * It is a copy, not a link, because it has to survive the plugin being
 * deactivated or deleted without breaking the site. The cost of a copy is that
 * a release changing the loader does not change the installed one. It used to
 * be refreshed only by activation, so a site kept whatever loader it was first
 * activated with until somebody deactivated and reactivated -- which nobody
 * does to a firewall unless told to, and the only place that told them was a
 * changelog.
 *
 * So the copy is now refreshed, under three rules:
 *
 * - **Never on a visitor's request, never by reading files per request.** The
 *   installed loader defines BASIC_FIREWALL_MU_LOADER_VERSION, which is already
 *   in memory on every request it ran on. Comparing that with VERSION is free,
 *   and is all that happens on an admin, cron or WP-CLI request until the two
 *   differ. The file itself is read only on the occasions that justify it: this
 *   plugin being updated, activation, a schema upgrade, and the Site Health
 *   test. Those compare contents, so they also catch a loader that changed
 *   without its version being bumped.
 * - **Replace, never create.** Refreshing only ever rewrites a loader that is
 *   there and is ours. A missing one is left missing: it may have been removed
 *   on purpose, and the plugin may be deactivated on this site. Activation is
 *   the one thing that installs it, as before, and Site Health reports its
 *   absence.
 * - **Atomically.** The new copy is written beside the old one under a name
 *   WordPress will not load, then renamed over it. A rename within a directory
 *   is atomic, so a concurrent request includes the old loader or the new one
 *   and never half of either.
 *
 * On a network the mu-plugins directory is shared by every site while the
 * plugin's files are too, so every site wants the same loader: once one site
 * has refreshed it, every other site finds it current and does nothing. The
 * failure it records is a network option for the same reason -- an unwritable
 * directory is a fact about the network, not about the site that noticed.
 *
 * The directory and the source are constructor arguments so that the tests can
 * point this at a scratch directory instead of the real mu-plugins.
 */
final class Mu_Loader {

	/**
	 * The loader's file name, in the plugin and in mu-plugins.
	 */
	public const FILENAME = 'basic-firewall-loader.php';

	/**
	 * The version of the loader this plugin ships.
	 *
	 * Equal to the `Version:` header and BASIC_FIREWALL_MU_LOADER_VERSION in
	 * mu-plugin/basic-firewall-loader.php; build/check-versions.sh fails when
	 * they disagree.
	 */
	public const VERSION = '1.2.0';

	/**
	 * The constant every copy of the loader defines, and so how one is recognised.
	 */
	public const MARKER = 'BASIC_FIREWALL_MU_LOADER';

	/**
	 * The constant the installed loader states its version in.
	 */
	public const VERSION_CONSTANT = 'BASIC_FIREWALL_MU_LOADER_VERSION';

	/**
	 * Define as false to stop the plugin rewriting an installed loader.
	 */
	public const REFRESH_CONSTANT = 'BASIC_FIREWALL_MU_LOADER_REFRESH';

	/**
	 * Network option holding why the last refresh could not write the loader.
	 */
	public const REFRESH_FAILURE_OPTION = 'basic_firewall_mu_loader_refresh_error';

	/**
	 * Outcomes of refresh().
	 */
	public const CURRENT   = 'current';
	public const REFRESHED = 'refreshed';
	public const ABSENT    = 'absent';
	public const FOREIGN   = 'foreign';
	public const DISABLED  = 'disabled';
	public const FAILED    = 'failed';

	/**
	 * Whether this request has already brought the real loader up to date.
	 *
	 * The constant the old loader defined stays in memory for the rest of the
	 * request that replaced it, so without this Site Health would report the
	 * loader it had just refreshed as out of date.
	 *
	 * @var bool
	 */
	private static bool $verified = false;

	/**
	 * Build one for a directory and a source file.
	 *
	 * @param string $directory Directory the loader is installed into.
	 * @param string $source    The loader this copy of the plugin ships.
	 */
	public function __construct(
		private string $directory,
		private string $source
	) {
		$this->directory = rtrim( $directory, '/\\' );
	}

	/**
	 * The real one: WPMU_PLUGIN_DIR, and the loader in this plugin.
	 */
	public static function instance(): self {
		return new self( WPMU_PLUGIN_DIR, BASIC_FIREWALL_DIR . 'mu-plugin/' . self::FILENAME );
	}

	/**
	 * Attach the refresh to the occasions it runs on.
	 */
	public static function register(): void {
		/*
		 * `init` rather than `admin_init` so that cron and WP-CLI count too. A
		 * site deployed with git or Composer never runs the updater, and may
		 * go weeks without an administrator logging in, but WP-Cron runs on
		 * its own within minutes of the deploy.
		 */
		add_action( 'init', array( self::class, 'refresh_if_version_changed' ), 20 );
		add_action( 'upgrader_process_complete', array( self::class, 'refresh_after_update' ), 10, 2 );
		add_action( 'basic_firewall_upgraded', array( self::class, 'refresh_installed' ) );
	}

	/**
	 * Refresh when the running loader is not the version this plugin ships.
	 *
	 * The per-request check, so it reads nothing: both sides are constants.
	 * Visitors' requests are skipped even when the loader is out of date,
	 * because a front-end request is where a write costs the most and where an
	 * anonymous client could make it happen -- and because right after a
	 * deploy, every concurrent request would find the same stale loader and
	 * race to replace it. Admin, cron and WP-CLI requests are rare enough that
	 * the first of them simply does it.
	 */
	public static function refresh_if_version_changed(): void {
		if ( ! is_admin() && ! wp_doing_cron() && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		if ( ! self::running_is_stale() ) {
			return;
		}

		self::refresh_installed();
	}

	/**
	 * Refresh after WordPress has updated this plugin.
	 *
	 * Runs in the request that did the update, so the code running here is the
	 * release being replaced while the files on disk are the new one. Nothing
	 * version-specific is trusted for that reason: refresh() compares the
	 * installed loader with the new file byte for byte.
	 *
	 * @param mixed $upgrader The upgrader. Unused beyond identifying an upload.
	 * @param mixed $extra    What was upgraded.
	 */
	public static function refresh_after_update( $upgrader, $extra ): void {
		if ( ! is_array( $extra ) || 'plugin' !== ( $extra['type'] ?? '' ) ) {
			return;
		}

		$ours    = plugin_basename( BASIC_FIREWALL_FILE );
		$updated = array();

		if ( isset( $extra['plugins'] ) && is_array( $extra['plugins'] ) ) {
			$updated = $extra['plugins'];
		} elseif ( isset( $extra['plugin'] ) && is_string( $extra['plugin'] ) ) {
			$updated = array( $extra['plugin'] );
		} elseif ( $upgrader instanceof \Plugin_Upgrader ) {
			// An uploaded zip replacing the installed copy says which plugin it was only here.
			$updated = array( (string) $upgrader->plugin_info() );
		}

		if ( ! in_array( $ours, $updated, true ) ) {
			return;
		}

		self::refresh_installed();
	}

	/**
	 * Refresh the real loader, if this plugin is active here.
	 *
	 * The active check is belt and braces -- none of the hooks above fire for a
	 * plugin that is not loaded -- but an installed loader is what makes an
	 * inactive plugin run early, so it is not left to inference.
	 */
	public static function refresh_installed(): void {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if ( ! is_plugin_active( plugin_basename( BASIC_FIREWALL_FILE ) ) ) {
			return;
		}

		$outcome = self::instance()->refresh();

		self::$verified = in_array( $outcome, array( self::CURRENT, self::REFRESHED ), true );
	}

	/**
	 * Whether the loader that ran this request is older than the one shipped.
	 *
	 * False when no loader ran, because there is then nothing to refresh -- and
	 * refresh() would not create one anyway.
	 */
	public static function running_is_stale(): bool {
		if ( self::$verified || ! defined( self::MARKER ) ) {
			return false;
		}

		return self::VERSION !== self::running_version();
	}

	/**
	 * The version of the loader that ran this request, or null.
	 *
	 * An empty string for a loader that ran but predates stating its version.
	 */
	public static function running_version(): ?string {
		if ( ! defined( self::MARKER ) ) {
			return null;
		}

		return defined( self::VERSION_CONSTANT ) ? (string) constant( self::VERSION_CONSTANT ) : '';
	}

	/**
	 * Whether refreshing has been switched off in wp-config.php.
	 */
	public static function refresh_disabled(): bool {
		return defined( self::REFRESH_CONSTANT ) && false === constant( self::REFRESH_CONSTANT );
	}

	/**
	 * Why the last refresh failed, or null.
	 */
	public static function refresh_failure(): ?string {
		$stored = get_site_option( self::REFRESH_FAILURE_OPTION, '' );

		return is_string( $stored ) && '' !== $stored ? $stored : null;
	}

	/**
	 * Where the loader is installed.
	 */
	public function path(): string {
		return $this->directory . '/' . self::FILENAME;
	}

	/**
	 * Install the loader, creating the directory if need be.
	 *
	 * Activation only. Unlike refresh() this does create the file, because
	 * activating is an administrator asking for it.
	 *
	 * @return string|null Why it could not be installed, or null when it was.
	 */
	public function install(): ?string {
		if ( ! is_readable( $this->source ) ) {
			return 'The mu-plugin loader is missing from this copy of the plugin.';
		}

		if ( ! is_dir( $this->directory ) && ! wp_mkdir_p( $this->directory ) ) {
			return 'The mu-plugins directory does not exist and could not be created.';
		}

		if ( ! wp_is_writable( $this->directory ) ) {
			return 'The mu-plugins directory is not writable.';
		}

		$contents = $this->read( $this->source );

		if ( null === $contents || ! $this->write( $contents ) ) {
			return 'The mu-plugin loader could not be copied into the mu-plugins directory.';
		}

		self::clear_failure();

		return null;
	}

	/**
	 * Bring an installed loader up to date with the shipped one.
	 *
	 * Compares contents rather than versions, so a loader edited by hand, or
	 * changed by a release that forgot to bump its version, is still put right.
	 * An up-to-date loader is not written at all, so its modification time --
	 * and whatever the opcode cache holds for it -- is left alone.
	 *
	 * @return string One of the outcome constants.
	 */
	public function refresh(): string {
		$target = $this->path();

		if ( ! is_file( $target ) ) {
			// Removed, perhaps on purpose. Only activation puts it back.
			self::clear_failure();

			return self::ABSENT;
		}

		$installed = $this->read( $target );
		$shipped   = $this->read( $this->source );

		if ( null === $installed || null === $shipped ) {
			return $this->fail( 'The mu-plugin loader could not be read to check whether it is up to date.' );
		}

		if ( false === strpos( $installed, self::MARKER ) ) {
			// Somebody else's file under our name. Not ours to overwrite.
			self::clear_failure();

			return self::FOREIGN;
		}

		if ( $installed === $shipped ) {
			self::clear_failure();

			return self::CURRENT;
		}

		if ( self::refresh_disabled() ) {
			self::clear_failure();

			return self::DISABLED;
		}

		if ( ! wp_is_writable( $this->directory ) || ! wp_is_writable( $target ) ) {
			return $this->fail( 'The mu-plugin loader is out of date, and could not be replaced because the mu-plugins directory is not writable.' );
		}

		if ( ! $this->write( $shipped ) ) {
			return $this->fail( 'The mu-plugin loader is out of date, and writing the new copy into the mu-plugins directory failed.' );
		}

		self::clear_failure();

		return self::REFRESHED;
	}

	/**
	 * Remove the loader, if it is ours.
	 *
	 * Only ever removes a file this plugin recognises as its own. An mu-plugin
	 * survives deactivation by design -- WordPress never disables them -- so
	 * leaving ours in place would mean a deactivated plugin still evaluating
	 * requests.
	 */
	public function remove(): void {
		$target = $this->path();

		if ( ! is_readable( $target ) ) {
			return;
		}

		$contents = (string) $this->read( $target );

		if ( false === strpos( $contents, self::MARKER ) ) {
			// Somebody else's file, or one an administrator has rewritten. Not ours to delete.
			return;
		}

		wp_delete_file( $target );
	}

	/**
	 * Write the loader by writing a temporary file and renaming it into place.
	 *
	 * The temporary name ends in `.tmp`, not `.php`, because WordPress loads
	 * every `*.php` in mu-plugins: a half-written file named like a plugin
	 * would be included by a concurrent request, which is the one thing this
	 * is here to prevent. The random part keeps two simultaneous refreshes --
	 * two sites of a network, say -- from writing into the same temporary file.
	 * Whichever rename lands last wins, and both carry the same bytes.
	 *
	 * @param string $contents The loader.
	 */
	private function write( string $contents ): bool {
		$target    = $this->path();
		$temporary = $this->directory . '/.' . self::FILENAME . '.' . bin2hex( random_bytes( 6 ) ) . '.tmp';

		// phpcs:ignore WordPress.WP.AlternativeFunctions -- WP_Filesystem cannot write a file and rename it atomically, and may not be initialised on cron or WP-CLI.
		$written = file_put_contents( $temporary, $contents );

		if ( strlen( $contents ) !== $written ) {
			if ( file_exists( $temporary ) ) {
				wp_delete_file( $temporary );
			}

			return false;
		}

		// Keep the permissions the installed copy had; otherwise WordPress's default for a file.
		$mode = is_file( $target ) ? ( fileperms( $target ) & 0777 ) : ( defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644 );
		chmod( $temporary, $mode ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- see above.

		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- the atomic step; see the docblock.
		if ( ! rename( $temporary, $target ) ) {
			wp_delete_file( $temporary );

			return false;
		}

		/*
		 * With opcache.validate_timestamps on, a changed file is noticed within
		 * revalidate_freq seconds anyway. With it off, as some hosts run it,
		 * the old loader would stay compiled until PHP restarted.
		 */
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $target, true );
		}

		return true;
	}

	/**
	 * A local file's contents, or null.
	 *
	 * @param string $path File to read.
	 */
	private function read( string $path ): ?string {
		if ( ! is_readable( $path ) ) {
			return null;
		}

		$contents = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, not a remote URL; WP_Filesystem is not loaded this early.

		return is_string( $contents ) ? $contents : null;
	}

	/**
	 * Record a failed refresh for Site Health, and say so.
	 *
	 * @param string $message Why.
	 */
	private function fail( string $message ): string {
		if ( self::refresh_failure() !== $message ) {
			update_site_option( self::REFRESH_FAILURE_OPTION, $message );
		}

		return self::FAILED;
	}

	/**
	 * Forget a recorded failure, without a write when there is none.
	 */
	private static function clear_failure(): void {
		if ( null !== self::refresh_failure() ) {
			delete_site_option( self::REFRESH_FAILURE_OPTION );
		}
	}
}
