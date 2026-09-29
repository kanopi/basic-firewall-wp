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
 * Everything below is self-contained, on purpose.
 *
 * WordPress includes this file without loading the plugin, so neither the
 * plugin's autoloader nor the scoped vendor tree can be relied on here -- and a
 * release zip whose autoloader is half-present is precisely the copy somebody
 * is deleting. The names this file needs from Paths, Schema and the compiler
 * are spelled out instead, each next to a note saying where the original
 * lives. The integration tests in LifecycleTest and UninstallLeftoversTest are
 * what keep the two in step.
 *
 * Function declarations are guarded so this file can be included more than
 * once in a process. WordPress's uninstall_plugin() defines WP_UNINSTALL_PLUGIN
 * and therefore only works once, so the test suite includes this file directly
 * to exercise it repeatedly -- and a redeclaration would be a fatal in the
 * middle of a destructive operation.
 */
if ( ! function_exists( 'basic_firewall_uninstall_site' ) ) {

	/**
	 * Record something uninstall could not remove, or read what was recorded.
	 *
	 * A security plugin that leaves the block list and the logs behind is a
	 * problem; one that leaves them behind without saying so is a worse one.
	 * Everything that is deliberately or unavoidably left is noted here, and
	 * printed at the end when WP-CLI is running the uninstall.
	 *
	 * @param string|null $note  A sentence to record, or null to only read.
	 * @param bool        $reset Forget everything recorded so far.
	 *
	 * @return list<string> Everything recorded, in order.
	 */
	function basic_firewall_uninstall_notes( $note = null, $reset = false ) {
		static $notes = array();

		if ( $reset ) {
			$notes = array();
		}

		if ( is_string( $note ) && '' !== $note && ! in_array( $note, $notes, true ) ) {
			$notes[] = $note;
		}

		return $notes;
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
	 * @return bool Whether this site cached in APCu, which is cleared once for
	 *              the whole server rather than per site.
	 */
	function basic_firewall_uninstall_site() {
		global $wpdb;

		/*
		 * Everything that says where the plugin wrote is read first, because
		 * all of it is about to be deleted. The settings name the storage and
		 * log files and the Redis servers, and the suffix names the private
		 * directory; neither can be recovered once the options are gone.
		 */
		$settings = get_option( 'basic_firewall_settings', array() );
		$settings = is_array( $settings ) ? $settings : array();
		$suffix   = get_option( 'basic_firewall_private_suffix', '' );
		$suffix   = is_string( $suffix ) ? $suffix : '';

		$private = basic_firewall_uninstall_private_dirs( $suffix );

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
		wp_clear_scheduled_hook( 'basic_firewall_warm_cache' );

		/*
		 * The plugin's own tables. Named with the site's prefix, which is what keeps
		 * one site in a network from dropping another's.
		 *
		 * Table names are assembled from a fixed list and the prefix rather than
		 * from anything stored, so a tampered option cannot direct a DROP somewhere
		 * else. They cannot be parameterised -- an identifier is not a value -- so
		 * the safety has to come from never letting user input reach this line.
		 * A table somebody renamed on the Storage screen is therefore reported
		 * rather than dropped; see basic_firewall_uninstall_note_tables().
		 */
		$tables = array( 'basic_firewall_blocked', 'basic_firewall_offenses', 'basic_firewall_log', 'basic_firewall_ratelimit' );

		foreach ( $tables as $table ) {
			$name = $wpdb->prefix . $table;

			/*
			 * A table name is an identifier, and an identifier cannot be a bound
			 * parameter -- $wpdb->prepare() has nothing to offer here. The safety
			 * comes from the name never containing user input: it is one of four
			 * literals above joined to $wpdb->prefix, with backticks stripped.
			 */
			// phpcs:ignore WordPress.DB.PreparedSQL, WordPress.DB.DirectDatabaseQuery
			$wpdb->query( 'DROP TABLE IF EXISTS `' . str_replace( '`', '', $name ) . '`' );
		}

		basic_firewall_uninstall_note_tables( $settings, $tables );

		/*
		 * Files named in the settings first, while the directories that vouch
		 * for them are still there to be checked. Then the private directory
		 * itself, then the caches.
		 */
		$base = $private['active'];

		foreach ( basic_firewall_uninstall_stored_files( $settings ) as $stored ) {
			$path = basic_firewall_uninstall_resolve( $stored['path'], $base );

			if ( null !== $path ) {
				basic_firewall_uninstall_stored_file( $path, $stored['rotating'] );
			}
		}

		$cache_directory = trim( (string) ( $settings['cache']['directory'] ?? '' ) );

		if ( '' !== $cache_directory ) {
			$resolved = basic_firewall_uninstall_resolve( $cache_directory, $base );

			if ( null !== $resolved ) {
				basic_firewall_uninstall_cache_pools( $resolved );
			}
		}

		foreach ( $private['owned'] as $dir ) {
			basic_firewall_uninstall_remove_owned( $dir );
		}

		if ( null !== $private['filtered'] ) {
			basic_firewall_uninstall_filtered_dir( $private['filtered'] );
		}

		foreach ( basic_firewall_uninstall_redis_targets( $settings ) as $target ) {
			basic_firewall_uninstall_redis( $target );
		}

		basic_firewall_uninstall_object_cache();

		return 'apcu' === ( $settings['cache']['backend'] ?? '' );
	}

	/**
	 * Where this site's private directory is, or was.
	 *
	 * Mirrors Paths::base() and Paths::default_base(), which this file cannot
	 * load: the uploads directory, or WP_CONTENT_DIR when uploads is
	 * unavailable, then the `basic_firewall_private_path` filter over the top.
	 * The filter is applied because it is where the README tells a site to put
	 * the directory, outside the web root; a site that took that advice and got
	 * nothing removed would be the one most surprised.
	 *
	 * Two kinds of answer, treated differently:
	 *
	 * - `owned`: directories named `basic-firewall-private[-<suffix>]` in the
	 *   places the plugin creates one. The random suffix makes the name the
	 *   plugin's alone, so these are removed outright. Globbed rather than
	 *   read from the suffix option alone, because a site that has been
	 *   through more than one install cycle can have more than one.
	 * - `filtered`: whatever the filter names. That is a path somebody chose,
	 *   possibly a directory that already held other things, so it goes
	 *   through the ownership checks in basic_firewall_uninstall_filtered_dir()
	 *   rather than being deleted wholesale.
	 *
	 * @param string $suffix This site's stored directory suffix, or empty.
	 *
	 * @return array{owned: list<string>, filtered: string|null, active: string|null}
	 *         `active` is the directory relative stored paths resolve inside.
	 */
	function basic_firewall_uninstall_private_dirs( $suffix ) {
		// Paths::DIRNAME.
		$dirname = 'basic-firewall-private';
		$suffix  = 1 === preg_match( '/^[a-f0-9]{16}$/', $suffix ) ? $suffix : '';
		$uploads = wp_upload_dir( null, false );
		$content = rtrim( (string) WP_CONTENT_DIR, '/\\' );

		$root = ( empty( $uploads['error'] ) && ! empty( $uploads['basedir'] ) )
			? rtrim( (string) $uploads['basedir'], '/\\' )
			: $content;

		$default = '' !== $suffix ? $root . '/' . $dirname . '-' . $suffix : null;
		$owned   = array();

		if ( $root !== $content ) {
			$owned = array_merge( $owned, (array) glob( $root . '/' . $dirname . '-*', GLOB_ONLYDIR ) );

			// The pre-suffix name, for a site installed before that existed.
			$owned[] = $root . '/' . $dirname;
		}

		/*
		 * The WP_CONTENT_DIR fallback. On a single site every match is this
		 * site's. On a network they all sit side by side in one directory, so
		 * only this site's own suffix is taken; the other sites' are reached
		 * when the loop visits them.
		 */
		if ( is_multisite() ) {
			if ( '' !== $suffix ) {
				$owned[] = $content . '/' . $dirname . '-' . $suffix;
			}
		} else {
			$owned   = array_merge( $owned, (array) glob( $content . '/' . $dirname . '-*', GLOB_ONLYDIR ) );
			$owned[] = $content . '/' . $dirname;
		}

		$owned = array_values(
			array_unique(
				array_filter(
					array_map( 'strval', $owned ),
					static function ( $dir ) use ( $dirname ) {
						return 1 === preg_match( '/^' . preg_quote( $dirname, '/' ) . '(-[a-f0-9]{16})?$/', basename( $dir ) )
							&& ( is_dir( $dir ) || is_link( $dir ) );
					}
				)
			)
		);

		/** This filter is documented in src/Support/Paths.php */
		$filtered = apply_filters( 'basic_firewall_private_path', null !== $default ? $default : $root . '/' . $dirname );
		$filtered = is_string( $filtered ) ? rtrim( $filtered, '/\\' ) : '';

		if ( '' === $filtered || $filtered === $default || $filtered === $root . '/' . $dirname || in_array( $filtered, $owned, true ) ) {
			$filtered = null;
		}

		return array(
			'owned'    => $owned,
			'filtered' => $filtered,
			'active'   => null !== $filtered ? $filtered : $default,
		);
	}

	/**
	 * Every file path the settings say the plugin writes to.
	 *
	 * All of them, whatever backend is selected now: a site that kept its
	 * block list in files last month and in the database today still has last
	 * month's file. The defaults are the Schema's and the rate limit rule
	 * type's, repeated here because this file cannot load either.
	 *
	 * @param array<string, mixed> $settings The stored settings document.
	 *
	 * @return list<array{path: string, rotating: bool}>
	 */
	function basic_firewall_uninstall_stored_files( array $settings ) {
		$files = array();
		$file  = is_array( $settings['storage']['file'] ?? null ) ? $settings['storage']['file'] : array();

		$storage_file = trim( (string) ( $file['storage_file'] ?? 'blocked.data' ) );
		$storage_file = '' !== $storage_file ? $storage_file : 'blocked.data';
		$offense_file = trim( (string) ( $file['offense_file'] ?? 'offenses.data' ) );

		$files[] = $storage_file;

		// The compiler derives the offense file from the storage file when the
		// field is blank, and older releases did the same with the default.
		$files[] = '' !== $offense_file ? $offense_file : $storage_file . '.offenses';
		$files[] = $storage_file . '.offenses';

		foreach ( (array) ( $settings['rules'] ?? array() ) as $rule ) {
			if ( ! is_array( $rule ) || 'rate_limit' !== ( $rule['type'] ?? '' ) ) {
				continue;
			}

			$counter = trim( (string) ( $rule['settings']['storage']['file'] ?? 'ratelimit.data' ) );
			$files[] = '' !== $counter ? $counter : 'ratelimit.data';
		}

		$list = array();

		foreach ( array_unique( $files ) as $path ) {
			$list[] = array(
				'path'     => $path,
				'rotating' => false,
			);
		}

		foreach ( (array) ( $settings['logger'] ?? array() ) as $handler ) {
			if ( ! is_array( $handler ) ) {
				continue;
			}

			$type = (string) ( $handler['type'] ?? 'rotating_file' );

			if ( 'rotating_file' !== $type && 'stream' !== $type ) {
				continue;
			}

			$path = trim( (string) ( $handler['path'] ?? 'logs/firewall.log' ) );

			$list[] = array(
				'path'     => '' !== $path ? $path : 'logs/firewall.log',
				'rotating' => 'rotating_file' === $type,
			);
		}

		return $list;
	}

	/**
	 * Resolve a stored path the way Paths::resolve() does, or null to skip it.
	 *
	 * A relative path lives inside the private directory, with `..` stripped
	 * so a stored value cannot climb out of it. An absolute one is used as
	 * given. A stream -- `php://stderr` -- is not a file and is skipped.
	 *
	 * @param string      $path Stored path.
	 * @param string|null $base The private directory, or null when unknown.
	 *
	 * @return string|null
	 */
	function basic_firewall_uninstall_resolve( $path, $base ) {
		$path = trim( $path );

		// Paths::LEGACY_SCHEME, still accepted on read.
		if ( 0 === strpos( $path, 'private://' ) ) {
			$path = substr( $path, strlen( 'private://' ) );
		}

		if ( '' === $path || 1 === preg_match( '#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', $path ) ) {
			return null;
		}

		if ( '/' === $path[0] || '\\' === $path[0] || 1 === preg_match( '#^[A-Za-z]:[\\\\/]#', $path ) ) {
			return $path;
		}

		if ( null === $base ) {
			return null;
		}

		$parts = array();

		foreach ( explode( '/', str_replace( '\\', '/', $path ) ) as $segment ) {
			if ( '' !== $segment && '.' !== $segment && '..' !== $segment ) {
				$parts[] = $segment;
			}
		}

		return array() === $parts ? null : $base . '/' . implode( '/', $parts );
	}

	/**
	 * Whether the plugin created this directory.
	 *
	 * Paths::OWNER_MARKER, which ensure() writes only into a directory it made
	 * itself. A symlink is never owned, whatever it points at.
	 *
	 * @param string $dir Directory.
	 *
	 * @return bool
	 */
	function basic_firewall_uninstall_is_owned( $dir ) {
		$marker = rtrim( $dir, '/\\' ) . '/.basic-firewall-owner';

		return is_dir( $dir ) && ! is_link( $dir ) && is_file( $marker ) && ! is_link( $marker );
	}

	/**
	 * Whether this directory carries the plugin's guard files.
	 *
	 * The `.htaccess` or `web.config` Paths::ensure() writes, recognised by the
	 * sentence it opens with rather than by name, since both names are common.
	 * A guarded directory is one the plugin has written into, which is not the
	 * same as one it created: the filter can point ensure() at an existing
	 * directory. So a guarded directory has the plugin's files taken out of
	 * it, and is itself left alone.
	 *
	 * @param string $dir Directory.
	 *
	 * @return bool
	 */
	function basic_firewall_uninstall_is_guarded( $dir ) {
		if ( ! is_dir( $dir ) || is_link( $dir ) ) {
			return false;
		}

		foreach ( array( '.htaccess', 'web.config' ) as $name ) {
			if ( basic_firewall_uninstall_is_guard_file( rtrim( $dir, '/\\' ) . '/' . $name ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a file is one of the guard files the plugin writes.
	 *
	 * @param string $path File.
	 *
	 * @return bool
	 */
	function basic_firewall_uninstall_is_guard_file( $path ) {
		if ( ! is_file( $path ) || is_link( $path ) || filesize( $path ) > 4096 ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, not a remote URL.
		$contents = (string) file_get_contents( $path );

		/*
		 * Paths::guard_files(). The index.php is the stock WordPress one, so it
		 * is recognised only by its exact content and only under its own name,
		 * and basic_firewall_uninstall_is_guarded() never counts it: half the
		 * directories in wp-content carry the same file.
		 */
		if ( 'index.php' === basename( $path ) ) {
			return "<?php\n// Silence is golden.\n" === $contents;
		}

		return false !== strpos( $contents, 'Basic Firewall private directory. Written by the plugin' );
	}

	/**
	 * Whether a path lies inside a directory that vouches for it.
	 *
	 * Checked against the real location of the directory holding the file, so
	 * a symlinked directory cannot borrow the ownership of the tree it sits in:
	 * `private/logs -> /var/log` resolves to `/var/log`, which vouches for
	 * nothing, and the file stays. A few levels up are accepted because the
	 * library creates subdirectories of its own inside the private directory.
	 *
	 * @param string $path File path.
	 *
	 * @return bool
	 */
	function basic_firewall_uninstall_is_vouched_for( $path ) {
		$dir = realpath( dirname( $path ) );

		for ( $level = 0; false !== $dir && $level < 4; $level++ ) {
			if ( basic_firewall_uninstall_is_owned( $dir ) || basic_firewall_uninstall_is_guarded( $dir ) ) {
				return true;
			}

			if ( 1 === preg_match( '/^basic-firewall-private(-[a-f0-9]{16})?$/', basename( $dir ) ) ) {
				return true;
			}

			$parent = dirname( $dir );
			$dir    = $parent !== $dir ? $parent : false;
		}

		return false;
	}

	/**
	 * Delete a file the settings name, if a directory vouches for it.
	 *
	 * With its companions: the library's `.lock` sidecar and any staged
	 * `.<pid>.tmp` write it did not get to rename, and for a rotating log every
	 * dated file Monolog made from the name (`firewall-2026-09-28.log`).
	 *
	 * An absolute path an administrator typed can point anywhere, including at
	 * a file the plugin never wrote -- `/var/log/syslog` is a perfectly good
	 * value for a log handler. So nothing is deleted outside a directory the
	 * plugin created or guards, and what is left is said out loud instead.
	 *
	 * @param string $path     Resolved absolute path.
	 * @param bool   $rotating Whether a rotating file handler writes it.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_stored_file( $path, $rotating ) {
		$candidates = array( $path, $path . '.lock' );
		$candidates = array_merge( $candidates, (array) glob( $path . '.*.tmp' ) );

		if ( $rotating ) {
			$info = pathinfo( $path );
			$ext  = isset( $info['extension'] ) && '' !== $info['extension'] ? '.' . $info['extension'] : '';
			$stem = ( $info['dirname'] ?? '.' ) . '/' . $info['filename'];

			foreach ( (array) glob( $stem . '-*' . $ext ) as $dated ) {
				$tail = substr( (string) $dated, strlen( $stem ) + 1, strlen( (string) $dated ) - strlen( $stem ) - 1 - strlen( $ext ) );

				if ( 1 === preg_match( '/^\d{4}(-\d{2}){0,2}$/', $tail ) ) {
					$candidates[] = (string) $dated;
				}
			}
		}

		$present = array_values(
			array_filter(
				array_map( 'strval', $candidates ),
				static function ( $candidate ) {
					return is_link( $candidate ) || is_file( $candidate );
				}
			)
		);

		if ( array() === $present ) {
			return;
		}

		if ( ! basic_firewall_uninstall_is_vouched_for( $path ) ) {
			basic_firewall_uninstall_notes(
				sprintf(
					/* translators: %s: file path. */
					__( 'Not removed: %s. It is outside any directory Basic Firewall created or guards, so uninstall cannot tell it is the plugin\'s to delete. Remove it yourself if it is.', 'basic-firewall' ),
					$path
				)
			);

			return;
		}

		foreach ( $present as $candidate ) {
			// A symlink is removed as a link. unlink() never follows one.
			wp_delete_file( $candidate );
		}
	}

	/**
	 * Remove the firewall's pools from the files cache backend's directory.
	 *
	 * The directory is the administrator's -- `/tmp/basic-firewall` is the
	 * README's example, and it may as well be `/tmp` -- so it is left. The
	 * pools inside it are named for the plugin's own cache namespaces
	 * (Cache_Backend::AGENTS and VERDICTS), created there because the plugin
	 * asked for them, and nothing else writes under those names.
	 *
	 * @param string $dir The resolved `cache.directory` setting.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_cache_pools( $dir ) {
		foreach ( array( 'basic_firewall_agents', 'basic_firewall_rdns' ) as $name_space ) {
			$pool = rtrim( $dir, '/\\' ) . '/' . $name_space;

			if ( is_link( $pool ) ) {
				wp_delete_file( $pool );
			} elseif ( is_dir( $pool ) ) {
				basic_firewall_uninstall_rmdir( $pool, 0 );
			}
		}
	}

	/**
	 * Remove a directory the plugin owns, and everything in it.
	 *
	 * @param string $dir Directory.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_remove_owned( $dir ) {
		if ( is_link( $dir ) ) {
			// A link named like the private directory is removed as a link, and
			// what it points at is somebody else's.
			wp_delete_file( $dir );

			return;
		}

		if ( is_dir( $dir ) ) {
			basic_firewall_uninstall_rmdir( $dir, 0 );
		}
	}

	/**
	 * Clear out the directory the `basic_firewall_private_path` filter names.
	 *
	 * The previous version of this file refused to touch it at all, on the
	 * grounds that recursively deleting a hand-chosen path is how somebody
	 * loses a directory they cared about. That was right about the risk and
	 * wrong about the answer: it left the block list and the logs behind on
	 * exactly the sites that had moved them out of the web root because they
	 * cared where that data went.
	 *
	 * So it is removed by degrees of proof:
	 *
	 * - **Created by the plugin** (it carries the owner marker): the whole
	 *   directory goes.
	 * - **Guarded by the plugin** (it carries the plugin's `.htaccess` or
	 *   `web.config`, but was not created by it): the plugin's own files come
	 *   out -- the guard files, the compiled configuration and its sidecar,
	 *   and the subdirectories the plugin made -- and the directory stays,
	 *   with anything else that was in it.
	 * - **Neither**: nothing is touched, and the uninstall says so.
	 *
	 * @param string $dir The filtered private directory.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_filtered_dir( $dir ) {
		if ( ! is_dir( $dir ) || is_link( $dir ) ) {
			return;
		}

		if ( basic_firewall_uninstall_is_owned( $dir ) ) {
			basic_firewall_uninstall_rmdir( $dir, 0 );

			return;
		}

		if ( ! basic_firewall_uninstall_is_guarded( $dir ) ) {
			basic_firewall_uninstall_notes(
				sprintf(
					/* translators: %s: directory path. */
					__( 'Not removed: %s, the private directory named by the basic_firewall_private_path filter. It carries neither the plugin\'s owner marker nor its guard files, so uninstall cannot tell what in it is the plugin\'s.', 'basic-firewall' ),
					$dir
				)
			);

			return;
		}

		// The files Paths writes at the top level: the compiled configuration,
		// the connection-paths sidecar, and anything a reachability probe left.
		$names = array( 'firewall.yml', 'connection-paths.json', 'reachability-probe.yml', 'reachability-probe.data' );

		foreach ( $names as $name ) {
			$path = $dir . '/' . $name;

			if ( is_link( $path ) || is_file( $path ) ) {
				wp_delete_file( $path );
			}
		}

		/*
		 * The subdirectories Paths::ensure() creates. Each is removed when it
		 * carries the owner marker, or -- for one made before the marker
		 * existed -- when the plugin's index.php is in it.
		 */
		foreach ( array( 'logs', 'cache', 'device-detector', 'abuseipdb' ) as $child ) {
			$path = $dir . '/' . $child;

			if ( is_link( $path ) ) {
				wp_delete_file( $path );
				continue;
			}

			if ( basic_firewall_uninstall_is_owned( $path ) || basic_firewall_uninstall_is_guard_file( $path . '/index.php' ) ) {
				basic_firewall_uninstall_rmdir( $path, 0 );
			}
		}

		foreach ( array( '.htaccess', 'web.config', 'index.php' ) as $name ) {
			if ( basic_firewall_uninstall_is_guard_file( $dir . '/' . $name ) ) {
				wp_delete_file( $dir . '/' . $name );
			}
		}

		basic_firewall_uninstall_notes(
			sprintf(
				/* translators: %s: directory path. */
				__( 'Kept: %s. The plugin\'s files were removed from it, but the directory existed before the plugin used it, so the directory and anything else in it were left in place.', 'basic-firewall' ),
				$dir
			)
		);
	}

	/**
	 * Remove what the library wrote into BASIC_FIREWALL_CACHE_DIR.
	 *
	 * Network-wide, because the constant is: every site's parsed configuration
	 * and imported list bodies share it. The library writes a fixed set of
	 * names into it -- see Paths::library_cache_dir() and the library's own
	 * cacheDir() methods -- and those are what is removed.
	 *
	 * Only with some proof the directory is the plugin's. It is a path somebody
	 * typed into wp-config.php and it can be `/tmp`, where `compiled/` or
	 * `sources/` could belong to anything. So: the whole directory when the
	 * plugin created it; the library's names when it carries the plugin's
	 * guard files or is named for the plugin, as the README's
	 * `/tmp/basic-firewall` is; otherwise nothing, reported.
	 *
	 * @param string|null $dir The directory, or null to read the constant.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_cache_constant_dir( $dir = null ) {
		if ( null === $dir ) {
			if ( ! defined( 'BASIC_FIREWALL_CACHE_DIR' ) ) {
				return;
			}

			$dir = constant( 'BASIC_FIREWALL_CACHE_DIR' );
		}

		$dir = is_string( $dir ) ? rtrim( trim( $dir ), '/\\' ) : '';

		if ( '' === $dir || ! is_dir( $dir ) || is_link( $dir ) ) {
			return;
		}

		if ( basic_firewall_uninstall_is_owned( $dir ) ) {
			basic_firewall_uninstall_rmdir( $dir, 0 );

			return;
		}

		$named = 1 === preg_match( '/basic[-_]firewall/i', basename( $dir ) );

		if ( ! $named && ! basic_firewall_uninstall_is_guarded( $dir ) ) {
			basic_firewall_uninstall_notes(
				sprintf(
					/* translators: %s: directory path. */
					__( 'Not removed: the parsed configuration and rule list caches in %s, the BASIC_FIREWALL_CACHE_DIR directory. The plugin did not create it and it is not named for the plugin, so uninstall will not delete from it. Remove its compiled, sources, device-detector, kanopi_firewall_rdns and abuseipdb directories yourself.', 'basic-firewall' ),
					$dir
				)
			);

			return;
		}

		$children = array( 'compiled', 'sources', 'device-detector', 'kanopi_firewall_rdns', 'abuseipdb', 'basic_firewall_agents', 'basic_firewall_rdns' );

		foreach ( $children as $child ) {
			$path = $dir . '/' . $child;

			if ( is_link( $path ) ) {
				wp_delete_file( $path );
			} elseif ( is_dir( $path ) ) {
				basic_firewall_uninstall_rmdir( $path, 0 );
			}
		}

		// Remote configuration bodies, which the library names md5( url ).cache.
		foreach ( (array) glob( $dir . '/*.cache' ) as $body ) {
			if ( 1 === preg_match( '/^[a-f0-9]{32}\.cache$/', basename( (string) $body ) ) && is_file( (string) $body ) ) {
				wp_delete_file( (string) $body );
			}
		}
	}

	/**
	 * Report tables the fixed DROP list did not reach.
	 *
	 * A table renamed on the Storage screen, or kept in another database
	 * through a DSN, is not dropped: a DROP built from a stored string is a
	 * DROP an imported settings document could aim at any table in the
	 * database. It is named instead, so somebody can drop it knowingly.
	 *
	 * @param array<string, mixed> $settings The stored settings document.
	 * @param list<string>         $dropped  Unprefixed names already dropped.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_note_tables( array $settings, array $dropped ) {
		$tables = array();

		if ( 'database' === ( $settings['storage']['backend'] ?? '' ) ) {
			$database = is_array( $settings['storage']['database'] ?? null ) ? $settings['storage']['database'] : array();
			$external = 'wordpress' !== ( $database['connection_source'] ?? 'wordpress' );

			$defaults = array(
				'storage_table'  => 'basic_firewall_blocked',
				'offenses_table' => 'basic_firewall_offenses',
			);

			foreach ( $defaults as $key => $default ) {
				$tables[] = array( (string) ( $database[ $key ] ?? $default ), $external );
			}
		}

		foreach ( (array) ( $settings['logger'] ?? array() ) as $handler ) {
			if ( is_array( $handler ) && 'database' === ( $handler['type'] ?? '' ) ) {
				$tables[] = array( (string) ( $handler['table'] ?? 'basic_firewall_log' ), 'wordpress' !== ( $handler['connection_source'] ?? 'wordpress' ) );
			}
		}

		$counted_in_wordpress = false;

		foreach ( (array) ( $settings['rules'] ?? array() ) as $rule ) {
			$storage = is_array( $rule ) && 'rate_limit' === ( $rule['type'] ?? '' ) ? ( $rule['settings']['storage'] ?? null ) : null;

			if ( is_array( $storage ) && 'database' === ( $storage['backend'] ?? '' ) ) {
				$tables[] = array( (string) ( $storage['table'] ?? 'basic_firewall_ratelimit' ), 'wordpress' !== ( $storage['connection_source'] ?? 'wordpress' ) );

				$counted_in_wordpress = $counted_in_wordpress || 'wordpress' === ( $storage['connection_source'] ?? 'wordpress' );
			}
		}

		/*
		 * Named, never dropped. Before 1.0.0 the table name was compiled under
		 * a key the library does not read, so a database-backed rate limit
		 * counted into the library's own default table -- unprefixed, and in
		 * WordPress's database. This plugin may have created it; so may any
		 * other application using kanopi/firewall with the same database, and
		 * nothing in it says which. Only reported when a rule here could have
		 * been the one writing to it.
		 */
		if ( $counted_in_wordpress ) {
			global $wpdb;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- uninstall, one lookup.
			if ( 'firewall_rate_limit_storage' === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', 'firewall_rate_limit_storage' ) ) ) {
				basic_firewall_uninstall_notes( __( 'Not dropped: the table firewall_rate_limit_storage. A build before 1.0.0 counted database-backed rate limits into it by mistake, but other software using the same firewall library writes to it too, so it is left in place for you to remove if nothing else uses it.', 'basic-firewall' ) );
			}
		}

		foreach ( $tables as $table ) {
			list( $name, $external ) = $table;

			if ( '' === trim( $name ) || ( ! $external && in_array( $name, $dropped, true ) ) ) {
				continue;
			}

			basic_firewall_uninstall_notes(
				$external
					/* translators: %s: table name. */
					? sprintf( __( 'Not dropped: the table %s, which is in a database reached through a connection DSN rather than WordPress\'s own.', 'basic-firewall' ), $name )
					/* translators: %s: table name. */
					: sprintf( __( 'Not dropped: the table %s, whose name was changed from the default. Uninstall only drops the tables it names itself.', 'basic-firewall' ), $name )
			);
		}
	}

	/**
	 * The Redis servers and key prefixes this site wrote to.
	 *
	 * Only the backends currently selected. A Redis server the settings still
	 * describe but no longer use is not contacted: its host defaults to
	 * 127.0.0.1, and on a single site the default prefix is the library's bare
	 * `firewall:`, which another application using kanopi/firewall on the same
	 * server would share. Deleting under that prefix on the strength of a
	 * default nobody chose is not a risk worth taking to tidy up keys that
	 * expire on their own.
	 *
	 * Prefixes follow Config_Compiler::redis_storage_options() and the rate
	 * limit rule type, including the per-site discriminator a network adds
	 * (Database_Credentials::redis_key_prefix()).
	 *
	 * @param array<string, mixed> $settings The stored settings document.
	 *
	 * @return list<array{host: string, port: int, prefix: string, auth: mixed}>
	 */
	function basic_firewall_uninstall_redis_targets( array $settings ) {
		$targets = array();

		if ( 'redis' === ( $settings['storage']['backend'] ?? '' ) ) {
			$redis    = is_array( $settings['storage']['redis'] ?? null ) ? $settings['storage']['redis'] : array();
			$username = trim( (string) ( $redis['username'] ?? '' ) );
			$password = (string) ( $redis['password'] ?? '' );

			$targets[] = array(
				'host'   => (string) ( $redis['host'] ?? '' ),
				'port'   => (int) ( $redis['port'] ?? 6379 ),
				'prefix' => trim( (string) ( $redis['prefix'] ?? '' ) ),
				'stem'   => 'firewall',
				'auth'   => '' === $password ? null : ( '' === $username ? $password : array( $username, $password ) ),
			);
		}

		foreach ( (array) ( $settings['rules'] ?? array() ) as $rule ) {
			$storage = is_array( $rule ) && 'rate_limit' === ( $rule['type'] ?? '' ) ? ( $rule['settings']['storage'] ?? null ) : null;

			if ( ! is_array( $storage ) || 'redis' !== ( $storage['backend'] ?? '' ) ) {
				continue;
			}

			$password  = (string) ( $storage['redis_password'] ?? '' );
			$targets[] = array(
				'host'   => (string) ( $storage['redis_host'] ?? '' ),
				'port'   => (int) ( $storage['redis_port'] ?? 6379 ),
				'prefix' => trim( (string) ( $storage['key_prefix'] ?? '' ) ),
				'stem'   => 'ratelimit',
				'auth'   => '' === $password ? null : $password,
			);
		}

		$list = array();

		foreach ( $targets as $target ) {
			$host   = trim( $target['host'] );
			$prefix = '' !== $target['prefix'] ? $target['prefix'] : basic_firewall_uninstall_redis_prefix( $target['stem'] );
			$key    = $host . '|' . $target['port'] . '|' . $prefix;

			$list[ $key ] = array(
				'host'   => '' !== $host ? $host : '127.0.0.1',
				'port'   => $target['port'] > 0 ? $target['port'] : 6379,
				'prefix' => $prefix,
				'auth'   => $target['auth'],
			);
		}

		return array_values( $list );
	}

	/**
	 * The prefix the plugin derives when none was typed.
	 *
	 * Database_Credentials::redis_key_prefix(), repeated.
	 *
	 * @param string $stem `firewall` or `ratelimit`.
	 *
	 * @return string
	 */
	function basic_firewall_uninstall_redis_prefix( $stem ) {
		global $wpdb;

		if ( ! is_multisite() ) {
			return $stem . ':';
		}

		$discriminator = trim( isset( $wpdb->prefix ) ? (string) $wpdb->prefix : '', '_' );

		if ( '' === $discriminator ) {
			$discriminator = 'site' . get_current_blog_id();
		}

		return $stem . ':' . $discriminator . ':';
	}

	/**
	 * Delete every key under a prefix on one Redis server.
	 *
	 * SCAN and DEL, never KEYS or FLUSHDB. KEYS blocks the server for as long
	 * as it takes to walk every key it holds, which on a shared Redis is an
	 * outage for everybody else on it; FLUSHDB deletes their data outright.
	 * SCAN walks in batches, and the prefix confines DEL to what this plugin
	 * wrote.
	 *
	 * Never fatal. A short connect and read timeout keeps an unreachable server
	 * from hanging the uninstall screen, a time budget bounds a huge keyspace,
	 * and every failure becomes a note rather than an exception: the options,
	 * tables and files are already gone by now, and a Redis outage is no
	 * reason to report the whole uninstall as failed.
	 *
	 * @param array{host: string, port: int, prefix: string, auth: mixed} $target Server and prefix.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_redis( array $target ) {
		$where = sprintf( '%s:%d', $target['host'], $target['port'] );

		if ( '' === $target['prefix'] ) {
			// Nothing derives an empty prefix, and an empty one would match every key.
			return;
		}

		if ( ! class_exists( 'Redis' ) ) {
			basic_firewall_uninstall_notes(
				sprintf(
					/* translators: 1: key prefix, 2: Redis host and port. */
					__( 'Not removed: the Redis keys under %1$s on %2$s. This PHP has no redis extension to reach them with. Delete them with SCAN and DEL from a machine that can.', 'basic-firewall' ),
					$target['prefix'],
					$where
				)
			);

			return;
		}

		try {
			$reason = basic_firewall_uninstall_redis_scan( $target, microtime( true ) + 10.0 );
		} catch ( Throwable $e ) {
			$reason = $e->getMessage();
		}

		if ( null === $reason ) {
			return;
		}

		basic_firewall_uninstall_notes(
			sprintf(
				/* translators: 1: key prefix, 2: Redis host and port, 3: reason. */
				__( 'Not removed: some or all of the Redis keys under %1$s on %2$s (%3$s). Block records carry their ban as an expiry and go on their own; offense histories and permanent bans do not. Delete them with SCAN and DEL once the server is reachable.', 'basic-firewall' ),
				$target['prefix'],
				$where,
				$reason
			)
		);
	}

	/**
	 * Connect, then SCAN and DEL under the prefix until done or out of time.
	 *
	 * Separate from its caller so that every way this can stop short -- a
	 * refused connection, a rejected password, a keyspace too large for the
	 * time budget -- arrives there as one reason to report. ext-redis throws
	 * RedisException for some of these and returns false for others; the
	 * caller catches the first and this returns the second.
	 *
	 * @param array{host: string, port: int, prefix: string, auth: mixed} $target   Server and prefix.
	 * @param float                                                       $deadline microtime() to give up at.
	 *
	 * @return string|null Why it stopped short, or null when every key went.
	 */
	function basic_firewall_uninstall_redis_scan( array $target, $deadline ) {
		$redis = new Redis();

		if ( ! $redis->connect( $target['host'], $target['port'], 1.0, null, 0, 1.0 ) ) {
			return 'connection refused';
		}

		if ( null !== $target['auth'] && ! $redis->auth( $target['auth'] ) ) {
			$redis->close();

			return 'authentication failed';
		}

		$redis->setOption( Redis::OPT_SCAN, Redis::SCAN_RETRY );

		// SCAN's MATCH is a glob, and a prefix is taken literally.
		$pattern  = addcslashes( $target['prefix'], '\\*?[]^' ) . '*';
		$iterator = null;

		while ( microtime( true ) < $deadline ) {
			$keys = $redis->scan( $iterator, $pattern, 500 );

			if ( is_array( $keys ) && array() !== $keys ) {
				$redis->del( $keys );
			}

			if ( false === $keys || 0 === $iterator ) {
				$redis->close();

				return null;
			}
		}

		$redis->close();

		return 'the time budget ran out';
	}

	/**
	 * Empty the plugin's object cache group, where the backend can.
	 *
	 * The group (Object_Cache_Adapter::GROUP) holds parsed user agents and
	 * reverse-DNS verdicts. WordPress 6.1 added wp_cache_flush_group(), but a
	 * persistent object cache drop-in has to implement it, and says whether it
	 * does through wp_cache_supports(). Without it the entries cannot be found
	 * to delete -- the adapter versions its keys -- and are left to the
	 * backend's own eviction, which is said rather than assumed.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_object_cache() {
		if ( function_exists( 'wp_cache_flush_group' ) && function_exists( 'wp_cache_supports' ) && wp_cache_supports( 'flush_group' ) ) {
			wp_cache_flush_group( 'basic_firewall' );

			return;
		}

		if ( wp_using_ext_object_cache() ) {
			basic_firewall_uninstall_notes( __( 'Not removed: the basic_firewall group in the persistent object cache. The object cache drop-in does not support flushing one group, so its entries are left to expire.', 'basic-firewall' ) );
		}
	}

	/**
	 * Delete the plugin's APCu entries.
	 *
	 * The namespaces are Cache_Backend::AGENTS and VERDICTS, both under the
	 * plugin's `basic_firewall_` prefix, so nothing else is matched. APCu is
	 * one store per server, shared by every site of a network, so this runs
	 * once.
	 *
	 * APCu's memory belongs to the process pool that filled it. From the admin
	 * screen that is the web server's, and this clears it. From WP-CLI it is
	 * the command line's own -- usually disabled, always a different one --
	 * and the web server's copy is out of reach.
	 *
	 * @param bool $used Whether any site cached in APCu.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_apcu( $used ) {
		if ( function_exists( 'apcu_enabled' ) && apcu_enabled() && class_exists( 'APCUIterator' ) ) {
			apcu_delete( new APCUIterator( '/^basic_firewall_/' ) );
		}

		if ( $used && defined( 'WP_CLI' ) && WP_CLI ) {
			basic_firewall_uninstall_notes( __( 'Not removed: the web server\'s APCu entries. APCu belongs to the process that filled it, and this uninstall ran from the command line. They expire on their own, or restart PHP-FPM to drop them now.', 'basic-firewall' ) );
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
		/*
		 * The deepest tree the plugin writes is a cache pool inside a cache
		 * directory inside the private directory, which is six levels. A
		 * deeper one means something unexpected is in there, and stopping is
		 * better than continuing to delete -- but it is said, not swallowed.
		 */
		if ( $depth > 8 ) {
			basic_firewall_uninstall_notes(
				sprintf(
					/* translators: %s: directory path. */
					__( 'Not removed: %s. It is nested deeper than anything the plugin writes, so uninstall stopped rather than keep deleting.', 'basic-firewall' ),
					$dir
				)
			);

			return;
		}

		/*
		 * scandir() rather than glob(). Matching dotfiles with glob() needs
		 * GLOB_BRACE, which is not defined on musl libc -- Alpine, and so a
		 * good share of container images -- before PHP 8.5, and an undefined
		 * constant is a fatal error: uninstall stopped at the first directory
		 * it tried to empty, having deleted the options and none of the files.
		 */
		$names = scandir( $dir );

		if ( false === $names ) {
			return;
		}

		$entries = array();

		foreach ( $names as $name ) {
			if ( '.' !== $name && '..' !== $name ) {
				$entries[] = rtrim( $dir, '/' ) . '/' . $name;
			}
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

	/**
	 * Say what was left behind, where anybody is listening.
	 *
	 * Under WP-CLI, as warnings. From the Plugins screen there is nowhere to
	 * say it -- WordPress deletes the plugin over Ajax and shows no output --
	 * which is why the README lists the same cases.
	 *
	 * @return void
	 */
	function basic_firewall_uninstall_report() {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI || ! class_exists( 'WP_CLI' ) ) {
			return;
		}

		foreach ( basic_firewall_uninstall_notes() as $note ) {
			WP_CLI::warning( 'Basic Firewall: ' . $note );
		}
	}

}

basic_firewall_uninstall_notes( null, true );

$basic_firewall_used_apcu = false;

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
		$basic_firewall_used_apcu = basic_firewall_uninstall_site() || $basic_firewall_used_apcu;
		restore_current_blog();
	}
} else {
	$basic_firewall_used_apcu = basic_firewall_uninstall_site();
}

/*
 * The cache directory constant and APCu are per server, not per site, so each
 * is cleared once, after every site.
 */
basic_firewall_uninstall_cache_constant_dir();
basic_firewall_uninstall_apcu( $basic_firewall_used_apcu );

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
 * Network options -- on a network, the record of a loader refresh that could
 * not write mu-plugins lives in sitemeta, beside the loader it describes.
 * Removed by prefix for the same reason per-site options are: a list of names
 * rots. On a single site these are ordinary options and went with the rest.
 */
if ( is_multisite() ) {
	global $wpdb;

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall, once.
	$basic_firewall_network_options = $wpdb->get_col(
		$wpdb->prepare(
			"SELECT DISTINCT meta_key FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s",
			$wpdb->esc_like( 'basic_firewall_' ) . '%'
		)
	);

	foreach ( (array) $basic_firewall_network_options as $basic_firewall_network_option ) {
		delete_site_option( (string) $basic_firewall_network_option );
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

basic_firewall_uninstall_report();
