<?php
/**
 * Locates and protects the plugin's private directory.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Support;

/**
 * The private directory, and the `private://` scheme that addresses it.
 *
 * Drupal has a private file system: a directory outside the web root, served
 * only through a code path that checks access. WordPress has nothing of the
 * kind. Everything under `wp-content/uploads/` is served directly by the web
 * server, and that is where a plugin is expected to write.
 *
 * This matters because of what goes in here. The compiled configuration can
 * carry table names and, where an administrator supplied one, a connection DSN.
 * The block list is a list of the addresses attacking the site. The logs record
 * every decision the firewall made. A directory listing of any of it is a gift
 * to whoever is on the other end.
 *
 * So the directory is created under uploads, hardened three ways, and then
 * **checked over HTTP** rather than assumed:
 *
 * - `.htaccess`  denies everything, for Apache and LiteSpeed.
 * - `web.config` denies everything, for IIS.
 * - `index.php`  makes a mis-served directory listing empty rather than a
 *                manifest. It is the only one of the three that works when the
 *                server ignores the other two -- nginx reads neither file.
 *
 * That last point is why the reachability probe exists and why its result is a
 * Site Health test rather than a comment in the readme. On nginx, which does not
 * read `.htaccess`, the first two files are inert decoration. The only way to
 * know whether the directory is exposed is to ask for a file in it and see what
 * comes back.
 *
 * The `private://` scheme is kept from the module deliberately. Stored paths
 * stay portable between environments whose absolute paths differ, an export
 * carries no filesystem layout, and a multisite network resolves the same
 * stored string to a different per-site directory.
 */
final class Paths {

	/**
	 * Directory name created under the uploads directory.
	 */
	public const DIRNAME = 'basic-firewall-private';

	/**
	 * The scheme used in stored settings.
	 */
	public const SCHEME = 'private://';

	/**
	 * Option holding this site's random directory suffix.
	 */
	public const SUFFIX_OPTION = 'basic_firewall_private_suffix';

	/**
	 * Cached base directory.
	 *
	 * @var string|null
	 */
	private ?string $base = null;

	/**
	 * Absolute path to the private directory, without a trailing slash.
	 *
	 * Not created as a side effect of being asked for. Callers that intend to
	 * write call ensure() and handle the failure.
	 */
	public function base(): string {
		if ( null !== $this->base ) {
			return $this->base;
		}

		/**
		 * Filters the absolute path of the firewall's private directory.
		 *
		 * The intended use is a directory outside the web root entirely, which
		 * is strictly better than anything under uploads and is available on
		 * hosts that allow writing there. A site taking this filter is
		 * responsible for the directory being writable; the guard files are
		 * still written, and the reachability test still runs.
		 *
		 * @param string $path Absolute path, no trailing slash.
		 */
		$filtered = apply_filters( 'basic_firewall_private_path', $this->default_base() );

		$this->base = rtrim( (string) $filtered, '/\\' );

		return $this->base;
	}

	/**
	 * The default location, under this site's uploads directory.
	 *
	 * `wp_upload_dir()` is per-site on multisite -- `uploads/sites/N/` -- which
	 * is what separates one site's block list, logs and counters from its
	 * siblings' without any work of our own.
	 */
	private function default_base(): string {
		$uploads = wp_upload_dir( null, false );
		$name    = self::DIRNAME . '-' . $this->suffix();

		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			// Fall back inside wp-content, which is writable if anything is.
			return rtrim( WP_CONTENT_DIR, '/\\' ) . '/' . $name;
		}

		return rtrim( (string) $uploads['basedir'], '/\\' ) . '/' . $name;
	}

	/**
	 * A random, stable, per-site suffix for the directory name.
	 *
	 * Defence in depth, and an unusually important piece of it, because the
	 * guard files cannot be relied on.
	 *
	 * `.htaccess` and `web.config` are read by Apache and IIS. **nginx reads
	 * neither**, and nginx serves a large share of WordPress sites -- including
	 * most of the managed hosts this plugin is aimed at. On such a server
	 * `index.php` prevents a directory *listing* and nothing else: a direct
	 * request for `blocked.data`, `firewall.yml` or a log file is answered with
	 * the file. That is not a hypothetical. It is what this plugin's own
	 * reachability probe finds on a stock nginx site, and it is why that probe
	 * must test a real filename rather than a dotfile -- see probe_reachability().
	 *
	 * A guessable path plus a server that serves it is a download link for the
	 * block list, the firewall log and the compiled configuration. An
	 * unguessable one means an attacker has to be told the name before any of
	 * that is reachable.
	 *
	 * This is mitigation, not a fix. The fix is a server rule or a directory
	 * outside the web root, and Site Health asks for one when the probe finds
	 * the directory exposed. But mitigation that works everywhere, with no
	 * configuration, is worth having underneath a fix that has to be applied by
	 * hand on every host that needs it.
	 *
	 * Generated once and stored, because changing it would orphan the block
	 * list and the logs rather than move them.
	 */
	private function suffix(): string {
		$stored = get_option( self::SUFFIX_OPTION, '' );

		if ( is_string( $stored ) && 1 === preg_match( '/^[a-f0-9]{16}$/', $stored ) ) {
			return $stored;
		}

		$suffix = bin2hex( random_bytes( 8 ) );

		update_option( self::SUFFIX_OPTION, $suffix, true );

		return $suffix;
	}

	/**
	 * The URL the private directory would be served at, if it is reachable.
	 *
	 * Returns null when the directory is not under the uploads directory, in
	 * which case there is no URL to probe and the reachability test reports
	 * that instead of a false pass.
	 */
	public function base_url(): ?string {
		$uploads = wp_upload_dir( null, false );

		if ( empty( $uploads['basedir'] ) || empty( $uploads['baseurl'] ) ) {
			return null;
		}

		$basedir = rtrim( (string) $uploads['basedir'], '/\\' );

		if ( 0 !== strpos( $this->base(), $basedir ) ) {
			return null;
		}

		$relative = str_replace( '\\', '/', substr( $this->base(), strlen( $basedir ) ) );

		return rtrim( (string) $uploads['baseurl'], '/' ) . $relative;
	}

	/**
	 * Resolve a stored path to an absolute one.
	 *
	 * A `private://` path resolves under the private directory. Anything else is
	 * returned untouched, so an administrator who supplied an absolute path gets
	 * the path they asked for.
	 *
	 * @param string $path Stored path.
	 */
	public function resolve( string $path ): string {
		if ( 0 !== strpos( $path, self::SCHEME ) ) {
			return $path;
		}

		$relative = substr( $path, strlen( self::SCHEME ) );

		/*
		 * A stored path is administrator-supplied and reaches this method from
		 * an imported document as readily as from a form, so `..` is stripped
		 * rather than trusted. Without this, `private://../../wp-config.php` is
		 * a writable target.
		 */
		$parts = array();

		foreach ( explode( '/', str_replace( '\\', '/', $relative ) ) as $segment ) {
			if ( '' === $segment || '.' === $segment || '..' === $segment ) {
				continue;
			}

			$parts[] = $segment;
		}

		return $this->base() . '/' . implode( '/', $parts );
	}

	/**
	 * Create the directory and write the guard files.
	 *
	 * Idempotent, and safe to call on every admin request. Returns the problems
	 * it could not fix, empty when everything is in place.
	 *
	 * @return list<string> Human-readable problems.
	 */
	public function ensure(): array {
		$problems = array();
		$base     = $this->base();

		if ( ! is_dir( $base ) && ! wp_mkdir_p( $base ) ) {
			return array(
				sprintf(
					/* translators: %s: directory path. */
					__( 'The private directory %s could not be created. The firewall cannot store its compiled configuration, block list or logs.', 'basic-firewall' ),
					$base
				),
			);
		}

		if ( ! wp_is_writable( $base ) ) {
			$problems[] = sprintf(
				/* translators: %s: directory path. */
				__( 'The private directory %s is not writable.', 'basic-firewall' ),
				$base
			);
		}

		foreach ( $this->guard_files() as $name => $contents ) {
			$path = $base . '/' . $name;

			if ( is_readable( $path ) && trim( (string) file_get_contents( $path ) ) === trim( $contents ) ) {
				continue;
			}

			if ( false === file_put_contents( $path, $contents ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$problems[] = sprintf(
					/* translators: %s: file path. */
					__( 'The guard file %s could not be written, so the directory may be readable over the web.', 'basic-firewall' ),
					$path
				);
			}
		}

		foreach ( array( 'logs', 'cache', 'cache/compiled', 'device-detector', 'abuseipdb' ) as $child ) {
			$path = $base . '/' . $child;

			if ( ! is_dir( $path ) ) {
				wp_mkdir_p( $path );
			}

			if ( is_dir( $path ) && ! is_readable( $path . '/index.php' ) ) {
				file_put_contents( $path . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			}
		}

		return $problems;
	}

	/**
	 * The guard files and their contents.
	 *
	 * @return array<string, string>
	 */
	private function guard_files(): array {
		return array(
			'.htaccess'  => "# Basic Firewall private directory. Written by the plugin; edits are overwritten.\n"
				. "# Apache 2.4 and LiteSpeed.\n"
				. "<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n"
				. "# Apache 2.2.\n"
				. "<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n"
				. "# Nothing here should ever be executed, whatever the server decides it is.\n"
				. "<IfModule mod_php.c>\n\tphp_flag engine off\n</IfModule>\n",

			'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				. "<!-- Basic Firewall private directory. Written by the plugin; edits are overwritten. -->\n"
				. "<configuration>\n\t<system.webServer>\n\t\t<authorization>\n"
				. "\t\t\t<deny users=\"*\" />\n"
				. "\t\t</authorization>\n\t</system.webServer>\n</configuration>\n",

			/*
			 * The only guard that works on nginx, which reads neither of the
			 * others. A request for the directory gets an empty page instead of
			 * an index of the block list and the logs.
			 */
			'index.php'  => "<?php\n// Silence is golden.\n",
		);
	}

	/**
	 * Ask the web server for a file in the private directory.
	 *
	 * The point is to find out what the server actually does, not what its
	 * configuration files say it should. A 200 carrying the canary means the
	 * directory is being served and every guard file was ignored.
	 *
	 * @return array{status: string, message: string, url: string|null}
	 */
	public function probe_reachability(): array {
		$url = $this->base_url();

		if ( null === $url ) {
			return array(
				'status'  => 'unknown',
				'message' => __( 'The private directory is outside the uploads directory, so it has no public URL to test. Confirm for yourself that it cannot be reached over the web.', 'basic-firewall' ),
				'url'     => null,
			);
		}

		$token   = 'basic-firewall-canary-' . bin2hex( random_bytes( 8 ) );
		$results = array();

		foreach ( $this->probe_filenames() as $name ) {
			$results[ $name ] = $this->probe_one( $url, $name, $token );
		}

		$exposed = array_keys( array_filter( $results, static fn ( string $r ): bool => 'exposed' === $r ) );

		if ( array() !== $exposed ) {
			return array(
				'status'  => 'exposed',
				'message' => sprintf(
					/* translators: %s: comma-separated list of filenames. */
					__( 'The private directory is readable over the web. A request for %s returned the file. The block list, the firewall logs and the compiled configuration can all be downloaded by anyone who knows the path. Deny access to this directory in your web server configuration, or move it outside the web root with the basic_firewall_private_path filter.', 'basic-firewall' ),
					implode( ', ', $exposed )
				),
				'url'     => $url,
			);
		}

		if ( in_array( 'protected', $results, true ) ) {
			return array(
				'status'  => 'protected',
				'message' => __( 'The private directory is not readable over the web.', 'basic-firewall' ),
				'url'     => $url,
			);
		}

		return array(
			'status'  => 'unknown',
			'message' => __( 'The private directory could not be reached for testing. That often means outbound requests from this server are blocked, which is not itself a problem, but it does mean this check proved nothing.', 'basic-firewall' ),
			'url'     => $url,
		);
	}

	/**
	 * The filenames the probe asks for.
	 *
	 * These are not arbitrary, and the list is the whole point of the check.
	 *
	 * An earlier version of this probe used a single dotfile and reported the
	 * directory **protected** on a stock nginx site whose `blocked.data` and
	 * `firewall.yml` were both downloadable. It was not wrong about the file it
	 * asked for: nginx configurations very commonly carry a
	 * `location ~ /\.  { deny all; }` rule, so a dotfile is denied on servers
	 * that serve everything else in the same directory. The probe had measured
	 * the one filename in the directory that was not at risk, and reported a
	 * pass.
	 *
	 * So the probe asks for the extensions that actually hold the sensitive
	 * data, and a dotfile is deliberately not among them.
	 *
	 * @return list<string>
	 */
	private function probe_filenames(): array {
		return array(
			// The compiled configuration.
			'reachability-probe.yml',
			// The block list and the offense history.
			'reachability-probe.data',
			// A log file, which is in a subdirectory and so tests that too.
			'logs/reachability-probe.log',
		);
	}

	/**
	 * Ask for one file and classify the answer.
	 *
	 * @param string $base_url Public URL of the private directory.
	 * @param string $name     Relative filename to write and request.
	 * @param string $token    Canary content to look for in the response.
	 *
	 * @return string One of exposed, protected, unknown.
	 */
	private function probe_one( string $base_url, string $name, string $token ): string {
		$path = $this->base() . '/' . $name;
		$dir  = dirname( $path );

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return 'unknown';
		}

		if ( false === file_put_contents( $path, $token ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return 'unknown';
		}

		$response = wp_remote_get(
			$base_url . '/' . $name,
			array(
				'timeout'     => 10,
				'redirection' => 0,
				/*
				 * A request to the site's own uploads directory, often over a
				 * local or development certificate. Verifying it would make this
				 * check fail for a reason that has nothing to do with what it is
				 * measuring.
				 */
				'sslverify'   => false,
				'user-agent'  => 'Basic Firewall private directory check',
			)
		);

		wp_delete_file( $path );

		if ( is_wp_error( $response ) ) {
			return 'unknown';
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		/*
		 * The body has to contain the canary. A 200 alone is not evidence of
		 * exposure -- a site with a catch-all route answers 200 with its own
		 * 404 page, and treating that as a leak would cry wolf on every site
		 * using a front controller.
		 */
		if ( 200 === $code && false !== strpos( (string) wp_remote_retrieve_body( $response ), $token ) ) {
			return 'exposed';
		}

		return 'protected';
	}

	/**
	 * Path of the compiled configuration file.
	 */
	public function compiled_file(): string {
		return $this->base() . '/firewall.yml';
	}

	/**
	 * Directory the library writes its parsed-configuration cache into.
	 *
	 * Beside the compiled file, and persistent. Pointed here rather than left to
	 * the system temporary directory because a temp directory gets cleared, and
	 * every clear costs a 42 ms parse on the next request through every worker.
	 */
	public function parse_cache_dir(): string {
		return $this->base() . '/cache/compiled';
	}

	/**
	 * Forget the cached base path. Test seam.
	 *
	 * @internal
	 */
	public function reset(): void {
		$this->base = null;
	}
}
