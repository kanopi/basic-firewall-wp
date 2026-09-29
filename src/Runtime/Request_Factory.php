<?php
/**
 * Builds the Symfony request the firewall evaluates.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Symfony\Component\HttpFoundation\Request;

/**
 * The one place a request for the firewall is made.
 *
 * **Why this exists.** The library matches `path`, rate limit patterns, the
 * block records it writes and the `path` it logs against Symfony's
 * `getPathInfo()`: the URL path with the front controller's base URL taken off.
 * Symfony finds that base URL from `SCRIPT_NAME`, which is right for an
 * application where every request goes through `index.php`. WordPress is not
 * one. It serves real pages from the file that was requested -- `wp-login.php`,
 * `xmlrpc.php`, `wp-cron.php`, every `wp-admin/*.php`, and whatever custom
 * endpoint a site drops in its root -- and for those `SCRIPT_NAME` *is* the
 * requested file. Symfony takes the whole path as the base URL and the path
 * the rules see is `/`. A `/wp-login.php` rate limit never counted a login, a
 * rule on `/wp-admin` never matched a screen, and a negated path condition
 * matched every one of them (#30).
 *
 * **What it does.** It builds the request from the globals as Symfony would,
 * then points `SCRIPT_NAME` and `PHP_SELF` at the front controller and
 * `SCRIPT_FILENAME` at `ABSPATH . 'index.php'` in *the request's own* server
 * bag. A direct request then looks the way an `index.php`-routed one already
 * does, and `getPathInfo()` is the requested path. The real `$_SERVER` is never
 * touched: WordPress derives `$pagenow` from `PHP_SELF`, and the login form's
 * action and the admin's redirects follow from that.
 *
 * **The front controller is worked out, not assumed.** A site served from
 * `/blog/` has its front controller at `/blog/index.php`, and a direct request
 * says so: `SCRIPT_NAME` is `/blog/wp-admin/edit.php` and `SCRIPT_FILENAME` is
 * `ABSPATH . 'wp-admin/edit.php'`, so the web prefix is what is left of the
 * one once the other's path under `ABSPATH` is taken off its end. When the two
 * cannot be reconciled -- a script outside `ABSPATH`, a server that reports
 * something else in `SCRIPT_NAME`, the CLI -- the request is left exactly as
 * Symfony built it. A wrong guess would move every path rule somewhere nobody
 * configured it; leaving it alone is the behaviour the site already had.
 *
 * **WordPress-free.** The wp-config.php path loads this file by hand, before
 * WordPress exists, and builds the request from the same copy of the library
 * it built the firewall from. Nothing here may call a WordPress function.
 */
final class Request_Factory {

	/**
	 * The front controller, as a path under ABSPATH.
	 */
	private const FRONT_CONTROLLER = 'index.php';

	/**
	 * The current request, as the firewall should see it.
	 */
	public static function from_globals(): Request {
		$request = Request::createFromGlobals();

		self::normalise( $request );

		return $request;
	}

	/**
	 * The current request, built from a named copy of Symfony's Request.
	 *
	 * For the wp-config.php path, which must use the copy the firewall was
	 * built from -- scoped or not, see basic_firewall_library_prefix() -- and
	 * cannot rely on this file's own `use` having been rewritten to match.
	 *
	 * @param string $request_class A Symfony Request class name.
	 *
	 * @return object The request, an instance of `$request_class`.
	 */
	public static function from_globals_of( string $request_class ): object {
		$request = call_user_func( array( $request_class, 'createFromGlobals' ) );

		self::normalise( $request );

		return $request;
	}

	/**
	 * Point a freshly built request's server bag at the front controller.
	 *
	 * Only on a request nothing has asked for its path yet: Symfony works the
	 * base URL out once and keeps it. A request built by createFromGlobals()
	 * or create() and handed straight here is in that state.
	 *
	 * @param object $request A Symfony Request.
	 */
	public static function normalise( object $request ): void {
		if ( ! isset( $request->server ) || ! is_object( $request->server ) || ! method_exists( $request->server, 'all' ) ) {
			return;
		}

		$replacement = self::front_controller( $request->server->all(), self::abspath() );

		foreach ( null === $replacement ? array() : $replacement as $key => $value ) {
			$request->server->set( $key, $value );
		}
	}

	/**
	 * The server values that make a direct request look `index.php`-routed.
	 *
	 * A pure function of its arguments, so every case can be tested without
	 * a web server. Null means "leave the request alone": it is already
	 * routed through the front controller, or the values do not describe a
	 * file under `$abspath` in a way that can be trusted.
	 *
	 * @param array<string, mixed> $server  Server values, as `$_SERVER` has them.
	 * @param string               $abspath The WordPress root, ABSPATH.
	 *
	 * @return array{SCRIPT_NAME: string, PHP_SELF: string, SCRIPT_FILENAME: string}|null
	 */
	public static function front_controller( array $server, string $abspath ): ?array {
		$script_name = $server['SCRIPT_NAME'] ?? null;
		$script_file = $server['SCRIPT_FILENAME'] ?? null;

		if ( ! is_string( $script_name ) || ! is_string( $script_file ) || '' === $script_name || '' === $script_file || '' === $abspath ) {
			return null;
		}

		$relative = self::relative_path( $script_file, $abspath );

		// Already the front controller, including `/index.php/some/path`:
		// Symfony handles that shape itself.
		if ( null === $relative || '' === $relative || self::FRONT_CONTROLLER === $relative ) {
			return null;
		}

		/*
		 * The web prefix is SCRIPT_NAME with the file's path under ABSPATH
		 * taken off its end. If SCRIPT_NAME does not end that way, the server
		 * is describing the request in terms this cannot map back -- a rewrite
		 * that changed the script name, `cgi.fix_pathinfo` folding PATH_INFO
		 * into it -- and the request is left as it was built.
		 */
		$suffix = '/' . $relative;

		if ( strlen( $script_name ) < strlen( $suffix ) || substr( $script_name, -strlen( $suffix ) ) !== $suffix ) {
			return null;
		}

		$prefix = substr( $script_name, 0, -strlen( $suffix ) );

		if ( '' !== $prefix && '/' !== $prefix[0] ) {
			return null;
		}

		$front     = $prefix . '/' . self::FRONT_CONTROLLER;
		$path_info = $server['PATH_INFO'] ?? '';

		return array(
			'SCRIPT_NAME'     => $front,

			// PHP_SELF is SCRIPT_NAME followed by any PATH_INFO, as the
			// server would have reported it for the front controller.
			'PHP_SELF'        => $front . ( is_string( $path_info ) ? $path_info : '' ),
			'SCRIPT_FILENAME' => rtrim( $abspath, '/\\' ) . '/' . self::FRONT_CONTROLLER,
		);
	}

	/**
	 * The server values a web server gives a request for a path on this site.
	 *
	 * For the requests this plugin makes up -- the request tester and the
	 * Site Health check -- so they are built the way a real request is and
	 * then go through front_controller() like one. A path naming a PHP file
	 * that exists under `$abspath` is a direct request for it; anything else
	 * is routed through `index.php`, as the web server's rewrite would.
	 *
	 * @param string $path      The path relative to the site, e.g. `/wp-login.php?x=1`.
	 * @param string $site_path The site's own path on the host: `` or `/blog`.
	 * @param string $abspath   The WordPress root, ABSPATH.
	 *
	 * @return array{REQUEST_URI: string, SCRIPT_NAME: string, PHP_SELF: string, SCRIPT_FILENAME: string}
	 */
	public static function server_for( string $path, string $site_path, string $abspath ): array {
		$site_path = rtrim( $site_path, '/' );
		$uri       = $site_path . '/' . ltrim( $path, '/' );
		$location  = (string) strtok( '/' . ltrim( $path, '/' ), '?#' );
		$root      = rtrim( $abspath, '/\\' ) . '/';
		$script    = '/' . self::FRONT_CONTROLLER;
		$extra     = $location;

		if ( 1 === preg_match( '#^(/(?:[^/]+/)*?[^/]+\.php)(/.*)?$#i', $location, $parts ) && is_file( $root . ltrim( $parts[1], '/' ) ) ) {
			$script = $parts[1];
			$extra  = $parts[2] ?? '';
		}

		return array(
			'REQUEST_URI'     => $uri,
			'SCRIPT_NAME'     => $site_path . $script,
			'PHP_SELF'        => $site_path . $script . ( '/' . self::FRONT_CONTROLLER === $script ? '' : $extra ),
			'SCRIPT_FILENAME' => $root . ltrim( $script, '/' ),
		);
	}

	/**
	 * The requested file's path under the WordPress root, or null.
	 *
	 * Compared as given first, which is every ordinary server. Only when that
	 * fails are both resolved, for a docroot reached through a symlink that
	 * ABSPATH (built from `__DIR__`, so already resolved) does not share.
	 *
	 * @param string $file    SCRIPT_FILENAME.
	 * @param string $abspath ABSPATH.
	 */
	private static function relative_path( string $file, string $abspath ): ?string {
		$relative = self::under( $file, $abspath );

		if ( null !== $relative ) {
			return $relative;
		}

		$real_file = realpath( $file );
		$real_root = realpath( $abspath );

		return false === $real_file || false === $real_root ? null : self::under( $real_file, $real_root );
	}

	/**
	 * `$file` relative to `$root`, with forward slashes, or null if outside it.
	 *
	 * @param string $file File path.
	 * @param string $root Directory path.
	 */
	private static function under( string $file, string $root ): ?string {
		$file = str_replace( '\\', '/', $file );
		$root = rtrim( str_replace( '\\', '/', $root ), '/' ) . '/';

		return 0 === strpos( $file, $root ) ? substr( $file, strlen( $root ) ) : null;
	}

	/**
	 * ABSPATH, or an empty string where it is not defined.
	 */
	private static function abspath(): string {
		return defined( 'ABSPATH' ) ? ABSPATH : '';
	}
}
