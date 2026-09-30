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
 * **Why it is one place.** The wp-config.php path, the mu-plugin's runner
 * (including a logged-in request deferred to `plugins_loaded`) and the
 * lockdown screen's address check all build the request the library
 * evaluates, and the wp-config.php path has to build it from the same copy of
 * the library -- scoped or not -- that it built the firewall from. Keeping the
 * construction here means none of them can see one request differently.
 *
 * **What it no longer does.** The library matched `path` against Symfony's
 * `getPathInfo()`, which is `/` for a file the web server runs directly --
 * `wp-login.php`, `xmlrpc.php`, every `wp-admin/*.php` (#30). This factory used
 * to work around that by pointing the request's own `SCRIPT_NAME` at
 * `index.php`, so `getPathInfo()` returned the path out of the raw
 * `REQUEST_URI`. That was bypassable: the web server decodes and normalises
 * the URL before it chooses a file, so `/./wp-login.php`, `/%77p-login.php`,
 * `//wp-login.php`, `/x/../wp-login.php` and `/wp-login.php;x` all run
 * wp-login.php, and each reached the rules as the raw string rather than
 * `/wp-login.php`. kanopi/firewall 2.34.0 fixed it where it belongs: the
 * compiled `global.path_source: script_name` matches the file the server ran.
 * So the request is now built exactly as Symfony builds it, with no edits to
 * its server values, and the real `$_SERVER` is never touched either.
 *
 * **WordPress-free.** The wp-config.php path loads this file by hand, before
 * WordPress exists. Nothing here may call a WordPress function.
 */
final class Request_Factory {

	/**
	 * The front controller's file name.
	 */
	private const FRONT_CONTROLLER = 'index.php';

	/**
	 * The current request, as the firewall should see it.
	 */
	public static function from_globals(): Request {
		return Request::createFromGlobals();
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
		return call_user_func( array( $request_class, 'createFromGlobals' ) );
	}

	/**
	 * The server values a web server gives a request for a path on this site.
	 *
	 * For the requests this plugin makes up -- the request tester and the
	 * Site Health check -- so the library resolves their path the way it
	 * resolves a real one. A path naming a PHP file that exists under
	 * `$abspath`, where WordPress's files are served, is a direct request for
	 * it: `SCRIPT_NAME` is that file and anything after it is `PATH_INFO`.
	 * Anything else is routed through the front controller, as the web
	 * server's rewrite would, with `SCRIPT_NAME` `<base>/index.php`.
	 *
	 * The server's own normalisation is not simulated: the path is taken as
	 * the file it names, which is what the server would have run.
	 *
	 * @param string $path      The path relative to the base path, e.g. `/wp-login.php?x=1`.
	 * @param string $base_path Where the front controller's directory is served: `` or `/blog`.
	 * @param string $core_path Where ABSPATH is served: `` , `/blog` or `/wp`.
	 * @param string $abspath   The WordPress root, ABSPATH.
	 *
	 * @return array{REQUEST_URI: string, SCRIPT_NAME: string, PHP_SELF: string, SCRIPT_FILENAME: string, PATH_INFO: string}
	 */
	public static function server_for( string $path, string $base_path, string $core_path, string $abspath ): array {
		$base_path = rtrim( $base_path, '/' );
		$core_path = rtrim( $core_path, '/' );
		$uri       = $base_path . '/' . ltrim( $path, '/' );
		$location  = (string) strtok( $uri, '?#' );
		$root      = rtrim( $abspath, '/\\' ) . '/';

		if ( '' === $core_path || 0 === strpos( $location, $core_path . '/' ) ) {
			$under_core = substr( $location, strlen( $core_path ) );

			if ( 1 === preg_match( '#^(/(?:[^/]+/)*?[^/]+\.php)(/.*)?$#i', $under_core, $parts ) && is_file( $root . ltrim( $parts[1], '/' ) ) ) {
				$script = $core_path . $parts[1];
				$extra  = $parts[2] ?? '';

				return array(
					'REQUEST_URI'     => $uri,
					'SCRIPT_NAME'     => $script,
					'PHP_SELF'        => $script . $extra,
					'SCRIPT_FILENAME' => $root . ltrim( $parts[1], '/' ),
					'PATH_INFO'       => $extra,
				);
			}
		}

		$front = $base_path . '/' . self::FRONT_CONTROLLER;

		return array(
			'REQUEST_URI'     => $uri,
			'SCRIPT_NAME'     => $front,
			'PHP_SELF'        => $front,
			'SCRIPT_FILENAME' => self::front_controller_file( $root, $base_path, $core_path ),
			'PATH_INFO'       => '',
		);
	}

	/**
	 * Where the front controller is on disk.
	 *
	 * Beside ABSPATH's own index.php when WordPress is served from the base
	 * path; that many directories up when it has a directory of its own
	 * (`/wp` under the base: one up). Symfony reads only the file's name, so
	 * this matters less than it looks, but it is the file the server would run.
	 *
	 * @param string $root      ABSPATH, with a trailing slash.
	 * @param string $base_path The base path.
	 * @param string $core_path The core path.
	 */
	private static function front_controller_file( string $root, string $base_path, string $core_path ): string {
		$prefix = '' === $base_path ? $core_path : ( 0 === strpos( $core_path, $base_path . '/' ) ? substr( $core_path, strlen( $base_path ) ) : '' );
		$depth  = '' === $prefix ? 0 : substr_count( $prefix, '/' );
		$dir    = rtrim( $root, '/' );

		for ( $i = 0; $i < $depth; $i++ ) {
			$dir = dirname( $dir );
		}

		return $dir . '/' . self::FRONT_CONTROLLER;
	}
}
