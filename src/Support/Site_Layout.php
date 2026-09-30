<?php
/**
 * Where the site's front controller and WordPress's own files are served.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Support;

/**
 * The two URL paths the library's `path_source: script_name` needs to know.
 *
 * Under `script_name` the library matches the file the web server ran:
 * `SCRIPT_NAME` plus `PATH_INFO`, or Symfony's `getPathInfo()` when that file
 * is the front controller, `<base_path>/index.php`. Nothing in a direct-file
 * request says where the front controller is -- `getBasePath()` for
 * `/wp-admin/edit.php` is `/wp-admin` -- so the compiler writes `base_path`
 * into the compiled file, and this is where it comes from.
 *
 * **base_path is where the front controller is, not where WordPress is.** The
 * two differ in exactly one common layout:
 *
 * | Layout                                  | home    | siteurl | base_path | wp-login.php matches as |
 * |-----------------------------------------|---------|---------|-----------|-------------------------|
 * | At the web root                         | `/`     | `/`     | none      | `/wp-login.php`         |
 * | In a subdirectory                       | `/blog` | `/blog` | `/blog`   | `/wp-login.php`         |
 * | In its own directory (Bedrock and kin)  | `/`     | `/wp`   | none      | `/wp/wp-login.php`      |
 * | Multisite, subdirectory network at `/`  | `/site2`| `/site2`| none      | `/wp-login.php`         |
 *
 * WordPress in its own directory keeps `index.php` at the web root and its core
 * files under `/wp/`, so the front controller is `/index.php` and `base_path`
 * has to be empty. Setting it to `/wp` would strip the prefix from the core
 * files, but it would also make `/wp/index.php` the front controller, and then
 * every front-end request -- which runs `/index.php` -- would be matched as
 * `/index.php`. So on that layout the core files match with their prefix, and
 * a rule on the login page has to say `/wp/wp-login.php`. Site Health and the
 * README say so. That is deliberate: the alternative is reading the path back
 * out of the raw URL, which is the spelling bypass `script_name` exists to
 * close.
 *
 * **A network uses its own path, not each site's.** On a subdirectory network
 * the web server rewrites `/site2/wp-login.php` and `/site2/wp-admin/...` to the
 * network's own copies (WordPress's generated `.htaccess` and nginx rules both
 * do), so `SCRIPT_NAME` is `/wp-login.php` for every site, and front-end
 * requests for every site go through the network's one `index.php`. The
 * network's path is therefore the base path, and WordPress's own files are
 * wherever the main site's WordPress address puts them.
 *
 * **Read from stored addresses, never from the current request.** The compiler
 * runs in wp-admin, on cron and under WP-CLI, so `$pagenow`, `SCRIPT_NAME` and
 * `PHP_SELF` at compile time describe whatever screen or command triggered the
 * rebuild -- `/wp-admin/admin.php`, or nothing at all -- and say nothing about
 * where the front controller is. The early path, which reads the compiled file,
 * cannot work it out either: it runs before WordPress and has no options. The
 * raw `home` and `siteurl` options are used rather than home_url() and
 * site_url(), whose filters a multilingual plugin uses to add a language
 * prefix that is no part of where the files are.
 */
final class Site_Layout {

	/**
	 * Where the front controller's directory is served: `` or `/blog`.
	 *
	 * The compiled `global.base_path`, when it is not empty.
	 */
	public static function base_path(): string {
		return self::derive( self::addresses() )['base_path'];
	}

	/**
	 * Where WordPress's own files are served: `` , `/blog` or `/wp`.
	 */
	public static function core_path(): string {
		return self::derive( self::addresses() )['core_path'];
	}

	/**
	 * Where WordPress's own files are, relative to the base path.
	 *
	 * Empty when they are served beside the front controller, `/wp` when
	 * WordPress has its own directory: the prefix a rule on `wp-login.php`
	 * needs on this site.
	 */
	public static function core_prefix(): string {
		$layout = self::derive( self::addresses() );

		return self::relative( $layout['core_path'], $layout['base_path'] );
	}

	/**
	 * The layout from the addresses, as a pure function.
	 *
	 * @param array{home: string, siteurl: string, network_path?: string|null, network_siteurl?: string|null} $addresses
	 *        The site's addresses; on a network, also the network's path and the main site's WordPress address.
	 *
	 * @return array{base_path: string, core_path: string}
	 */
	public static function derive( array $addresses ): array {
		$network_path = $addresses['network_path'] ?? null;

		if ( is_string( $network_path ) ) {
			return array(
				'base_path' => self::trim( $network_path ),
				'core_path' => self::path_of( (string) ( $addresses['network_siteurl'] ?? $network_path ) ),
			);
		}

		return array(
			'base_path' => self::path_of( $addresses['home'] ),
			'core_path' => self::path_of( $addresses['siteurl'] ),
		);
	}

	/**
	 * `$path` relative to `$base`, or `$path` whole when it is not under it.
	 *
	 * @param string $path A URL path without a trailing slash.
	 * @param string $base A URL path without a trailing slash.
	 */
	public static function relative( string $path, string $base ): string {
		if ( '' === $base ) {
			return $path;
		}

		if ( $path === $base ) {
			return '';
		}

		return 0 === strpos( $path, $base . '/' ) ? substr( $path, strlen( $base ) ) : $path;
	}

	/**
	 * The addresses this site is stored with.
	 *
	 * @return array{home: string, siteurl: string, network_path?: string|null, network_siteurl?: string|null}
	 */
	private static function addresses(): array {
		$addresses = array(
			'home'    => (string) get_option( 'home' ),
			'siteurl' => (string) get_option( 'siteurl' ),
		);

		if ( is_multisite() ) {
			$network = get_network();

			$addresses['network_path']    = $network ? (string) $network->path : '/';
			$addresses['network_siteurl'] = (string) get_site_url( get_main_site_id() );
		}

		return $addresses;
	}

	/**
	 * The path of a URL, with no trailing slash: `` for the root.
	 *
	 * @param string $url An absolute URL.
	 */
	private static function path_of( string $url ): string {
		// parse_url(), not wp_parse_url(): derive() is pure and unit-tested
		// without WordPress, and the addresses are absolute URLs either way.
		$path = parse_url( $url, PHP_URL_PATH ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url

		return is_string( $path ) ? self::trim( $path ) : '';
	}

	/**
	 * A path with one leading slash and no trailing one, or `` for the root.
	 *
	 * @param string $path A URL path.
	 */
	private static function trim( string $path ): string {
		$path = trim( trim( $path ), '/' );

		return '' === $path ? '' : '/' . $path;
	}
}
