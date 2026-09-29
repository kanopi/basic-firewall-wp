<?php
/**
 * Works out which Composer autoloader the running library came from.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Support;

/**
 * Finds the `autoload.php` a site-level Composer install loaded the library
 * through, and says whether the wp-config.php snippet has to name it.
 *
 * The bootstrap can guess two places for a site's autoloader: the plugin's
 * own vendor/ and a vendor/ beside the WordPress root. A site whose
 * composer.json moves `vendor-dir` anywhere else -- into mu-plugins, say --
 * has to name it in the snippet, and cannot be expected to know that it has
 * to. By the time an admin screen runs, though, the library has been loaded
 * from somewhere, and where is a fact: the file its entry class was declared
 * in. So the screen that prints the snippet asks, and adds the line only when
 * the answer is somewhere the bootstrap would not have looked.
 *
 * No WordPress in here, so the unit suite can pin every branch.
 */
final class Autoloader_Locator {

	/**
	 * The autoloader line the snippet needs, as PHP source, or null for none.
	 *
	 * Only a `site-composer` install ever needs one. A release zip or a
	 * plugin-local install is found in the plugin's own vendor/, which the
	 * bootstrap tries first; and a location the bootstrap would guess anyway
	 * is left out, because a line that says what the default already says is
	 * one more thing to go stale in a copied wp-config.php.
	 *
	 * @param string             $mode        How Library_Loader resolved the library.
	 * @param string|null        $class_file  The file the library's entry class was declared in.
	 * @param array<int, string> $vendor_dirs Vendor directories of the registered Composer loaders.
	 * @param string             $abspath     ABSPATH.
	 * @param string             $plugin_dir  The plugin's own directory.
	 */
	public static function snippet_expression( string $mode, ?string $class_file, array $vendor_dirs, string $abspath, string $plugin_dir ): ?string {
		if ( 'site-composer' !== $mode || null === $class_file || '' === $class_file ) {
			return null;
		}

		$autoload = self::autoloader_for( $class_file, $vendor_dirs );

		if ( null === $autoload || self::is_guessed( $autoload, $abspath, $plugin_dir ) ) {
			return null;
		}

		return self::expression( $autoload, $abspath );
	}

	/**
	 * The `autoload.php` of the vendor tree a class file sits in.
	 *
	 * Composer 2 lists its registered loaders by vendor directory, which
	 * names the tree without guessing at what the directory is called -- a
	 * vendor-dir need not end in `vendor`. The deepest one containing the
	 * file wins, so a package that happens to carry a vendor tree of its own
	 * inside the site's is not mistaken for the site's. Without that list, the
	 * nearest directory above the file holding both `autoload.php` and
	 * `composer/` is the vendor directory, which is how Composer lays one out.
	 *
	 * @param string             $class_file  The file a class was declared in.
	 * @param array<int, string> $vendor_dirs Vendor directories of the registered Composer loaders.
	 */
	public static function autoloader_for( string $class_file, array $vendor_dirs ): ?string {
		$file = self::normalise( $class_file );
		$best = null;

		foreach ( $vendor_dirs as $vendor_dir ) {
			$dir = rtrim( self::normalise( (string) $vendor_dir ), '/' );

			if ( '' === $dir || 0 !== strpos( $file, $dir . '/' ) ) {
				continue;
			}

			if ( null === $best || strlen( $dir ) > strlen( $best ) ) {
				$best = $dir;
			}
		}

		if ( null !== $best ) {
			return $best . '/autoload.php';
		}

		$dir = dirname( $file );

		while ( '' !== $dir && '/' !== $dir && '.' !== $dir ) {
			if ( is_file( $dir . '/autoload.php' ) && is_dir( $dir . '/composer' ) ) {
				return $dir . '/autoload.php';
			}

			$parent = dirname( $dir );

			if ( $parent === $dir ) {
				break;
			}

			$dir = $parent;
		}

		return null;
	}

	/**
	 * Whether the bootstrap would find this autoloader without being told.
	 *
	 * The same places basic_firewall_resolve_autoloader() tries, compared
	 * after resolving symlinks and `..`, since `ABSPATH . '../vendor'` and
	 * `dirname( ABSPATH )` spell one directory two ways.
	 *
	 * @param string $autoload   Path to an autoload.php.
	 * @param string $abspath    ABSPATH.
	 * @param string $plugin_dir The plugin's own directory.
	 */
	public static function is_guessed( string $autoload, string $abspath, string $plugin_dir ): bool {
		$candidates = array(
			rtrim( $plugin_dir, '/' ) . '/vendor/autoload.php',
			dirname( rtrim( $abspath, '/' ) ) . '/vendor/autoload.php',
		);

		$autoload = self::normalise( $autoload );

		foreach ( $candidates as $candidate ) {
			if ( self::normalise( $candidate ) === $autoload ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * A path as PHP source for wp-config.php.
	 *
	 * Relative to ABSPATH when it is inside it, the way the snippet's
	 * require_once line is written, so the line survives the site moving
	 * between environments whose document roots differ. Anywhere else it is
	 * the absolute path, because there is nothing it is reliably relative to.
	 *
	 * @param string $autoload Path to an autoload.php.
	 * @param string $abspath  ABSPATH.
	 */
	public static function expression( string $autoload, string $abspath ): string {
		$autoload = self::normalise( $autoload );
		$root     = rtrim( self::normalise( $abspath ), '/' ) . '/';

		if ( '/' !== $root && 0 === strpos( $autoload, $root ) ) {
			return 'ABSPATH . ' . self::quote( substr( $autoload, strlen( $root ) ) );
		}

		return self::quote( $autoload );
	}

	/**
	 * A path with symlinks and `..` resolved when it exists, as given when not.
	 *
	 * @param string $path A filesystem path.
	 */
	private static function normalise( string $path ): string {
		$real = '' === $path ? false : realpath( $path );

		return str_replace( '\\', '/', false === $real ? $path : $real );
	}

	/**
	 * A single-quoted PHP string literal.
	 *
	 * @param string $value The string.
	 */
	private static function quote( string $value ): string {
		return "'" . str_replace( array( '\\', "'" ), array( '\\\\', "\\'" ), $value ) . "'";
	}
}
