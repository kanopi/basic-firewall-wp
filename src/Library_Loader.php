<?php
/**
 * Locates and registers the firewall library.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

/**
 * Decides which copy of kanopi/firewall this request is going to run against.
 *
 * There are three ways the library can arrive, and they are not interchangeable:
 *
 * 1. `bundled-scoped`   -- the release zip. vendor/ was built by CI and every
 *                          namespace in it was rewritten under a prefix private
 *                          to this plugin. Cannot collide with anything.
 * 2. `bundled-unscoped` -- a working copy where `composer install` was run in
 *                          the plugin directory. Convenient for development,
 *                          and collides like any other vendored library.
 * 3. `site-composer`    -- the plugin was installed with
 *                          `composer require kanopi/basic-firewall-wp`, so the
 *                          library lives in the site's own vendor tree and is
 *                          already autoloaded before any plugin file runs.
 *
 * Only the first is collision-proof. For the other two this class does what the
 * brief calls the guarded autoload: it refuses to silently defer to whatever
 * version loaded first. If the library is already present when we arrive, we do
 * not register a second copy over the top of it -- the first autoloader
 * registered wins in PHP regardless, so registering anyway would only produce a
 * plugin that believes it is running code it is not. Instead the already-loaded
 * version is checked, and a version too old to support this plugin is reported
 * as an Error in Site Health rather than being run against.
 *
 * @see DECISIONS.md, sections 0 and 1.
 */
final class Library_Loader {

	/**
	 * Lowest library version this plugin is tested against.
	 *
	 * Mirrors the Drupal module's floor, for the reasons its README gives: the
	 * parse cache (2.21.0) and content-based invalidation (2.23.0) are the
	 * difference between reading the compiled configuration in 0.08 ms and in
	 * 42 ms on every single request.
	 */
	public const MINIMUM_LIBRARY = '2.24.0';

	/**
	 * Canonical, unprefixed name of the library's entry class.
	 *
	 * Written as a string rather than a ::class constant on purpose: in a scoped
	 * build php-scoper rewrites ::class constants, and this check needs to ask
	 * about the *unscoped* name specifically.
	 */
	private const UNSCOPED_ENTRY = 'Kanopi\\Firewall\\Firewall';

	/**
	 * How the library was resolved, or null before boot() has run.
	 *
	 * @var string|null
	 */
	private static ?string $mode = null;

	/**
	 * Why the library is unusable, or null when it is fine.
	 *
	 * @var string|null
	 */
	private static ?string $failure = null;

	/**
	 * Resolved library version, or null when it could not be determined.
	 *
	 * @var string|null
	 */
	private static ?string $version = null;

	/**
	 * Resolve and register the library.
	 *
	 * Never throws and never fatals. A firewall that cannot load its library
	 * must leave the site serving traffic and report the problem; taking the
	 * site down to complain about itself is not an option.
	 */
	public static function boot(): void {
		if ( null !== self::$mode ) {
			return;
		}

		// Case 3 and the double-load case: something already provided it.
		if ( self::entry_class_exists() ) {
			self::$mode    = class_exists( self::UNSCOPED_ENTRY, false ) ? 'site-composer' : 'bundled-scoped';
			self::$version = self::detect_version();
			self::check_version();
			return;
		}

		$autoload = BASIC_FIREWALL_DIR . 'vendor/autoload.php';

		if ( ! is_readable( $autoload ) ) {
			self::$mode    = 'missing';
			self::$failure = __( 'The firewall library is not installed. This copy of the plugin has no vendor directory, which usually means it was checked out from git rather than installed from a release zip.', 'basic-firewall' );
			return;
		}

		require_once $autoload;

		if ( ! self::entry_class_exists() ) {
			self::$mode    = 'missing';
			self::$failure = __( 'The firewall library did not load. A vendor directory is present but does not contain kanopi/firewall.', 'basic-firewall' );
			return;
		}

		self::$mode    = self::is_scoped() ? 'bundled-scoped' : 'bundled-unscoped';
		self::$version = self::detect_version();
		self::check_version();
	}

	/**
	 * Whether the library entry class is loadable under either name.
	 */
	private static function entry_class_exists(): bool {
		return class_exists( self::UNSCOPED_ENTRY ) || class_exists( self::scoped_entry() );
	}

	/**
	 * The prefixed entry class name used by a scoped build.
	 *
	 * Assembled rather than written literally so that php-scoper does not
	 * rewrite it into a doubly-prefixed name when it processes this file.
	 */
	private static function scoped_entry(): string {
		return 'Kanopi\\BasicFirewall\\Vendor\\' . self::UNSCOPED_ENTRY;
	}

	/**
	 * Whether the loaded library is the scoped copy.
	 */
	private static function is_scoped(): bool {
		return ! class_exists( self::UNSCOPED_ENTRY, false ) && class_exists( self::scoped_entry(), false );
	}

	/**
	 * Best available reading of the installed library version.
	 *
	 * Three sources, most to least trustworthy. The build-time marker is first
	 * because it is the only one that survives scoping with certainty --
	 * Composer's runtime API is itself a class in a namespace, and a scoped
	 * build may have rewritten or dropped it.
	 */
	private static function detect_version(): ?string {
		$marker = BASIC_FIREWALL_DIR . 'vendor-version.php';

		if ( is_readable( $marker ) ) {
			$pinned = require $marker;

			if ( is_array( $pinned ) && isset( $pinned['kanopi/firewall'] ) && is_string( $pinned['kanopi/firewall'] ) ) {
				return ltrim( $pinned['kanopi/firewall'], 'v' );
			}
		}

		foreach ( array( 'Composer\\InstalledVersions', 'Kanopi\\BasicFirewall\\Vendor\\Composer\\InstalledVersions' ) as $class ) {
			if ( ! class_exists( $class ) || ! method_exists( $class, 'isInstalled' ) ) {
				continue;
			}

			try {
				if ( ! $class::isInstalled( 'kanopi/firewall' ) ) {
					continue;
				}

				$pretty = $class::getPrettyVersion( 'kanopi/firewall' );

				if ( is_string( $pretty ) && '' !== $pretty ) {
					return ltrim( $pretty, 'v' );
				}
			} catch ( \Throwable $e ) {
				continue;
			}
		}

		return null;
	}

	/**
	 * Record a failure when the resolved version is below the floor.
	 *
	 * An undetectable version is deliberately not a failure. Version detection
	 * is a convenience; the plugin's real defence against a library that cannot
	 * do what it needs is the capability detection in Library_Capabilities,
	 * which asks the library what it can do rather than what it is called.
	 */
	private static function check_version(): void {
		if ( null === self::$version ) {
			return;
		}

		if ( version_compare( self::$version, self::MINIMUM_LIBRARY, '>=' ) ) {
			return;
		}

		self::$failure = sprintf(
			/* translators: 1: installed library version, 2: required library version. */
			__( 'The firewall library is version %1$s, and this plugin requires %2$s or later. An older library re-parses the compiled configuration on every request and does not support every rule type offered here.', 'basic-firewall' ),
			self::$version,
			self::MINIMUM_LIBRARY
		);
	}

	/**
	 * How the library was resolved. One of the mode strings, or null pre-boot.
	 */
	public static function mode(): ?string {
		return self::$mode;
	}

	/**
	 * The resolved library version, or null if it could not be read.
	 */
	public static function version(): ?string {
		return self::$version;
	}

	/**
	 * Whether the library is present and usable.
	 */
	public static function is_usable(): bool {
		return null === self::$failure && self::entry_class_exists();
	}

	/**
	 * Why the library is unusable, or null when it is fine.
	 */
	public static function failure(): ?string {
		return self::$failure;
	}

	/**
	 * Whether this build is immune to autoloader collisions.
	 */
	public static function is_collision_safe(): bool {
		return 'bundled-scoped' === self::$mode;
	}

	/**
	 * Reset internal state. Test seam only.
	 *
	 * @internal
	 */
	public static function reset(): void {
		self::$mode    = null;
		self::$failure = null;
		self::$version = null;
	}
}
