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
	 * Fragments of the library's entry class name.
	 *
	 * Assembled at runtime, never written as a single literal, and that is not
	 * paranoia -- it is a bug that shipped.
	 *
	 * This class has to ask two questions that a scoped build makes subtle: does
	 * the UNPREFIXED name exist, and does the PREFIXED one? A `::class` constant
	 * cannot answer the first, because php-scoper rewrites it. Neither can a
	 * plain string: php-scoper also rewrites string literals that look like
	 * class names, so `'Kanopi\\Firewall\\Firewall'` became
	 * `'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Firewall'` in the built
	 * plugin. The check for "is the unscoped class present" then found the
	 * scoped one, concluded the build was unscoped, and reported
	 *
	 *   Library  2.25.0 (bundled-unscoped)
	 *   Collision safe  no
	 *
	 * on a correctly scoped release. The firewall worked; the one thing this
	 * class exists to tell you about it was inverted.
	 *
	 * Split across an implode(), php-scoper sees no class name to rewrite.
	 *
	 * @var list<string>
	 */
	private const ENTRY_FRAGMENTS = array( 'Kanopi', 'Firewall', 'Firewall' );

	/**
	 * Fragments of this plugin's vendor prefix, for the same reason.
	 *
	 * @var list<string>
	 */
	private const PREFIX_FRAGMENTS = array( 'Kanopi', 'BasicFirewall', 'Vendor' );

	/**
	 * How the library was resolved, or null before boot() has run.
	 *
	 * @var string|null
	 */
	private static ?string $mode = null;

	/**
	 * Why the library is unusable, as a message key, or null when it is fine.
	 *
	 * A key rather than a translated string. boot() runs when the plugin file
	 * is loaded, long before `init`, and calling __() there makes WordPress 6.7
	 * and later emit "Translation loading was triggered too early" on every
	 * request -- a notice that is correct, and that a security plugin printing
	 * on every page is not a good look for. The message is translated when it is
	 * read, which is always inside an admin screen or a CLI command.
	 *
	 * @var string|null
	 */
	private static ?string $failure = null;

	/**
	 * Substituted into the failure message when it is read.
	 *
	 * @var array<int, string>
	 */
	private static array $failure_args = array();

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

		if ( ! self::entry_class_exists() ) {
			$autoload = BASIC_FIREWALL_DIR . 'vendor/autoload.php';

			if ( ! is_readable( $autoload ) ) {
				self::$mode    = 'missing';
				self::$failure = 'no-vendor';

				return;
			}

			require_once $autoload;

			if ( ! self::entry_class_exists() ) {
				self::$mode    = 'missing';
				self::$failure = 'no-library';

				return;
			}
		}

		self::$mode    = self::resolve_mode();
		self::$version = self::detect_version();

		self::check_version();
	}

	/**
	 * Work out where the loaded library actually came from.
	 *
	 * Determined from the resolved file path of the entry class, not from
	 * whether we were the one who registered the autoloader.
	 *
	 * The first version of this inferred the mode from load order -- "the class
	 * already existed when we looked, so somebody else must have provided it".
	 * That was wrong on a perfectly ordinary site: this one has three Composer
	 * class loaders registered before the plugin runs, and the answer depended
	 * on which of them happened to win a race we had no visibility into. It
	 * reported `site-composer` for a library sitting in the plugin's own vendor
	 * directory.
	 *
	 * The file path cannot be raced. It says where the code being executed lives,
	 * which is the only thing the caller actually wants to know.
	 */
	private static function resolve_mode(): string {
		$scoped = ! class_exists( self::unscoped_entry(), false ) && class_exists( self::scoped_entry(), false );
		$class  = $scoped ? self::scoped_entry() : self::unscoped_entry();

		try {
			$file = ( new \ReflectionClass( $class ) )->getFileName();
		} catch ( \Throwable $e ) {
			$file = false;
		}

		if ( false === $file ) {
			return $scoped ? 'bundled-scoped' : 'unknown';
		}

		$ours = realpath( BASIC_FIREWALL_DIR . 'vendor' );
		$real = realpath( $file );

		if ( false !== $ours && false !== $real && 0 === strpos( $real, $ours . DIRECTORY_SEPARATOR ) ) {
			return $scoped ? 'bundled-scoped' : 'bundled-unscoped';
		}

		/*
		 * A scoped library outside our own vendor directory would mean a second
		 * copy of this plugin, which is not a thing WordPress permits -- so this
		 * is a site-level Composer install, and it is the case the version check
		 * below exists for.
		 */
		return 'site-composer';
	}

	/**
	 * Whether the library entry class is loadable under either name.
	 *
	 * Marked impure because its answer genuinely changes between two calls that
	 * look identical: boot() asks, requires the vendor autoloader, and asks
	 * again. Without this, static analysis treats the second call as already
	 * narrowed and reports the check as dead code -- which it would be, if
	 * requiring an autoloader had no effect.
	 *
	 * @phpstan-impure
	 */
	private static function entry_class_exists(): bool {
		return class_exists( self::unscoped_entry() ) || class_exists( self::scoped_entry() );
	}

	/**
	 * The prefixed entry class name used by a scoped build.
	 *
	 * Assembled rather than written literally so that php-scoper does not
	 * rewrite it into a doubly-prefixed name when it processes this file.
	 */
	private static function scoped_entry(): string {
		return self::vendor_prefix() . '\\' . self::unscoped_entry();
	}

	/**
	 * The library's entry class as it is named outside a scoped build.
	 */
	private static function unscoped_entry(): string {
		return implode( '\\', self::ENTRY_FRAGMENTS );
	}

	/**
	 * This plugin's vendor namespace prefix.
	 */
	private static function vendor_prefix(): string {
		return implode( '\\', self::PREFIX_FRAGMENTS );
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

		$composer = implode( '\\', array( 'Composer', 'InstalledVersions' ) );

		foreach ( array( $composer, self::vendor_prefix() . '\\' . $composer ) as $class ) {
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

		self::$failure      = 'too-old';
		self::$failure_args = array( (string) self::$version, self::MINIMUM_LIBRARY );
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
		if ( null === self::$failure ) {
			return null;
		}

		switch ( self::$failure ) {
			case 'no-vendor':
				return __( 'The firewall library is not installed. This copy of the plugin has no vendor directory, which usually means it was checked out from git rather than installed from a release zip.', 'basic-firewall' );

			case 'no-library':
				return __( 'The firewall library did not load. A vendor directory is present but does not contain kanopi/firewall.', 'basic-firewall' );

			case 'too-old':
				return sprintf(
					/* translators: 1: installed library version, 2: required library version. */
					__( 'The firewall library is version %1$s, and this plugin requires %2$s or later. An older library re-parses the compiled configuration on every request and does not support every rule type offered here.', 'basic-firewall' ),
					self::$failure_args[0] ?? '',
					self::$failure_args[1] ?? self::MINIMUM_LIBRARY
				);

			default:
				return self::$failure;
		}
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
		self::$mode         = null;
		self::$failure      = null;
		self::$failure_args = array();
		self::$version      = null;
	}
}
