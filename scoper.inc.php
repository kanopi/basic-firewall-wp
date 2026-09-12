<?php
/**
 * PHP-Scoper configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

use Isolated\Symfony\Component\Finder\Finder;

/*
 * Scoping puts the whole vendor tree under a namespace private to this plugin,
 * so that a site running a different copy of kanopi/firewall cannot make this
 * one run against a version it was never tested on.
 *
 * The part that needs care is documented in DECISIONS.md section 0 and repeated
 * here because this is the file that has to act on it:
 *
 *   kanopi/firewall resolves class names OUT OF CONFIGURATION DATA. PluginManager,
 *   StorageFactory, ChallengeProviderFactory and LoggingFactory all take a
 *   string from the config, call class_exists() on it, and instantiate it. And
 *   the library ships preset YAML files that hard-code those class names.
 *
 *   PHP-Scoper rewrites PHP. It does not rewrite YAML. Without the patcher
 *   below, a scoped build leaves every preset naming a class that no longer
 *   exists -- and the library responds by SKIPPING the plugin and carrying on.
 *   No exception, preset still ticked in the UI, status page green, nothing
 *   enforced.
 *
 * build/verify-scope.php is what proves the patcher actually did its job, and
 * keeps proving it when the library adds a preset or a new kind of data file.
 */

/**
 * Rewrite class-name strings inside a vendored data file.
 *
 * Exposed as a named function so the test at build/patcher-test.php can call it
 * without loading the Finder.
 *
 * @param string $file_path Absolute path of the file being processed.
 * @param string $prefix    The namespace prefix being applied.
 * @param string $contents  File contents.
 *
 * @return string
 */
function basic_firewall_scope_data_file( string $file_path, string $prefix, string $contents ): string {
	/*
	 * ONLY the firewall library's own configuration data.
	 *
	 * This patcher exists to repair class names in the YAML the library reads at
	 * runtime. Letting it loose on every data file in the vendor tree does real
	 * damage, and did: it normalises by stripping the prefix and re-applying it
	 * to a known list of namespaces, so running over Composer's installed.json
	 * removed the prefix PHP-Scoper had correctly written for `Psr\Log\` --
	 * which is not on that list -- and left the package declaring an autoload
	 * prefix its files no longer use.
	 *
	 * `composer dump-autoload --classmap-authoritative` then found classes named
	 * `Kanopi\BasicFirewall\Vendor\Psr\Log\LoggerInterface` under a prefix
	 * declared as `Psr\Log\`, judged them non-compliant, and silently omitted
	 * them from the classmap. The plugin installed, activated, ran WP-CLI and
	 * served traffic, and fell over only when something first constructed a
	 * logger:
	 *
	 *   Interface "Kanopi\BasicFirewall\Vendor\Psr\Log\LoggerInterface" not found
	 *
	 * PHP-Scoper handles the rest of the tree correctly on its own. This
	 * patcher's business is the presets, and nothing else.
	 */
	$is_library_data = preg_match( '#/kanopi/(firewall|crs-engine)/(presets|config|supplemental)/#', $file_path )
		&& preg_match( '/\.(ya?ml|json)$/i', $file_path );

	if ( ! $is_library_data ) {
		return $contents;
	}

	$namespaces = array(
		'Kanopi\\Firewall',
		'Kanopi\\Crs',
		'Monolog',
		'Doctrine',
		'Symfony\\Component',
	);

	/*
	 * This patcher NORMALISES rather than prefixes, and that is the whole point.
	 *
	 * PHP-Scoper does not leave data files alone. It finds class-name-shaped
	 * strings in YAML and prefixes them itself -- and it gets the escaping
	 * wrong. Given a double-quoted YAML scalar, which escapes the namespace
	 * separator, it emits the prefix with SINGLE backslashes into a string
	 * using double ones:
	 *
	 *     "\\Kanopi\BasicFirewall\Vendor\\Monolog\\Handler\\StreamHandler"
	 *      ^^ double          ^ single   ^^ double
	 *
	 * A YAML parser reading that sees `\B` and `\V` as invalid escapes, so the
	 * class name it produces is not the class name anything registered. And a
	 * patcher written on the assumption that it receives untouched input then
	 * adds a second, correctly spelled prefix on top of the broken one.
	 *
	 * So: strip every prefix occurrence in any spelling first, then apply
	 * exactly one, spelled to match the separator style at each site. That is
	 * correct whatever PHP-Scoper did beforehand, and idempotent by
	 * construction -- which the test at build/patcher-test.php pins.
	 */
	$prefix_pattern = implode(
		'\\\\{1,2}',
		array_map(
			static fn ( string $part ): string => preg_quote( $part, '/' ),
			explode( '\\', $prefix )
		)
	) . '\\\\{1,2}';

	/*
	 * The separator run is matched as {1,2} and removed WITH the prefix, not
	 * left behind.
	 *
	 * PHP-Scoper inserts its prefix after the opening escape of a scalar, so
	 * `"\\Monolog\\..."` becomes `"\\Kanopi\BasicFirewall\Vendor\\Monolog\\..."`.
	 * Stripping a fixed-length lead there leaves one orphan backslash and the
	 * scalar ends up with three in a row, which escapes to something that is
	 * again not the class name. Consuming the whole run is what avoids that.
	 */
	$contents = (string) preg_replace( '/' . $prefix_pattern . '/', '', $contents );

	foreach ( $namespaces as $namespace ) {
		$parts = array_map(
			static fn ( string $part ): string => preg_quote( $part, '/' ),
			explode( '\\', $namespace )
		);

		$head = array_shift( $parts );
		$body = array() !== $parts
			? $head . '(\\\\{1,2})' . implode( '\\1', $parts ) . '\\1'
			: $head . '(\\\\{1,2})';

		$contents = (string) preg_replace_callback(
			'/' . $body . '/',
			static function ( array $match ) use ( $prefix ): string {
				// The separator style found here is the style used to write the
				// prefix, so the result is consistent within the scalar.
				$separator = $match[1];

				return str_replace( '\\', $separator, $prefix ) . $separator . $match[0];
			},
			$contents
		);
	}

	return $contents;
}

return array(
	'prefix'                  => 'Kanopi\\BasicFirewall\\Vendor',

	'finders'                 => array(
		Finder::create()
			->files()
			->ignoreVCS( true )
			->notName( '/LICENSE|.*\.md|Makefile/' )
			->exclude(
				array(
					'doc',
					'test',
					'tests',
					'Tests',
					'vendor-bin',
					'example',
					'examples',
					'.github',
					'.circleci',
				)
			)
			->in( 'vendor' ),

		/*
		 * The plugin's own source has to go through the scoper too.
		 *
		 * Not to rename it -- `Kanopi\BasicFirewall` is excluded below and stays
		 * exactly where it is -- but to rewrite the REFERENCES it makes. src/ is
		 * written against the unprefixed library (`use Symfony\Component\Yaml\Yaml`),
		 * which is what keeps it readable and lets the unscoped Composer install
		 * work unchanged. In a scoped build those names no longer exist, so the
		 * `use` statements and `::class` constants have to be rewritten to match.
		 *
		 * Leaving src/ out of the finder produced a zip that installed, activated,
		 * and then fatally failed on the first compile with
		 *
		 *   Class "Symfony\Component\Yaml\Yaml" not found
		 *
		 * because every vendored class had moved and nothing had told the plugin.
		 */
		Finder::create()
			->files()
			->ignoreVCS( true )
			->name( '*.php' )
			->in( 'src' ),

		/*
		 * ONLY composer.json. The plugin's four root PHP files are deliberately
		 * NOT scoped.
		 *
		 * None of them references a vendored class: basic-firewall.php is
		 * PHP-5.2-compatible by design, loader.php and uninstall.php use only
		 * WordPress, and bootstrap.php reaches the library through string class
		 * names that it already resolves under both the scoped and the unscoped
		 * spelling.
		 *
		 * Scoping them actively breaks the plugin, because PHP-Scoper moves a
		 * global function declaration into the prefixed namespace. bootstrap.php
		 * declares basic_firewall_evaluate(), which is the function every site's
		 * wp-config.php calls by name -- so a scoped build produced
		 *
		 *   Fatal error: Call to undefined function basic_firewall_evaluate()
		 *
		 * on every request of every site using the early evaluation path. The
		 * zip installed and activated cleanly first, which is what made it worth
		 * writing down.
		 */
		Finder::create()->append( array( 'composer.json' ) ),
	),

	/*
	 * The plugin's own namespace is NOT prefixed. Scoping our own code would
	 * change the class names WordPress and this plugin's own stored options
	 * refer to. Its `use` statements are still rewritten, which is what lets
	 * src/ be written against the unprefixed library and still work in a scoped
	 * build.
	 */
	'exclude-namespaces'      => array(
		'Kanopi\\BasicFirewall',

		/*
		 * WP-CLI is not vendored. It is provided by the `wp` binary at runtime,
		 * so prefixing references to it points them at classes and functions
		 * that exist nowhere:
		 *
		 *   Call to undefined function Kanopi\BasicFirewall\Vendor\WP_CLI\Utils\format_items()
		 *
		 * on the first `wp basic-firewall` command, in a build that installed
		 * and activated perfectly.
		 */
		'WP_CLI',
	),

	/*
	 * NOTHING is aliased back into the global namespace.
	 *
	 * This is the setting that matters most in this file, and its default is
	 * wrong for this plugin.
	 *
	 * PHP-Scoper defaults to exposing global-namespace classes: it renames
	 * `class Spyc` to `Kanopi\BasicFirewall\Vendor\Spyc` and then appends
	 * `class_alias(..., 'Spyc')` so old code still finds it. That alias
	 * reintroduces exactly the collision scoping exists to prevent -- and it did:
	 * WP-CLI bundles mustangostang/spyc too, so every `wp` command against a
	 * scoped build emitted
	 *
	 *   Cannot redeclare class Spyc
	 *
	 * Spyc arrives here as a transitive dependency of matomo/device-detector,
	 * which nothing in this plugin calls directly, so the alias bought nothing
	 * and cost the one guarantee the build is for.
	 */
	/*
	 * Every constant this plugin or WordPress names as a STRING.
	 *
	 * PHP-Scoper rewrites the argument of defined() and constant() as if it were
	 * a constant it owned, so `defined( 'WP_CLI' )` became
	 * `defined( 'Kanopi\\BasicFirewall\\Vendor\\WP_CLI' )` -- which is never
	 * true. The WP-CLI commands silently stopped registering in a build that
	 * installed, activated and served traffic correctly; `wp basic-firewall
	 * status` simply reported "not a registered wp command".
	 *
	 * These are WordPress's constants, the host's, the library's, and this
	 * plugin's own wp-config.php contract. None of them is ours to rename.
	 */
	'exclude-constants'       => array(
		// WordPress and the host.
		'ABSPATH',
		'WP_CONTENT_DIR',
		'WP_PLUGIN_DIR',
		'WPMU_PLUGIN_DIR',
		'WP_CACHE',
		'WP_CLI',
		'DB_NAME',
		'DB_USER',
		'DB_PASSWORD',
		'DB_HOST',
		'DB_CHARSET',
		'MINUTE_IN_SECONDS',
		// The library's.
		'KANOPI_FIREWALL_CACHE_DIR',
		'KANOPI_FIREWALL_CACHE_MAX_AGE',
		'KANOPI_FIREWALL_SOURCES_OFFLINE',
		// This plugin's wp-config.php contract, which sites write by hand.
		'BASIC_FIREWALL_VERSION',
		'BASIC_FIREWALL_MIN_PHP',
		'BASIC_FIREWALL_FILE',
		'BASIC_FIREWALL_DIR',
		'BASIC_FIREWALL_URL',
		'BASIC_FIREWALL_LOADED',
		'BASIC_FIREWALL_EVALUATED',
		'BASIC_FIREWALL_ENABLED',
		'BASIC_FIREWALL_MODE',
		'BASIC_FIREWALL_MU_LOADER',
		'BASIC_FIREWALL_CHALLENGE_SECRET',
		'BASIC_FIREWALL_TRUSTED_PROXIES',
		'BASIC_FIREWALL_TRUSTED_HEADERS',
		'BASIC_FIREWALL_SECRET_DIRECTORIES',
		'BASIC_FIREWALL_SOURCES_OFFLINE',
	),

	'expose-global-classes'   => false,
	'expose-global-functions' => false,
	'expose-global-constants' => false,

	/*
	 * WordPress's own API is global and must stay global.
	 */
	'exclude-functions'       => array(
		'add_action',
		'add_filter',
		'apply_filters',
		'do_action',
		'wp_upload_dir',
		'get_option',
		'update_option',
	),

	'exclude-classes'         => array(
		'WP_CLI',
		'wpdb',
		'WP_Error',
	),

	'patchers'                => array(
		'basic_firewall_scope_data_file',
	),
);
