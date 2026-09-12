<?php
/**
 * Proves a scoped build actually works.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

/*
 * THE BUILD GATE.
 *
 * A scoping miss must break the build, never the firewall.
 *
 * kanopi/firewall resolves class names out of configuration data: it calls
 * class_exists() on a string from the config and instantiates it. When that
 * string names a class that scoping renamed, the library does not throw -- it
 * skips the plugin and carries on. The result is a firewall that reports itself
 * healthy, shows every preset as enabled, and enforces nothing.
 *
 * Two checks, in increasing order of how much they prove.
 *
 * 1. FUNCTIONAL. Load the built autoloader and resolve, for real, the classes
 *    the library will be asked for at runtime -- including the ones named as
 *    strings inside its shipped presets. This is the check that matters: it
 *    asks the same question the library asks, in the same way.
 *
 * 2. TEXTUAL. Scan the library's own configuration data for a class name that
 *    scoping should have rewritten and did not. This catches a preset that is
 *    not currently enabled by anybody, which the functional check would not
 *    exercise.
 *
 * The textual check is deliberately scoped to data the LIBRARY reads. It does
 * not scan every vendored file for every namespace, because that produces a
 * wall of findings that are all noise -- exception messages mentioning a class,
 * docblocks, Composer's own metadata -- and burying the one real finding among
 * forty false ones is how a gate stops being read.
 *
 * Usage:  php build/verify-scope.php <staged-plugin-dir> <prefix>
 */

$plugin_dir = $argv[1] ?? 'build/stage/basic-firewall';
$prefix     = $argv[2] ?? 'Kanopi\\BasicFirewall\\Vendor';

if ( ! is_dir( $plugin_dir ) ) {
	fwrite( STDERR, sprintf( "verify-scope: %s is not a directory.\n", $plugin_dir ) );
	exit( 1 );
}

$failures = array();

/**
 * Record a failure.
 *
 * @param string $message What went wrong.
 *
 * @return void
 */
function bfw_fail( string $message ): void {
	global $failures;

	$failures[] = $message;

	printf( "  FAIL  %s\n", $message );
}

/**
 * Record a pass.
 *
 * @param string $message What was checked.
 *
 * @return void
 */
function bfw_pass( string $message ): void {
	printf( "  ok    %s\n", $message );
}

// ---------------------------------------------------------------------------
// 1. Functional: does the built autoloader resolve what the library will ask for?
// ---------------------------------------------------------------------------

echo "verify-scope: functional checks\n";

$autoload = $plugin_dir . '/vendor/autoload.php';

if ( ! is_readable( $autoload ) ) {
	bfw_fail( sprintf( 'no autoloader at %s', $autoload ) );
} else {
	require_once $autoload;

	$expected = array(
		// Every dependency the library constructs at runtime, not only the ones
		// this plugin names directly. Psr\Log is here because it went missing
		// from the classmap once, and nothing noticed until a logger was built.
		'Psr\\Log\\LoggerInterface',
		'Psr\\Log\\LogLevel',
		'Doctrine\\DBAL\\DriverManager',
		'Kanopi\\Crs\\CrsEngine',
		'Kanopi\\Firewall\\Firewall',
		'Kanopi\\Firewall\\Plugins\\IpAddress',
		'Kanopi\\Firewall\\Plugins\\Url',
		'Kanopi\\Firewall\\Plugins\\UserAgent',
		'Kanopi\\Firewall\\Plugins\\RateLimit',
		'Kanopi\\Firewall\\Storage\\FileStorage',
		'Kanopi\\Firewall\\Storage\\DatabaseStorage',
		'Kanopi\\Firewall\\Logging\\Handler\\DatabaseHandler',
		'Monolog\\Handler\\RotatingFileHandler',
		'Monolog\\Level',
		'Symfony\\Component\\Yaml\\Yaml',
		'Symfony\\Component\\HttpFoundation\\Request',
	);

	foreach ( $expected as $class ) {
		$scoped = $prefix . '\\' . $class;

		if ( class_exists( $scoped ) || interface_exists( $scoped ) || enum_exists( $scoped ) ) {
			bfw_pass( sprintf( 'the scoped %s resolves', $class ) );

			continue;
		}

		bfw_fail( sprintf( 'the scoped %s does NOT resolve -- the autoloader is wrong', $class ) );
	}

	/*
	 * And the unscoped name must NOT resolve. If it does, the vendor tree was
	 * not scoped at all and the build is not collision-safe, however healthy
	 * everything else looks.
	 */
	/*
	 * And the classmap has to be COMPLETE, not merely present.
	 *
	 * `--classmap-authoritative` means a class missing from the map is simply
	 * unloadable, with no PSR-4 fallback. A package whose declared autoload
	 * prefix no longer matches its files is skipped by Composer during the dump,
	 * silently -- which is how Psr\Log vanished from a build that otherwise
	 * worked.
	 */
	$classmap = $plugin_dir . '/vendor/composer/autoload_classmap.php';

	if ( is_readable( $classmap ) ) {
		$map       = require $classmap;
		$unprefixed = 0;

		/*
		 * Three things legitimately appear unprefixed:
		 *
		 * - the plugin's own Kanopi\BasicFirewall\* classes, which are excluded
		 *   from prefixing on purpose (renaming them would change the class names
		 *   WordPress and this plugin's stored options refer to);
		 * - Composer's runtime API, left global so anything else on the site
		 *   asking what is installed still gets a real answer;
		 * - polyfill stubs for platform classes, which must be global to work.
		 */
		$allowed = array(
			'Kanopi\\BasicFirewall\\',
			'Composer\\InstalledVersions',
			'Normalizer',
			'ValueError',
			'Attribute',
			'Stringable',
			'UnhandledMatchError',
		);

		$offenders = array();

		foreach ( array_keys( is_array( $map ) ? $map : array() ) as $mapped ) {
			$mapped = (string) $mapped;

			if ( 0 === strpos( $mapped, $prefix ) ) {
				continue;
			}

			$permitted = false;

			foreach ( $allowed as $allow ) {
				if ( 0 === strpos( $mapped, $allow ) ) {
					$permitted = true;

					break;
				}
			}

			// Our own namespace must not have been prefixed either.
			if ( 0 === strpos( $mapped, 'Kanopi\\BasicFirewall\\Vendor' ) ) {
				$permitted = false;
			}

			if ( ! $permitted ) {
				++$unprefixed;
				$offenders[] = $mapped;
			}
		}

		if ( $unprefixed > 0 ) {
			bfw_fail(
				sprintf(
					'%d classmap entries are not prefixed -- some package was not scoped (%s)',
					$unprefixed,
					implode( ', ', array_slice( $offenders, 0, 5 ) )
				)
			);
		} else {
			bfw_pass( sprintf( 'every one of the %d classmap entries is prefixed', count( (array) $map ) ) );
		}
	}

	if ( class_exists( 'Kanopi\\Firewall\\Firewall' ) ) {
		bfw_fail( 'the UNSCOPED Kanopi\\Firewall\\Firewall resolves -- this build is not scoped' );
	} else {
		bfw_pass( 'the unscoped Kanopi\\Firewall\\Firewall does not resolve' );
	}
}

// ---------------------------------------------------------------------------
// 2. Textual: does the library's own configuration data still name old classes?
// ---------------------------------------------------------------------------

echo "verify-scope: the library's configuration data\n";

$data_dirs = array(
	$plugin_dir . '/vendor/kanopi/firewall/presets',
	$plugin_dir . '/vendor/kanopi/firewall/config',
);

$forbidden = array( 'Kanopi\\Firewall\\', 'Kanopi\\Crs\\', 'Monolog\\', 'Doctrine\\' );

$leads = array(
	$prefix . '\\',
	str_replace( '\\', '\\\\', $prefix ) . '\\\\',
);

$scanned = 0;

foreach ( $data_dirs as $dir ) {
	if ( ! is_dir( $dir ) ) {
		continue;
	}

	foreach ( (array) glob( $dir . '/*.{yml,yaml,json}', GLOB_BRACE ) as $file ) {
		$contents = (string) file_get_contents( (string) $file );
		++$scanned;

		foreach ( $forbidden as $namespace ) {
			foreach ( array( $namespace, str_replace( '\\', '\\\\', $namespace ) ) as $needle ) {
				$offset = 0;

				while ( false !== ( $at = strpos( $contents, $needle, $offset ) ) ) {
					$offset = $at + 1;

					/*
					 * Both prefix spellings are accepted for every match. They
					 * are not disjoint: the bare needle `Monolog\` matches
					 * inside the escaped `Monolog\\`, and what precedes it is
					 * then the ESCAPED prefix. Checking only the matching
					 * spelling reports every correctly scoped escaped reference
					 * as a failure.
					 */
					$prefixed = false;

					foreach ( $leads as $lead ) {
						if ( $at >= strlen( $lead )
							&& substr( $contents, $at - strlen( $lead ), strlen( $lead ) ) === $lead ) {
							$prefixed = true;

							break;
						}
					}

					if ( $prefixed ) {
						continue;
					}

					bfw_fail(
						sprintf(
							'%s line %d names the unscoped %s',
							basename( (string) $file ),
							substr_count( substr( $contents, 0, $at ), "\n" ) + 1,
							rtrim( $namespace, '\\' )
						)
					);

					break 3;
				}
			}
		}
	}
}

printf( "  (scanned %d configuration files)\n", $scanned );

if ( 0 === $scanned ) {
	bfw_fail( 'no library configuration files were found to scan -- is the vendor tree complete?' );
}

// ---------------------------------------------------------------------------
// 2a. Constants named as strings must not have been renamed.
// ---------------------------------------------------------------------------

echo "verify-scope: constant references\n";

/*
 * PHP-Scoper rewrites the argument of defined() and constant(), so
 * `defined( 'WP_CLI' )` becomes `defined( '<prefix>\WP_CLI' )` -- never true.
 * The WP-CLI commands stopped registering in a build that installed, activated
 * and served traffic correctly, and the only symptom was `wp basic-firewall`
 * reporting "not a registered wp command".
 */
$constant_users = array(
	'src/Plugin.php'                  => 'WP_CLI',
	'src/Database_Credentials.php'    => 'DB_NAME',
	'src/Runtime/Runner.php'          => 'BASIC_FIREWALL_EVALUATED',
	'src/Health/Site_Health.php'      => 'WP_CACHE',
);

foreach ( $constant_users as $file => $constant ) {
	$path = $plugin_dir . '/' . $file;

	if ( ! is_readable( $path ) ) {
		continue;
	}

	$contents = (string) file_get_contents( $path );

	if ( preg_match( '/(defined|constant)\\(\\s*.' . preg_quote( $prefix, '/' ) . '/', $contents ) ) {
		bfw_fail( sprintf( '%s has had a constant name prefixed', $file ) );

		continue;
	}

	if ( false === strpos( $contents, "'" . $constant . "'" ) ) {
		bfw_fail( sprintf( '%s no longer references %s by its real name', $file, $constant ) );

		continue;
	}

	bfw_pass( sprintf( '%s still names %s correctly', $file, $constant ) );
}

// ---------------------------------------------------------------------------
// 2a-ii. The scoping DETECTOR must not itself have been scoped.
// ---------------------------------------------------------------------------

echo "verify-scope: the scoping detector\n";

/*
 * Library_Loader decides whether this build is collision-safe by asking whether
 * the UNPREFIXED library class exists. If the literal it asks with has itself
 * been prefixed, the answer inverts: a correctly scoped release reported
 * "bundled-unscoped / Collision safe: no". The names are therefore assembled
 * from fragments, and this is the check that they stayed that way.
 */
$loader_path = $plugin_dir . '/src/Library_Loader.php';

if ( ! is_readable( $loader_path ) ) {
	bfw_fail( 'src/Library_Loader.php is missing from the build' );
} else {
	$loader = (string) file_get_contents( $loader_path );

	if ( preg_match( '/[\'"]' . preg_quote( $prefix, '/' ) . '/', $loader ) ) {
		bfw_fail( 'Library_Loader contains a prefixed class-name literal -- its scoping detection is inverted' );
	} else {
		bfw_pass( 'Library_Loader still asks about the unprefixed class name' );
	}
}

// ---------------------------------------------------------------------------
// 2b. Nothing may be aliased back into the global namespace.
// ---------------------------------------------------------------------------

echo "verify-scope: global-namespace leakage\n";

/*
 * PHP-Scoper's default is to alias every global-namespace class back to its
 * original name, which reintroduces exactly the collision scoping is for.
 * Measured: WP-CLI bundles mustangostang/spyc, and a scoped build that aliased
 * `Spyc` back emitted "Cannot redeclare class Spyc" on every wp command.
 */
$aliases = 0;

$iterator = new RecursiveIteratorIterator(
	new RecursiveDirectoryIterator( $plugin_dir . '/vendor', FilesystemIterator::SKIP_DOTS )
);

foreach ( $iterator as $file ) {
	if ( ! $file->isFile() || 'php' !== strtolower( $file->getExtension() ) ) {
		continue;
	}

	$relative = str_replace( $plugin_dir . '/', '', $file->getPathname() );

	/*
	 * Polyfills are the legitimate exception, and the only one.
	 *
	 * symfony/polyfill-* exists to PROVIDE a global class that PHP or an
	 * extension would otherwise supply -- Normalizer from intl, ValueError from
	 * PHP 8. Those have to be global to do their job, they are guarded by a
	 * class_exists() check so they never redeclare, and they are not classes
	 * this plugin or its library owns. Flagging them would mean either a build
	 * that cannot pass or a check nobody trusts.
	 */
	if ( false !== strpos( $relative, 'symfony/polyfill-' ) ) {
		continue;
	}

	$contents = (string) file_get_contents( $file->getPathname() );

	// An alias back to a bare, unnamespaced name is the dangerous shape.
	if ( preg_match( "/class_alias\\([^,]+,\\s*'[A-Za-z_][A-Za-z0-9_]*'/", $contents ) ) {
		++$aliases;

		if ( $aliases <= 5 ) {
			bfw_fail( sprintf( '%s aliases a scoped class back into the global namespace', $relative ) );
		}
	}
}

if ( 0 === $aliases ) {
	bfw_pass( 'no scoped class is aliased back into the global namespace' );
} elseif ( $aliases > 5 ) {
	bfw_fail( sprintf( '... and %d more files alias classes globally', $aliases - 5 ) );
}

// ---------------------------------------------------------------------------
// 3. The verbatim files must stay verbatim.
// ---------------------------------------------------------------------------

echo "verify-scope: the unscoped entry points\n";

/*
 * bootstrap.php declares basic_firewall_evaluate(), which is the function every
 * site's wp-config.php calls by name. PHP-Scoper moves a global function
 * declaration into the prefixed namespace, so a build that scoped this file
 * produces
 *
 *   Fatal error: Call to undefined function basic_firewall_evaluate()
 *
 * on every request of every site using the early evaluation path -- after
 * installing and activating perfectly cleanly. Checked here because nothing
 * else would notice until a site did.
 */
$verbatim = array(
	'bootstrap.php'      => array( 'basic_firewall_evaluate', 'basic_firewall_compiled_path', 'basic_firewall_build_overrides', 'basic_firewall_set_trusted_proxies', 'basic_firewall_enable_file_secrets', 'basic_firewall_define_cache_constants' ),
	'basic-firewall.php' => array( 'basic_firewall_activate', 'basic_firewall_deactivate' ),
);

foreach ( $verbatim as $file => $functions ) {
	$path = $plugin_dir . '/' . $file;

	if ( ! is_readable( $path ) ) {
		bfw_fail( sprintf( '%s is missing from the build', $file ) );

		continue;
	}

	$contents = (string) file_get_contents( $path );

	if ( preg_match( '/^namespace\s+/m', $contents ) ) {
		bfw_fail( sprintf( '%s was given a namespace -- its global functions are no longer global', $file ) );

		continue;
	}

	foreach ( $functions as $function ) {
		if ( false === strpos( $contents, 'function ' . $function . '(' ) ) {
			bfw_fail( sprintf( '%s no longer declares %s()', $file, $function ) );

			continue;
		}

		bfw_pass( sprintf( '%s() is still declared globally', $function ) );
	}
}

if ( array() === $failures ) {
	echo "\nverify-scope: OK\n";
	exit( 0 );
}

fwrite( STDERR, sprintf( "\nverify-scope: FAILED with %d problem(s).\n\n", count( $failures ) ) );
fwrite(
	STDERR,
	"An unscoped class name in a scoped build does not throw. The library calls\n"
	. "class_exists() on it, gets false, skips the plugin and carries on -- so the\n"
	. "firewall would come up reporting success and enforcing nothing.\n\n"
	. "Fix the patcher in scoper.inc.php rather than relaxing this check.\n"
);

exit( 1 );
