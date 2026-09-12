<?php
/**
 * Evaluates a request before WordPress loads.
 *
 * @package Kanopi\BasicFirewall
 */

/*
 * THE EARLY PATH.
 *
 * Required from wp-config.php, before wp-settings.php. At that moment there is
 * no WordPress: no options, no $wpdb, no hooks, no autoloader, no plugins. So
 * this file contains no WordPress API calls at all, and it must stay that way
 * -- adding one turns a firewall into a fatal error on every request.
 *
 * Why it exists, given the plugin already runs from an mu-plugin:
 *
 *     host edge cache (Varnish/CDN)  <- no PHP runs. Unreachable from here.
 *       wp-config.php                <- THIS FILE
 *         advanced-cache.php         <- Batcache, W3TC, WP Super Cache:
 *                                       serves the cached page and exits
 *           mu-plugins               <- the normal path. Never reached above.
 *             plugins
 *
 * A page cache serves from `advanced-cache.php` and calls exit() without ever
 * loading an mu-plugin. So on exactly the busy, cached site that most needs a
 * firewall, the normal path does not run. This one does.
 *
 * WHAT IT CANNOT DO, and this is carried over from the Drupal module unchanged
 * because hiding it would be worse than the limitation:
 *
 *   **Database-backed block storage must not be used here.** There is no CMS to
 *   read credentials from, so the connection cannot be built, and a site
 *   combining the two fails open on every request while the admin screens go on
 *   reporting the firewall as enabled and blocking. Use file storage on this
 *   path, or supply a connection explicitly in the options below.
 *
 * Usage -- the Site Health screen prints this with your site's real path
 * filled in, because the private directory carries a random per-site suffix:
 *
 *     require_once ABSPATH . 'wp-content/plugins/basic-firewall/bootstrap.php';
 *     basic_firewall_evaluate( array(
 *         'private_path' => '/absolute/path/to/basic-firewall-private-abc123',
 *     ) );
 */

if ( ! function_exists( 'basic_firewall_evaluate' ) ) {

	/**
	 * Evaluate the current request against the compiled configuration.
	 *
	 * Never throws and never fatals. Every failure allows the request through:
	 * a firewall that cannot start must not be the reason a site is down.
	 *
	 * @param array<string, mixed> $options Bootstrap options. See basic_firewall_options().
	 *
	 * @return bool True when the request may continue.
	 */
	function basic_firewall_evaluate( array $options = array() ) {
		$options = basic_firewall_options( $options );

		if ( ! $options['enabled'] ) {
			return true;
		}

		$compiled = basic_firewall_compiled_path( $options );

		if ( null === $compiled ) {
			return true;
		}

		$autoload = basic_firewall_autoloader( $options );

		if ( null === $autoload ) {
			return true;
		}

		require_once $autoload;

		if ( ! class_exists( 'Kanopi\\Firewall\\Firewall' )
			&& ! class_exists( 'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Firewall' ) ) {
			return true;
		}

		basic_firewall_define_cache_constants( $options );
		basic_firewall_enable_file_secrets( $options );
		basic_firewall_set_trusted_proxies( $options );

		/*
		 * Marks the request as dealt with, so the mu-plugin does not evaluate it
		 * a second time when WordPress finally loads.
		 */
		if ( ! defined( 'BASIC_FIREWALL_EVALUATED' ) ) {
			define( 'BASIC_FIREWALL_EVALUATED', true );
		}

		$class = class_exists( 'Kanopi\\Firewall\\Firewall' )
			? 'Kanopi\\Firewall\\Firewall'
			: 'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Firewall';

		try {
			$firewall = call_user_func(
				array( $class, 'create' ),
				array( $compiled ),
				basic_firewall_build_overrides( $options )
			);

			return $firewall->evaluate();
		} catch ( \Throwable $e ) {
			/*
			 * Includes the blocking exception in `exception` mode. On this path
			 * there is no responder to hand it to -- the plugin's own is not
			 * loadable without its autoloader having been registered, and the
			 * library exits by itself in every other mode -- so anything
			 * reaching here allows the request. Fail open.
			 */
			return true;
		}
	}

	/**
	 * Fill in the bootstrap options.
	 *
	 * @param array<string, mixed> $options Caller-supplied options.
	 *
	 * @return array<string, mixed>
	 */
	function basic_firewall_options( array $options = array() ) {
		$defaults = array(
			// Absolute path to the private directory. The Site Health screen
			// prints the right value; discovered by glob when absent.
			'private_path'       => null,
			// Absolute path to the plugin directory.
			'plugin_path'        => __DIR__,
			// Whether to run at all.
			'enabled'            => ! ( defined( 'BASIC_FIREWALL_ENABLED' ) && false === BASIC_FIREWALL_ENABLED ),
			// Addresses permitted to declare the client address.
			'trusted_proxies'    => defined( 'BASIC_FIREWALL_TRUSTED_PROXIES' ) ? BASIC_FIREWALL_TRUSTED_PROXIES : array(),
			// Directories a %file() token may read a secret from.
			'secret_directories' => defined( 'BASIC_FIREWALL_SECRET_DIRECTORIES' ) ? BASIC_FIREWALL_SECRET_DIRECTORIES : array(),
			// Runtime overrides, as Symfony property-access paths.
			'overrides'          => array(),
		);

		return array_merge( $defaults, $options );
	}

	/**
	 * Locate the compiled configuration file.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return string|null Absolute path, or null when there is not one.
	 */
	function basic_firewall_compiled_path( array $options ) {
		$private = basic_firewall_private_path( $options );

		if ( null === $private ) {
			return null;
		}

		$compiled = $private . '/firewall.yml';

		/*
		 * On this path the plugin cannot rebuild a missing compiled file -- that
		 * needs settings, which need WordPress. So a missing file means skip
		 * evaluation rather than try to recover.
		 */
		return is_readable( $compiled ) ? $compiled : null;
	}

	/**
	 * Locate the private directory.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return string|null
	 */
	function basic_firewall_private_path( array $options ) {
		if ( ! empty( $options['private_path'] ) && is_dir( $options['private_path'] ) ) {
			return rtrim( $options['private_path'], '/\\' );
		}

		/*
		 * Discovery fallback. The directory carries a random per-site suffix, so
		 * it cannot be named literally here -- and the suffix lives in an option
		 * this path cannot read. One glob is cheap; passing `private_path`
		 * explicitly avoids even that, which is why Site Health prints it.
		 */
		$roots = array();

		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$roots[] = WP_CONTENT_DIR . '/uploads';
			$roots[] = WP_CONTENT_DIR;
		}

		if ( defined( 'ABSPATH' ) ) {
			$roots[] = ABSPATH . 'wp-content/uploads';
			$roots[] = ABSPATH . 'wp-content';
		}

		foreach ( $roots as $root ) {
			$found = glob( $root . '/basic-firewall-private-*', GLOB_ONLYDIR );

			if ( ! empty( $found ) ) {
				return rtrim( $found[0], '/\\' );
			}
		}

		return null;
	}

	/**
	 * Locate the Composer autoloader.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return string|null
	 */
	function basic_firewall_autoloader( array $options ) {
		$candidates = array(
			// The release zip, and a plugin-local composer install.
			$options['plugin_path'] . '/vendor/autoload.php',
		);

		// A site-level Composer install, where the plugin is a dependency.
		if ( defined( 'ABSPATH' ) ) {
			$candidates[] = dirname( ABSPATH, 1 ) . '/vendor/autoload.php';
			$candidates[] = ABSPATH . '../vendor/autoload.php';
		}

		foreach ( $candidates as $candidate ) {
			if ( is_readable( $candidate ) ) {
				return $candidate;
			}
		}

		return null;
	}

	/**
	 * Build the runtime overrides.
	 *
	 * Note what is *not* here: WordPress's database credentials. On the normal
	 * path the runner injects them per request, which is what makes a rotated
	 * password take effect immediately. Here there is no WordPress to read them
	 * from, which is precisely why database-backed storage cannot be used on
	 * this path. A site that needs it must pass a connection in `overrides`.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return array<string, mixed>
	 */
	function basic_firewall_build_overrides( array $options ) {
		$options = basic_firewall_options( $options );

		$overrides = is_array( $options['overrides'] ) ? $options['overrides'] : array();

		if ( defined( 'BASIC_FIREWALL_MODE' ) && is_string( BASIC_FIREWALL_MODE ) ) {
			$overrides['[global][mode]'] = BASIC_FIREWALL_MODE;
		}

		return $overrides;
	}

	/**
	 * Establish which proxies may declare the client address.
	 *
	 * Without this every rule that looks at an address is either useless (every
	 * visitor shares the proxy's address) or forgeable (anything may claim to be
	 * anyone). There is no safe default between those, so nothing happens unless
	 * the site says what to trust.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return void
	 */
	function basic_firewall_set_trusted_proxies( array $options ) {
		$options = basic_firewall_options( $options );
		$proxies = $options['trusted_proxies'];

		if ( is_string( $proxies ) ) {
			$proxies = explode( ',', $proxies );
		}

		if ( ! is_array( $proxies ) || array() === $proxies ) {
			return;
		}

		$clean = array();

		foreach ( $proxies as $proxy ) {
			$proxy = is_string( $proxy ) ? trim( $proxy ) : '';

			if ( '' !== $proxy ) {
				$clean[] = $proxy;
			}
		}

		if ( array() === $clean ) {
			return;
		}

		foreach ( array( 'Symfony\\Component\\HttpFoundation\\Request', 'Kanopi\\BasicFirewall\\Vendor\\Symfony\\Component\\HttpFoundation\\Request' ) as $request_class ) {
			if ( ! class_exists( $request_class ) ) {
				continue;
			}

			/*
			 * Deliberately not HEADER_X_FORWARDED_HOST: a forwarded host decides
			 * which URLs get generated, and trusting it is how cache poisoning
			 * and forged password-reset links start.
			 */
			$headers = constant( $request_class . '::HEADER_X_FORWARDED_FOR' )
				| constant( $request_class . '::HEADER_X_FORWARDED_PROTO' )
				| constant( $request_class . '::HEADER_X_FORWARDED_PORT' );

			if ( defined( 'BASIC_FIREWALL_TRUSTED_HEADERS' ) && is_int( BASIC_FIREWALL_TRUSTED_HEADERS ) ) {
				$headers = BASIC_FIREWALL_TRUSTED_HEADERS;
			}

			call_user_func( array( $request_class, 'setTrustedProxies' ), $clean, $headers );

			return;
		}
	}

	/**
	 * Point the library's parse cache somewhere writable and persistent.
	 *
	 * The single biggest performance factor: 0.08 ms to read the compiled
	 * configuration from the parse cache, against 42 ms to parse the YAML. Left
	 * alone the library falls back to the system temporary directory, which gets
	 * cleared -- and every clear costs that 42 ms again on every worker.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return void
	 */
	function basic_firewall_define_cache_constants( array $options ) {
		$options = basic_firewall_options( $options );

		if ( ! defined( 'KANOPI_FIREWALL_CACHE_DIR' ) ) {
			$private = basic_firewall_private_path( $options );

			if ( null !== $private ) {
				define( 'KANOPI_FIREWALL_CACHE_DIR', $private . '/cache' );
			}
		}

		if ( ! defined( 'KANOPI_FIREWALL_SOURCES_OFFLINE' ) ) {
			/*
			 * Only an explicit false opts out. Anything else, the constant being
			 * absent included, keeps network access off the request path: a
			 * firewall that makes an outbound call while a visitor waits is a
			 * firewall that fails when the network does.
			 */
			$offline = ! ( defined( 'BASIC_FIREWALL_SOURCES_OFFLINE' ) && false === BASIC_FIREWALL_SOURCES_OFFLINE );

			define( 'KANOPI_FIREWALL_SOURCES_OFFLINE', $offline );
		}
	}

	/**
	 * Permit configuration values to be read from files on disk.
	 *
	 * The library can read a secret out of a file -- `%file(/etc/firewall/key)%`
	 * -- but the processor behind it is off until an application enables it and
	 * names the directories it may read from.
	 *
	 * Scope it as narrowly as the secrets allow. Library configuration does not
	 * only come from this plugin's own screens: the Advanced screen takes YAML
	 * directly, and another plugin can contribute a preset. The allowlist is
	 * what bounds the damage if any of those is compromised. An empty list
	 * disables the prefix check entirely inside the library, which is why an
	 * empty or malformed setting is treated here as not having opted in at all
	 * rather than being passed through.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return void
	 */
	function basic_firewall_enable_file_secrets( array $options ) {
		$options = basic_firewall_options( $options );

		$directories = $options['secret_directories'];

		if ( ! is_array( $directories ) ) {
			return;
		}

		$clean = array();

		foreach ( $directories as $directory ) {
			// Non-string and empty entries are dropped rather than forwarded:
			// one bad element must not be why an allowlist becomes permissive.
			$directory = is_string( $directory ) ? trim( $directory ) : '';

			if ( '' !== $directory ) {
				$clean[] = $directory;
			}
		}

		if ( array() === $clean ) {
			return;
		}

		/*
		 * Assembled rather than written out, so that neither PHP-Scoper nor a
		 * static analyser resolves it to one particular class: on a scoped build
		 * only the second name exists, on an unscoped one only the first.
		 */
		$token_class = implode( '\\', array( 'Kanopi', 'Firewall', 'Utility', 'TokenSubstitute' ) );
		$vendor      = implode( '\\', array( 'Kanopi', 'BasicFirewall', 'Vendor' ) );

		foreach ( array( $token_class, $vendor . '\\' . $token_class ) as $class ) {
			if ( ! class_exists( $class ) || ! method_exists( $class, 'enableUnsafeProcessors' ) ) {
				continue;
			}

			try {
				/*
				 * `file` only, never `require`.
				 *
				 * The library offers both behind the same switch. `file` reads a
				 * path and returns its contents; `require` *executes* it. A
				 * configuration value that can name a path to execute turns any
				 * environment-variable injection into remote code execution, and
				 * this plugin has no feature that needs it -- so it is never
				 * enabled, whatever a site asks for.
				 *
				 * The base directories throw if they do not resolve, which is
				 * why this is wrapped: a typo in the allowlist must not be the
				 * reason the firewall does not start.
				 */
				call_user_func( array( $class, 'enableUnsafeProcessors' ), array( 'file' ), $clean );
			} catch ( \Throwable $e ) {
				// An allowlist that does not resolve is treated as not having
				// opted in, rather than as permission for everything.
				return;
			}

			return;
		}
	}
}
