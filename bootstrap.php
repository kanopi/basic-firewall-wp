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
 * WHAT IT CAN AND CANNOT DO.
 *
 * The Drupal module documents database-backed block storage as unusable on this
 * path, because there is no CMS to read credentials from. That is true of
 * Drupal and not of WordPress: `wp-config.php` defines DB_NAME, DB_USER,
 * DB_PASSWORD and DB_HOST as plain constants above the line this file is
 * required from, so they are already in scope here. Database storage therefore
 * works -- see basic_firewall_build_overrides() for how, and for the sidecar
 * that supplies the injection paths without needing an option.
 *
 * Placement is the condition, and it is the one thing to get right: required
 * *below* the DB_ constants and immediately above wp-settings.php. Required
 * above them, the constants do not exist yet, no connection is built, and a
 * site using database storage fails open on every request through this path
 * while the admin screens go on reporting the firewall as blocking. Site Health
 * checks for exactly that and says so.
 *
 * What genuinely is not available here is the rest of WordPress: no options, no
 * hooks, no $wpdb, no translations. The table names the library writes to are
 * baked into the compiled file with the site's prefix already applied, which is
 * why storage needs nothing from $wpdb at this point.
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
		/*
		 * The bootstrap's report on itself, written before anything can
		 * short-circuit. Everything here is a fact only this line is in a
		 * position to establish, because by the time WordPress loads and
		 * something asks, the evidence is gone:
		 *
		 * `called` -- that wp-config.php actually *calls* this function, not
		 * merely that it required the file. Nothing downstream can tell those
		 * apart: `function_exists()` is true either way, and the constant that
		 * used to stand in for this is also set by the mu-plugin runner, so a
		 * snippet pasted without its second half reported a healthy early path
		 * that was never running.
		 *
		 * `credentials` -- whether the DB_ constants existed at this moment,
		 * which is the question of where in wp-config.php the snippet sits.
		 * They are always defined by the time Site Health asks.
		 *
		 * `evaluated` and `reason` are filled in below, once it is known
		 * whether this request was actually evaluated here or handed onward.
		 */
		$GLOBALS['basic_firewall_early'] = array(
			'called'      => true,
			'credentials' => defined( 'DB_NAME' ) && defined( 'DB_USER' ) && defined( 'DB_HOST' ),
			'evaluated'   => false,
			'reason'      => null,
		);

		$options = basic_firewall_options( $options );

		if ( ! $options['enabled'] ) {
			$GLOBALS['basic_firewall_early']['reason'] = 'disabled';

			return true;
		}

		$compiled = basic_firewall_compiled_path( $options );

		if ( null === $compiled ) {
			$GLOBALS['basic_firewall_early']['reason'] = 'no-compiled-file';

			return true;
		}

		$autoload = basic_firewall_autoloader( $options );

		if ( null === $autoload ) {
			$GLOBALS['basic_firewall_early']['reason'] = 'no-autoloader';

			return true;
		}

		require_once $autoload;

		if ( ! class_exists( 'Kanopi\\Firewall\\Firewall' )
			&& ! class_exists( 'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Firewall' ) ) {
			$GLOBALS['basic_firewall_early']['reason'] = 'library-missing';

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

		$GLOBALS['basic_firewall_early']['evaluated'] = true;

		$class = class_exists( 'Kanopi\\Firewall\\Firewall' )
			? 'Kanopi\\Firewall\\Firewall'
			: 'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Firewall';

		try {
			$firewall = call_user_func(
				array( $class, 'create' ),
				array( $compiled ),
				basic_firewall_build_overrides( $options )
			);

			/*
			 * The request is built here rather than left to the library, so the
			 * marks can be read back off it.
			 *
			 * A `mark` response flags a request without refusing it -- the
			 * honeypot case. The library records that as an attribute on the
			 * Symfony Request, which WordPress knows nothing about, and on this
			 * path WordPress does not exist yet so there is no hook to fire.
			 * Stashing it in a global lets the plugin announce it later, once
			 * there is something listening. Without this, a mark applied on the
			 * early path is invisible to the entire site.
			 */
			$request_class = class_exists( 'Symfony\\Component\\HttpFoundation\\Request' )
				? 'Symfony\\Component\\HttpFoundation\\Request'
				: 'Kanopi\\BasicFirewall\\Vendor\\Symfony\\Component\\HttpFoundation\\Request';

			$request = call_user_func( array( $request_class, 'createFromGlobals' ) );

			$allowed = $firewall->evaluate( $request );

			$marks = $request->attributes->get( 'firewall.marks' );

			if ( is_array( $marks ) && array() !== $marks ) {
				$GLOBALS['basic_firewall_marks'] = array_values( array_map( 'strval', $marks ) );
			}

			return $allowed;
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
	 * Including WordPress's database credentials, which is what lets database
	 * block storage work on this path.
	 *
	 * The Drupal module documents this as a fail-open, and it is one there:
	 * `settings.php` puts `$databases` behind enough machinery that reading it
	 * without bootstrapping Drupal is not something a config file can promise.
	 * WordPress is not shaped that way. `wp-config.php` defines `DB_NAME`,
	 * `DB_USER`, `DB_PASSWORD` and `DB_HOST` as plain constants near the top of
	 * the file, and this bootstrap is required *below* them, immediately before
	 * `wp-settings.php`. By the time this function runs the credentials are
	 * therefore already in scope -- so the limitation is Drupal's, not the
	 * early path's, and carrying it over would have been transliteration.
	 *
	 * The two halves the compiler splits still hold. Values are read from the
	 * constants at request time, so a rotated password takes effect on the next
	 * request rather than the next rebuild; and the *paths* they are injected
	 * at come from a sidecar written beside the compiled file, because the
	 * option the normal path reads them from needs a WordPress that does not
	 * exist yet. Neither half puts a credential on disk.
	 *
	 * Anything explicitly passed in `overrides` still wins: a site supplying
	 * its own connection is not overwritten by this.
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

		$credentials = basic_firewall_connection_parameters( $options );

		if ( array() !== $credentials ) {
			foreach ( basic_firewall_connection_paths( $options ) as $path ) {
				if ( ! isset( $overrides[ $path ] ) ) {
					$overrides[ $path ] = $credentials;
				}
			}
		}

		return $overrides;
	}

	/**
	 * Where the compiled configuration wants live credentials injected.
	 *
	 * Read from the sidecar the compiler writes beside the compiled file. An
	 * absent or unreadable file means no injection, which is the behaviour this
	 * path had before the sidecar existed: storage that needs a connection
	 * fails open, and Site Health says so.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return array<string>
	 */
	function basic_firewall_connection_paths( array $options ) {
		$compiled = basic_firewall_compiled_path( $options );

		if ( null === $compiled ) {
			return array();
		}

		$sidecar = dirname( $compiled ) . '/connection-paths.json';

		if ( ! is_readable( $sidecar ) ) {
			return array();
		}

		$decoded = json_decode( (string) file_get_contents( $sidecar ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, and WP_Filesystem does not exist on this path.

		if ( ! is_array( $decoded ) ) {
			return array();
		}

		$paths = array();

		foreach ( $decoded as $path ) {
			if ( is_string( $path ) && '' !== $path ) {
				$paths[] = $path;
			}
		}

		return $paths;
	}

	/**
	 * WordPress's database connection, read from the constants.
	 *
	 * Delegates to the same class the normal path uses, so the two paths cannot
	 * drift -- `DB_HOST` alone has four shapes (host, host:port, bracketed IPv6,
	 * unix socket) and getting them right twice is getting them right once and
	 * wrong once. The class is loaded by hand because the release build's
	 * autoloader is an authoritative classmap of the *vendored* tree and does
	 * not carry this plugin's own `src/`; the guard stops a redeclare when the
	 * normal path has already autoloaded it.
	 *
	 * Only `get_connection_parameters()` is called, which touches nothing but
	 * the constants. The rest of the class uses `$wpdb` and would fatal here.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return array<string, mixed>
	 */
	function basic_firewall_connection_parameters( array $options ) {
		if ( ! defined( 'DB_NAME' ) || ! defined( 'DB_USER' ) || ! defined( 'DB_HOST' ) ) {
			return array();
		}

		$class = 'Kanopi\\BasicFirewall\\Database_Credentials';

		if ( ! class_exists( $class, false ) ) {
			$file = rtrim( (string) $options['plugin_path'], '/' ) . '/src/Database_Credentials.php';

			if ( ! is_readable( $file ) ) {
				return array();
			}

			require_once $file;
		}

		if ( ! class_exists( $class, false ) ) {
			return array();
		}

		try {
			return ( new $class() )->get_connection_parameters();
		} catch ( \Throwable $e ) {
			// A malformed DB_HOST is not a reason for the site to stop serving:
			// no credentials means no injection, which means storage that needs
			// one fails open and Site Health reports it.
			return array();
		}
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
