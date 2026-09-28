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
 * `EXCEPTION` MODE.
 *
 * In every other mode the library sends its own response and exits, so nothing
 * here is involved. In `exception` mode it throws the verdict for the host to
 * answer, and this file is the host. It answers a block, a lockdown, a redirect
 * and a challenge on the spot, with the plugin's own Outcome_Responder loaded
 * by hand -- not later from the mu-plugin, because advanced-cache.php runs in
 * between, and a page cache would serve the refused visitor the page. The one
 * verdict it leaves for WordPress is a solved challenge, which needs settings
 * to set the pass cookie; see basic_firewall_answer_outcome().
 *
 * The plugin being deactivated does not reach this file: whether it is active
 * is an option, and there are no options here. Deactivation deletes the
 * compiled file instead, so this path stops evaluating in every mode at once.
 * A plugin switched off without that hook running -- `active_plugins` edited
 * by hand, a database restored from before activation -- leaves the compiled
 * file behind, and this path goes on enforcing the last configuration in
 * `exception` mode exactly as it would in `block` mode, where the library
 * answers without asking anyone. Only a solved challenge, left for a runner
 * that never loads, goes unanswered -- and that grants nothing.
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
	 * @return bool True when the request may continue. False when `exception`
	 *              mode reached a verdict this path left for WordPress to
	 *              answer; every verdict it answers itself ends the request.
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

		/*
		 * An `X-Firewall-Mark` the client sent is not a mark. The header is
		 * where the plugin mirrors the marks it applies, and anything reading
		 * it cannot tell the two apart, so it goes before anything can
		 * short-circuit -- whether or not this request is evaluated here. The
		 * runner does the same on the mu-plugin path; see
		 * Runner::forget_client_marks().
		 */
		unset( $_SERVER['HTTP_X_FIREWALL_MARK'] );

		$options = basic_firewall_options( $options );

		/*
		 * `responder` -- whether this path can answer an `exception` mode
		 * verdict itself, or would have to leave it until the mu-plugin loads,
		 * after a page cache has had the chance to serve the page. Site Health
		 * reports the second as critical when the mode is `exception`.
		 */
		$GLOBALS['basic_firewall_early']['responder'] = null !== basic_firewall_responder_file( $options );

		if ( ! $options['enabled'] ) {
			$GLOBALS['basic_firewall_early']['reason'] = 'disabled';

			return true;
		}

		$compiled = basic_firewall_compiled_path( $options );

		if ( null === $compiled ) {
			$GLOBALS['basic_firewall_early']['reason'] = 'no-compiled-file';

			return true;
		}

		$runtime = basic_firewall_runtime( $options );

		/*
		 * "Enable the firewall" unticked in the admin. The runner reads that
		 * setting from an option; this path has no options, so the compiler
		 * mirrors it into the runtime sidecar. Checked before anything is
		 * loaded, and before BASIC_FIREWALL_MODE gets a say: a mode pinned in
		 * wp-config.php chooses how the firewall answers, not whether a
		 * firewall somebody switched off runs at all.
		 */
		if ( false === $runtime['enabled'] ) {
			$GLOBALS['basic_firewall_early']['reason'] = 'switched-off';

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

		$request = null;

		try {
			$firewall = call_user_func(
				array( $class, 'create' ),
				array( $compiled ),
				basic_firewall_build_overrides( $options ),
				basic_firewall_decision_dispatcher( $options )
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
			$request_class = 'Kanopi\\Firewall\\Firewall' === $class
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
			 * Every verdict `exception` mode throws lands here -- a block, a
			 * lockdown, a challenge, a redirect -- alongside every genuine
			 * failure. The library exits by itself in every other mode, so this
			 * is only ever `exception` mode or a firewall that could not run.
			 *
			 * This used to allow all of it. The mu-plugin never evaluated again
			 * because BASIC_FIREWALL_EVALUATED was already defined, so a site in
			 * `exception` mode on this path refused nobody at all.
			 */
			return basic_firewall_answer_outcome( $e, $request, $options );
		}
	}

	/**
	 * Answer what `exception` mode threw, or fail open on anything else.
	 *
	 * **Answered here, not later.** The tempting design stashes the verdict and
	 * lets the mu-plugin answer it once WordPress has loaded, which is how a
	 * mark crosses the gap. For a refusal that is wrong in exactly the case this
	 * path exists for: advanced-cache.php loads between here and the mu-plugin,
	 * and on a cache hit it serves the page and exits. The visitor the firewall
	 * refused would get the page from the cache instead. So a block, a lockdown,
	 * a redirect and a challenge are answered now, by the same Outcome_Responder
	 * the normal path uses, loaded by hand the way Decision_Dispatcher is.
	 *
	 * **Stashed, for the runner.** A solved challenge is not a refusal. It sets
	 * the pass cookie, whose name lives in settings, which need WordPress; and
	 * it is a POST to the challenge path, which no page cache serves. So it is
	 * left in a global and answered by the runner at `muplugins_loaded`, before
	 * any ordinary plugin loads. The same global carries a refusal in the one
	 * case this path cannot answer it -- the responder missing from this copy
	 * of the plugin -- so it is still answered, late, rather than dropped; the
	 * bootstrap's self-report says so and Site Health calls it critical.
	 *
	 * A stash nobody answers -- the plugin switched off without its
	 * deactivation hook running -- fails open. For a solved challenge that
	 * grants nothing: the visitor has no pass cookie and is challenged again.
	 *
	 * Anything that is not a verdict is a failure of the firewall rather than
	 * a decision about the request, and fails open exactly as it always has.
	 *
	 * @param \Throwable           $outcome What the firewall threw.
	 * @param object|null          $request The request it was about, when it got that far.
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return bool True when the request may continue.
	 */
	function basic_firewall_answer_outcome( \Throwable $outcome, $request, array $options ) {
		$kind = basic_firewall_outcome_kind( $outcome );

		if ( null === $kind ) {
			return true;
		}

		$GLOBALS['basic_firewall_early']['outcome'] = $kind;
		$GLOBALS['basic_firewall_outcome']          = array(
			'outcome' => $outcome,
			'request' => $request,
		);

		if ( 'solved' === $kind ) {
			return false;
		}

		$responder = basic_firewall_outcome_responder( $options );

		if ( null === $responder ) {
			$GLOBALS['basic_firewall_early']['deferred'] = true;

			return false;
		}

		unset( $GLOBALS['basic_firewall_outcome'] );

		try {
			// Ends the request for every verdict it is handed.
			return $responder->respond( $outcome, $request );
		} catch ( \Throwable $e ) {
			// A responder that cannot answer is not a reason for a fatal
			// error on every refused request. Hand it to the runner instead.
			$GLOBALS['basic_firewall_outcome']           = array(
				'outcome' => $outcome,
				'request' => $request,
			);
			$GLOBALS['basic_firewall_early']['deferred'] = true;

			return false;
		}
	}

	/**
	 * Which verdict an exception is, or null when it is not one.
	 *
	 * By class name in both spellings, because a release build carries the
	 * library under a prefix and a Composer install does not, and this file is
	 * copied into the release verbatim rather than scoped.
	 *
	 * @param \Throwable $outcome What the firewall threw.
	 *
	 * @return string|null `solved`, `challenge`, `redirect`, `blocked`, or null.
	 */
	function basic_firewall_outcome_kind( \Throwable $outcome ) {
		$kinds = array(
			'ChallengeSolvedException'   => 'solved',
			'ChallengeRequiredException' => 'challenge',
			'FirewallRedirectException'  => 'redirect',

			// FirewallLockdownException extends this one.
			'FirewallBlockedException'   => 'blocked',
		);

		foreach ( $kinds as $class => $kind ) {
			foreach ( array( 'Kanopi\\Firewall\\Exception\\', 'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Exception\\' ) as $namespace ) {
				if ( is_a( $outcome, $namespace . $class ) ) {
					return $kind;
				}
			}
		}

		return null;
	}

	/**
	 * Where the plugin's outcome responder lives, when this copy has one.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return string|null
	 */
	function basic_firewall_responder_file( array $options ) {
		$file = rtrim( (string) $options['plugin_path'], '/' ) . '/src/Runtime/Outcome_Responder.php';

		return is_readable( $file ) ? $file : null;
	}

	/**
	 * The plugin's own outcome responder, loaded without its autoloader.
	 *
	 * The same class the normal path answers with, so the two paths cannot
	 * answer the same verdict differently. Loaded by hand for the reason
	 * Decision_Dispatcher is: the release build's autoloader carries the
	 * vendored tree and not this plugin's own `src/`. Only reached when a
	 * verdict needs answering, so an allowed request never pays for it.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return object|null
	 */
	function basic_firewall_outcome_responder( array $options ) {
		$class = 'Kanopi\\BasicFirewall\\Runtime\\Outcome_Responder';

		if ( ! class_exists( $class, false ) ) {
			$file = basic_firewall_responder_file( $options );

			if ( null === $file ) {
				return null;
			}

			try {
				require_once $file;
			} catch ( \Throwable $e ) {
				return null;
			}
		}

		return class_exists( $class, false ) ? new $class() : null;
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
	 * What the compiler left for this path in the runtime sidecar.
	 *
	 * The settings the library's configuration has no key for, which the
	 * runner reads from options and this path cannot. An absent or unreadable
	 * sidecar means every default -- the compiler writes one only when
	 * something differs -- and so does anything in it of the wrong type, so a
	 * damaged file never switches a feature on.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return array{enabled: bool}
	 */
	function basic_firewall_runtime( array $options ) {
		$runtime = array(
			'enabled' => true,
		);

		$compiled = basic_firewall_compiled_path( $options );

		if ( null === $compiled ) {
			return $runtime;
		}

		$sidecar = dirname( $compiled ) . '/runtime.json';

		if ( ! is_readable( $sidecar ) ) {
			return $runtime;
		}

		$decoded = json_decode( (string) file_get_contents( $sidecar ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, and WP_Filesystem does not exist on this path.

		if ( ! is_array( $decoded ) ) {
			return $runtime;
		}

		if ( false === ( $decoded['enabled'] ?? true ) ) {
			$runtime['enabled'] = false;
		}

		return $runtime;
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

			/*
			 * And the panic file is disarmed, so the constant keeps winning.
			 * The library applies a panic file over whatever mode the
			 * configuration arrived at, overrides included, so without this an
			 * environment that pins its mode in wp-config.php would have it
			 * changed by a file. The runner does the same on the other path.
			 */
			$overrides['[global][panic_file]'] = '';
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
	 * The dispatcher the library announces its decisions on.
	 *
	 * There are no WordPress actions yet, so this path cannot announce
	 * anything. It hands the library the same dispatcher the normal path uses,
	 * which holds each decision until WordPress has loaded and plugins have had
	 * the chance to listen, and announces it then -- the way a mark waits.
	 *
	 * Loaded by hand for the reason Database_Credentials is: the release
	 * build's autoloader carries the vendored tree and not this plugin's own
	 * `src/`. A dispatcher that cannot be loaded means no announcements, never
	 * a request that fails.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return object|null
	 */
	function basic_firewall_decision_dispatcher( array $options ) {
		$class = 'Kanopi\\BasicFirewall\\Runtime\\Decision_Dispatcher';

		if ( ! class_exists( $class, false ) ) {
			$file = rtrim( (string) $options['plugin_path'], '/' ) . '/src/Runtime/Decision_Dispatcher.php';

			if ( ! is_readable( $file ) ) {
				return null;
			}

			try {
				require_once $file;
			} catch ( \Throwable $e ) {
				// The PSR interface it implements is missing from this vendor tree.
				return null;
			}
		}

		return class_exists( $class, false ) ? new $class() : null;
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
			/*
			 * BASIC_FIREWALL_CACHE_DIR first. It moves the two caches that can
			 * only ever be files -- the parsed configuration and imported list
			 * bodies -- off storage that is slow for many small reads, and it is
			 * a constant precisely so that this path and the mu-plugin path read
			 * the same answer. Paths::library_cache_dir() is the other half and
			 * must agree with this.
			 */
			$configured = defined( 'BASIC_FIREWALL_CACHE_DIR' ) ? BASIC_FIREWALL_CACHE_DIR : null;

			if ( is_string( $configured ) && '' !== trim( $configured ) ) {
				define( 'KANOPI_FIREWALL_CACHE_DIR', rtrim( trim( $configured ), '/' ) );
			} else {
				$private = basic_firewall_private_path( $options );

				if ( null !== $private ) {
					define( 'KANOPI_FIREWALL_CACHE_DIR', $private . '/cache' );
				}
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
