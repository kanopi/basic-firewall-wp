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
 *
 * A site that installed the plugin with Composer and moved its `vendor-dir`
 * somewhere other than beside the WordPress root adds the autoloader's path,
 * which the status screens also fill in when they can see it:
 *
 *         'autoloader'   => ABSPATH . 'wp-content/mu-plugins/vendor/autoload.php',
 *
 * Not on a multisite network: see basic_firewall_is_multisite(). There the
 * call returns without evaluating, and the mu-plugin evaluates each site
 * against its own rules.
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
			return basic_firewall_not_evaluated( 'disabled', $options );
		}

		/*
		 * Not on a multisite network. One wp-config.php serves every site of
		 * it, and at this point WordPress has not yet worked out which site a
		 * request is for -- that is ms-settings.php, well after this line. But
		 * each site has its own settings, its own compiled file and its own
		 * private directory, and the glob below finds whichever came first:
		 * so this path used to evaluate every site's traffic against one
		 * site's rules, and by marking the request evaluated it stopped the
		 * mu-plugin applying the right ones.
		 *
		 * So it steps aside, and does not mark the request, and the mu-plugin
		 * evaluates each site against its own rules. Site Health on a network
		 * says the snippet is doing nothing and can go.
		 */
		if ( basic_firewall_is_multisite( $options ) ) {
			return basic_firewall_not_evaluated( 'multisite', $options );
		}

		$compiled = basic_firewall_compiled_path( $options );

		if ( null === $compiled ) {
			return basic_firewall_not_evaluated( 'no-compiled-file', $options );
		}

		/*
		 * `compiled` -- which file this path read, and when it was written.
		 * The compiler may run in another container from the one serving
		 * requests (WP-CLI through a hosting CLI, say), and a report taken
		 * there says nothing about what a web container is reading. The
		 * runner saves this beside its own view of the file, so the two can
		 * be compared; see Diagnostics. The hash prefix is what makes that
		 * comparison mean something (#41): a container reading a stale copy
		 * of the file -- shared storage that has not caught up, a deploy
		 * that shipped an old one -- has a different hash from the last
		 * compile's, and the report flags it as a `mismatch`. One hash of a
		 * file of a few kilobytes, the same one the library is about to read.
		 */
		$hash = hash_file( 'sha256', $compiled );

		$GLOBALS['basic_firewall_early']['compiled'] = array(
			'path'  => $compiled,
			'mtime' => (int) filemtime( $compiled ),
			'hash'  => is_string( $hash ) ? substr( $hash, 0, 12 ) : null,
		);

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
			return basic_firewall_not_evaluated( 'switched-off', $options );
		}

		/*
		 * A role is exempt, and this request carries a WordPress login cookie.
		 * Whose it is cannot be known until WordPress validates it, so the
		 * request is left unmarked for the runner, which evaluates it -- or,
		 * for a member of an exempt role, does not -- once it can. Anything
		 * without the cookie is evaluated here as usual; see Role_Bypass.
		 */
		if ( $runtime['defer_login'] && basic_firewall_carries_login_cookie( $options ) ) {
			return basic_firewall_not_evaluated( 'deferred-login', $options );
		}

		/*
		 * `autoloader` -- which autoloader this path used, and where it came
		 * from, so the status screens can say which file a failure is about.
		 * A site whose Composer vendor-dir is somewhere this file cannot guess
		 * names it in the snippet, and a name that does not resolve is worth
		 * saying out loud; see basic_firewall_resolve_autoloader().
		 */
		$autoload = basic_firewall_resolve_autoloader( $options );

		$GLOBALS['basic_firewall_early']['autoloader'] = $autoload;

		if ( 'unreadable' === $autoload['source'] ) {
			return basic_firewall_not_evaluated( 'autoloader-unreadable', $options );
		}

		if ( 'none' === $autoload['source'] ) {
			return basic_firewall_not_evaluated( 'no-autoloader', $options );
		}

		if ( null !== $autoload['file'] ) {
			require_once $autoload['file'];
		}

		$prefix = basic_firewall_library_prefix();

		if ( null === $prefix ) {
			return basic_firewall_not_evaluated( 'library-missing', $options );
		}

		// `library` -- which copy of the library this path runs.
		$GLOBALS['basic_firewall_early']['library'] = '' === $prefix ? 'unscoped' : 'scoped';

		basic_firewall_define_cache_constants( $options );

		// `cache_dir` -- where the library's file caches go on this path,
		// which is the only backend it has: the object cache cannot be
		// handed to it before WordPress. See Cache_Backend.
		$GLOBALS['basic_firewall_early']['cache_dir'] = defined( 'KANOPI_FIREWALL_CACHE_DIR' ) ? (string) constant( 'KANOPI_FIREWALL_CACHE_DIR' ) : null;
		basic_firewall_enable_file_secrets( $options );
		basic_firewall_set_trusted_proxies( $options );
		basic_firewall_apply_redaction( $options, $runtime['redact'] );

		/*
		 * Marks the request as dealt with, so the mu-plugin does not evaluate it
		 * a second time when WordPress finally loads.
		 */
		if ( ! defined( 'BASIC_FIREWALL_EVALUATED' ) ) {
			define( 'BASIC_FIREWALL_EVALUATED', true );
		}

		$GLOBALS['basic_firewall_early']['evaluated'] = true;

		$class = $prefix . 'Kanopi\\Firewall\\Firewall';

		$request = null;

		try {
			$firewall = call_user_func(
				array( $class, 'create' ),
				array( $compiled ),
				basic_firewall_build_overrides( $options ),
				basic_firewall_decision_dispatcher( $options )
			);

			/*
			 * `mode` -- the mode the firewall this path built is actually in,
			 * panic file and BASIC_FIREWALL_MODE included. The settings say
			 * what was asked for; this is what a web request got.
			 */
			$GLOBALS['basic_firewall_early']['mode'] = basic_firewall_firewall_mode( $firewall );

			/*
			 * `panic` -- whether a panic file is what put the firewall in that
			 * mode, so a mode that differs from the configured one is reported
			 * as the override it is rather than flagged as a mismatch.
			 */
			$GLOBALS['basic_firewall_early']['panic'] = basic_firewall_panic_active( $firewall );

			/*
			 * `failed_rules` -- the rules this path's firewall could not
			 * construct, which the library skips and logs rather than fatals
			 * on (#41). A rule that fails only on the web containers -- a
			 * storage host only they cannot reach, an extension only the CLI
			 * image has -- showed up nowhere a status screen could see.
			 * Asked before evaluating, so a request the library then refuses
			 * and exits on is still reported; building the rules here is
			 * work evaluate() reuses rather than repeats.
			 */
			$GLOBALS['basic_firewall_early']['failed_rules'] = basic_firewall_failed_rules( $firewall );

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
			 *
			 * Built by the plugin's request factory, from the Request class of
			 * the copy the firewall came from, so a directly requested file
			 * such as wp-login.php is matched on its own path rather than on
			 * `/`. See basic_firewall_request().
			 */
			$request_class = $prefix . 'Symfony\\Component\\HttpFoundation\\Request';

			$request = basic_firewall_request( $request_class, $options );

			$allowed = $firewall->evaluate( $request );

			$marks = $request->attributes->get( 'firewall.marks' );

			if ( is_array( $marks ) && array() !== $marks ) {
				$GLOBALS['basic_firewall_marks'] = array_values( array_map( 'strval', $marks ) );
			}

			basic_firewall_send_debug_header();

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
	 * The current request, as the firewall should see it.
	 *
	 * Built by the plugin's Request_Factory, the same class the mu-plugin
	 * builds its request with, so the two paths cannot see one request
	 * differently. The request is Symfony's own, unedited: which path the
	 * rules match for a directly requested file -- wp-login.php, xmlrpc.php,
	 * a wp-admin screen -- is the library's job, under the compiled
	 * `path_source: script_name`.
	 *
	 * Loaded by hand for the reason Decision_Dispatcher is: the release
	 * build's autoloader carries the vendored tree and not this plugin's own
	 * `src/`. A copy of the plugin without the factory still evaluates, on the
	 * request exactly as Symfony builds it.
	 *
	 * @param string               $request_class The Request class of the copy the firewall is built from.
	 * @param array<string, mixed> $options       Bootstrap options.
	 *
	 * @return object
	 */
	function basic_firewall_request( $request_class, array $options ) {
		$class = 'Kanopi\\BasicFirewall\\Runtime\\Request_Factory';

		if ( ! class_exists( $class, false ) ) {
			$file = rtrim( (string) $options['plugin_path'], '/' ) . '/src/Runtime/Request_Factory.php';

			if ( is_readable( $file ) ) {
				require_once $file;
			}
		}

		if ( class_exists( $class, false ) ) {
			return call_user_func( array( $class, 'from_globals_of' ), $request_class );
		}

		return call_user_func( array( $request_class, 'createFromGlobals' ) );
	}

	/**
	 * Return without evaluating, and say why.
	 *
	 * Records the reason in the bootstrap's report, as every early return
	 * always has, and -- for a reason that means the snippet is not doing
	 * the job it was added for -- writes it to the PHP error log as well.
	 * The report lives only as long as the request, and the status screens
	 * read the report of *their own* request: an admin screen, or WP-CLI in
	 * another container altogether. So a web server whose early path never
	 * evaluated anything could look healthy from every screen (#34).
	 *
	 * At most once per interval per reason, because a misconfiguration is
	 * the same on every request and a log line per request buries it.
	 *
	 * @param string               $reason  Why this request was not evaluated here.
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return bool Always true: the request continues, for the mu-plugin.
	 */
	function basic_firewall_not_evaluated( $reason, array $options ) {
		$GLOBALS['basic_firewall_early']['reason'] = $reason;

		if ( ! in_array( $reason, basic_firewall_benign_reasons(), true ) ) {
			$file = (string) ( $GLOBALS['basic_firewall_early']['autoloader']['file'] ?? '' );

			basic_firewall_warn_once(
				$reason,
				sprintf(
					'not-evaluated (early): the wp-config.php path did not evaluate this request (%s%s), so the mu-plugin evaluates it instead, after any page cache. Run `wp basic-firewall early-report` for the last web request\'s report. Logged at most once every %d minutes.',
					$reason,
					in_array( $reason, array( 'autoloader-unreadable', 'library-missing' ), true ) && '' !== $file ? ': ' . $file : '',
					(int) ceil( basic_firewall_warn_interval( $options ) / 60 )
				),
				$options
			);
		}

		basic_firewall_send_debug_header();

		return true;
	}

	/**
	 * Reasons for not evaluating that are the configuration working as meant.
	 *
	 * `disabled` and `switched-off` are the firewall being off on both paths,
	 * which the operating-mode checks report. `deferred-login` is a request
	 * with a login cookie on a site with an exempt role, handed to the runner
	 * on purpose. Everything else means the snippet is present and doing
	 * nothing. Diagnostics::BENIGN_REASONS must agree with this.
	 *
	 * @return list<string>
	 */
	function basic_firewall_benign_reasons() {
		return array( 'disabled', 'switched-off', 'deferred-login' );
	}

	/**
	 * How long a not-evaluated warning stays quiet after it is logged, in seconds.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return int
	 */
	function basic_firewall_warn_interval( array $options ) {
		return isset( $options['warn_interval'] ) && is_numeric( $options['warn_interval'] ) ? max( 0, (int) $options['warn_interval'] ) : 900;
	}

	/**
	 * Write a warning to the PHP error log.
	 *
	 * The only log reachable before WordPress, and the one a host keeps: the
	 * firewall's own logger is configured by the compiled file, which is what
	 * may have failed.
	 *
	 * @param string $message What happened.
	 *
	 * @return void
	 */
	function basic_firewall_warn( $message ) {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- no WordPress and no firewall logger before wp-settings.php.
		error_log( 'Basic Firewall [warning]: ' . $message );
	}

	/**
	 * Write a warning, unless the same one was written within the interval.
	 *
	 * Remembered in a marker file's modification time, in the private
	 * directory when there is one -- which on a host with several web
	 * containers is shared storage, so the interval holds across all of them
	 * -- and in the system temporary directory otherwise. A file rather than
	 * APCu because APCu is per container and often per worker pool, and it is
	 * not there at all on plenty of hosts. Checking costs one stat.
	 *
	 * A marker that cannot be written means the warning is logged every time,
	 * which is noisy and never silent.
	 *
	 * @param string               $key     What the warning is about: a reason code.
	 * @param string               $message The warning.
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return bool True when it was logged.
	 */
	function basic_firewall_warn_once( $key, $message, array $options ) {
		$private = basic_firewall_private_path( $options );
		$key     = preg_replace( '/[^a-z0-9-]/', '', strtolower( (string) $key ) );
		$marker  = null !== $private
			? $private . '/.warned-' . $key
			: rtrim( sys_get_temp_dir(), '/' ) . '/basic-firewall-warned-' . md5( (string) $options['plugin_path'] ) . '-' . $key;

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- no marker yet is the ordinary answer.
		$written = @filemtime( $marker );

		if ( false !== $written && time() - $written < basic_firewall_warn_interval( $options ) ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions -- best effort, and WP_Filesystem does not exist on this path.
		@touch( $marker );

		basic_firewall_warn( $message );

		return true;
	}

	/**
	 * Write a warning at most once per interval per key, counting the ones held back.
	 *
	 * For a warning that can happen on every request -- a fail-open -- where
	 * the first matters, a line per request buries the log, and how many
	 * were held back is itself the thing somebody investigating wants. The
	 * next line written says how many there were since the last:
	 * `... (12 more since 2026-01-01 12:00:00 UTC)`.
	 *
	 * The marker-file approach of basic_firewall_warn_once(), with the state
	 * in the file rather than its modification time, because a count has to
	 * be kept somewhere: when the key was last logged, and how many have been
	 * held back since. Locked while it is read and rewritten, so two workers
	 * failing at once neither both log nor lose a count. In the private
	 * directory when there is one, shared across web containers on a host
	 * that shares it; the system temporary directory otherwise. A marker
	 * that cannot be opened means the warning is logged every time -- noisy,
	 * never silent. Diagnostics::warn_throttled() writes the same file on the
	 * runner path.
	 *
	 * @param string               $key     What the warning is about, e.g. where, class and origin.
	 * @param string               $message The warning.
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return bool True when it was logged.
	 */
	function basic_firewall_warn_throttled( $key, $message, array $options ) {
		$interval = isset( $options['fail_open_interval'] ) && is_numeric( $options['fail_open_interval'] ) ? max( 0, (int) $options['fail_open_interval'] ) : 60;
		$private  = basic_firewall_private_path( $options );
		$name     = 'fail-open-' . substr( md5( (string) $key ), 0, 16 );
		$marker   = null !== $private
			? $private . '/.warned-' . $name
			: rtrim( sys_get_temp_dir(), '/' ) . '/basic-firewall-warned-' . md5( (string) $options['plugin_path'] ) . '-' . $name;

		// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors.Discouraged -- no WP_Filesystem on this path, and a marker that cannot be opened is not an error.
		$handle = @fopen( $marker, 'c+' );

		if ( false === $handle ) {
			basic_firewall_warn( $message );

			return true;
		}

		@flock( $handle, LOCK_EX );

		$state      = json_decode( (string) stream_get_contents( $handle ), true );
		$logged_at  = is_array( $state ) ? (int) ( $state['logged'] ?? 0 ) : 0;
		$suppressed = is_array( $state ) ? (int) ( $state['suppressed'] ?? 0 ) : 0;
		$now        = time();
		$write      = $logged_at <= 0 || $now - $logged_at >= $interval;

		if ( $write ) {
			if ( $suppressed > 0 ) {
				$message .= sprintf( ' (%d more since %s UTC)', $suppressed, gmdate( 'Y-m-d H:i:s', $logged_at ) );
			}

			basic_firewall_warn( $message );

			$logged_at  = $now;
			$suppressed = 0;
		} else {
			++$suppressed;
		}

		ftruncate( $handle, 0 );
		rewind( $handle );
		fwrite(
			$handle,
			(string) json_encode(
				array(
					'logged'     => $logged_at,
					'suppressed' => $suppressed,
				)
			)
		); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress yet.
		@flock( $handle, LOCK_UN );
		fclose( $handle );
		// phpcs:enable WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors.Discouraged

		return $write;
	}

	/**
	 * What a throwable was, for a log line or a report.
	 *
	 * Class, message and where it was thrown -- not a trace, which is long,
	 * mostly the library's own frames, and carries argument values. The
	 * message has any `user:password@` in a URL masked, since a storage
	 * backend that cannot connect may name the DSN it tried, and it is cut
	 * short so one exception cannot fill a log line or a header.
	 *
	 * @param \Throwable $e What was thrown.
	 *
	 * @return array{class: string, message: string, origin: string}
	 */
	function basic_firewall_describe_throwable( \Throwable $e ) {
		$message = (string) preg_replace( '#(://[^/\s:@]*):[^@\s/]*@#', '$1:***@', $e->getMessage() );
		$message = trim( (string) preg_replace( '/\s+/', ' ', $message ) );

		if ( strlen( $message ) > 300 ) {
			$message = substr( $message, 0, 300 ) . '...';
		}

		return array(
			'class'   => get_class( $e ),
			'message' => $message,
			'origin'  => $e->getFile() . ':' . $e->getLine(),
		);
	}

	/**
	 * The mode a firewall is actually in, or null when it cannot say.
	 *
	 * @param object $firewall The firewall.
	 *
	 * @return string|null
	 */
	function basic_firewall_firewall_mode( $firewall ) {
		if ( ! is_callable( array( $firewall, 'getMode' ) ) ) {
			return null;
		}

		$mode = call_user_func( array( $firewall, 'getMode' ) );

		return $mode instanceof \BackedEnum ? (string) $mode->value : null;
	}

	/**
	 * Whether a panic file is changing a firewall's mode.
	 *
	 * @param object $firewall The firewall.
	 *
	 * @return bool
	 */
	function basic_firewall_panic_active( $firewall ) {
		if ( ! is_callable( array( $firewall, 'getPanicSwitch' ) ) ) {
			return false;
		}

		$switch = call_user_func( array( $firewall, 'getPanicSwitch' ) );

		return is_array( $switch ) && ! empty( $switch['active'] );
	}

	/**
	 * The rules a firewall could not construct, by name, or null when it cannot say.
	 *
	 * Each is `bucket/Class:index` -- the bucket it was configured in and the
	 * library's own name for it, with the namespace dropped so a scoped and
	 * an unscoped copy name a rule alike. Names only: the constructor's
	 * message can carry a host or a DSN, and the library already logs it.
	 *
	 * Never throws. The library's answer is built by constructing every rule,
	 * and a constructor that fails with an Error rather than an Exception is
	 * not caught by the library; that is a failure the evaluation that
	 * follows reports as a fail-open, so here it is only "cannot say".
	 * Diagnostics::failed_rules() does the same on the runner path.
	 *
	 * @param object $firewall The firewall.
	 *
	 * @return list<string>|null
	 */
	function basic_firewall_failed_rules( $firewall ) {
		if ( ! is_callable( array( $firewall, 'getFailedRules' ) ) ) {
			return null;
		}

		try {
			$failed = call_user_func( array( $firewall, 'getFailedRules' ) );
		} catch ( \Throwable $e ) {
			return null;
		}

		$names = array();

		foreach ( is_array( $failed ) ? $failed : array() as $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}

			$plugin = (string) ( $entry['plugin'] ?? '' );
			$slash  = strrpos( $plugin, '\\' );

			$names[] = (string) ( $entry['bucket'] ?? '?' ) . '/' . ( false === $slash ? $plugin : substr( $plugin, $slash + 1 ) );
		}

		return $names;
	}

	/**
	 * Whether BASIC_FIREWALL_DEBUG asks for the diagnostic response header.
	 *
	 * @return bool
	 */
	function basic_firewall_debug_enabled() {
		return defined( 'BASIC_FIREWALL_DEBUG' ) && (bool) constant( 'BASIC_FIREWALL_DEBUG' );
	}

	/**
	 * The bootstrap's report, compact, for the debug header.
	 *
	 * No secrets: no paths but a file name and line, no message text, no
	 * request data. Diagnostics::compact_early() writes the same shape on the
	 * runner path.
	 *
	 * @return array<string, mixed>
	 */
	function basic_firewall_debug_report() {
		$early  = isset( $GLOBALS['basic_firewall_early'] ) && is_array( $GLOBALS['basic_firewall_early'] ) ? $GLOBALS['basic_firewall_early'] : array();
		$origin = isset( $early['failure_origin'] ) ? (string) $early['failure_origin'] : '';

		return array(
			'called'       => ! empty( $early['called'] ),
			'evaluated'    => ! empty( $early['evaluated'] ),
			'reason'       => $early['reason'] ?? null,
			'autoloader'   => $early['autoloader']['source'] ?? null,
			'library'      => $early['library'] ?? null,
			'mode'         => $early['mode'] ?? null,
			'outcome'      => $early['outcome'] ?? null,
			'failure'      => isset( $early['failure'] ) ? strtok( (string) $early['failure'], ':' ) . ( '' !== $origin ? ' @ ' . basename( $origin ) : '' ) : null,
			'refused'      => ! empty( $early['refused'] ),
			'responder'    => ! empty( $early['responder'] ),

			// Names only, and null when this path built no firewall.
			'failed_rules' => isset( $early['failed_rules'] ) && is_array( $early['failed_rules'] ) ? array_values( array_map( 'strval', $early['failed_rules'] ) ) : null,
		);
	}

	/**
	 * Add the X-Basic-Firewall-Early header, when BASIC_FIREWALL_DEBUG asks.
	 *
	 * For troubleshooting only: it tells anybody who can make a request how
	 * the firewall is deployed. Off unless the constant is defined truthy.
	 * Sent from every exit of the early path, so it is on the responses the
	 * bootstrap writes itself and on a page served from a cache that runs
	 * before the runner; the runner replaces it with a fuller one on any
	 * request that reaches WordPress.
	 *
	 * @return void
	 */
	function basic_firewall_send_debug_header() {
		if ( ! basic_firewall_debug_enabled() || headers_sent() ) {
			return;
		}

		$json = json_encode( array( 'early' => basic_firewall_debug_report() ), JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress yet.

		if ( is_string( $json ) ) {
			header( 'X-Basic-Firewall-Early: ' . $json, true );
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
	 * any ordinary plugin loads.
	 *
	 * **Refused, when it cannot be answered.** A verdict the responder cannot
	 * answer -- the responder missing from this copy of the plugin, throwing,
	 * or returning instead of ending the request -- is refused here, with a
	 * plain 503, rather than left for the runner: the runner runs after the
	 * page cache, and a verdict waved on to it is a page served (#34). See
	 * basic_firewall_refuse().
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
			/*
			 * Failed open, and said so. The runner takes this up once
			 * WordPress loads, so Site Health reports the failure rather
			 * than a firewall that evaluated this request and allowed it.
			 *
			 * And logged. The report above only lives as long
			 * as this request, and reaches Site Health only when this
			 * request is the one Site Health is rendering -- so a firewall
			 * that failed on every visitor's request and never on an
			 * administrator's left no trace anywhere (#34). The PHP error
			 * log is the one place this path can write to that somebody
			 * investigating later will read.
			 *
			 * At most once a minute for the same exception from the same
			 * place (#41), with a count of the ones held back: a failure that
			 * persists -- a storage outage on a busy site -- would otherwise
			 * write a line per request and bury everything else in the log.
			 * The first is always written.
			 */
			$failure = basic_firewall_describe_throwable( $outcome );

			$GLOBALS['basic_firewall_early']['failure']        = $failure['class'] . ': ' . $failure['message'];
			$GLOBALS['basic_firewall_early']['failure_origin'] = $failure['origin'];

			basic_firewall_warn_throttled(
				'early|' . $failure['class'] . '|' . $failure['origin'],
				sprintf(
					'fail-open (early): the firewall threw %s "%s" at %s on the wp-config.php path, so the request was let through unfiltered.',
					$failure['class'],
					$failure['message'],
					$failure['origin']
				),
				$options
			);

			basic_firewall_send_debug_header();

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
			/*
			 * This copy of the plugin has no responder to answer with. The
			 * verdict used to be left for the runner, which answers it once
			 * WordPress loads -- after advanced-cache.php, which on a cache
			 * hit serves the page and exits first. A refusal now, plain as it
			 * is, never serves the page. Site Health says why it was plain.
			 */
			basic_firewall_refuse( $kind, 'the plugin\'s responder is missing from this copy of the plugin' );

			return false;
		}

		unset( $GLOBALS['basic_firewall_outcome'] );

		// Queued before the responder writes anything, which it does not replace.
		basic_firewall_send_debug_header();

		try {
			// Ends the request for every verdict it is handed.
			$responder->respond( $outcome, $request );

			/*
			 * Reaching this line means it did not: the responder took the
			 * verdict for something that lets the request continue. #34 was
			 * a challenge the page was served in place of, with nothing
			 * logged, and this line returning the responder's `true` is one
			 * way that happens. A verdict is never a reason to serve the page.
			 */
			$why = 'the responder returned without answering it';
		} catch ( \Throwable $e ) {
			/*
			 * This used to hand the verdict to the runner, which answers it
			 * after a page cache has had the chance to serve the page -- and
			 * not at all where nothing loads the plugin before the cache.
			 */
			$why = 'the responder threw ' . get_class( $e ) . ': ' . $e->getMessage();
		}

		basic_firewall_refuse( $kind, $why );

		return false;
	}

	/**
	 * Refuse the request, without WordPress and without the responder.
	 *
	 * The last answer to a verdict this path could not answer properly -- no
	 * responder, a responder that threw, or one that returned instead of
	 * ending the request. Whatever the verdict was, the visitor gets a
	 * temporary refusal and not the page: failing open here is what #34
	 * reported, a challenge rule serving the page it stands in front of, with
	 * WordPress's cache headers, to be cached at the edge and served to
	 * everyone after.
	 *
	 * Written by hand because anything more capable is what just failed. The
	 * no-store set is the library's own when it has one; see
	 * basic_firewall_no_store_headers(). What went wrong goes to the PHP error
	 * log at warning, the only log reachable before WordPress, and into the
	 * bootstrap's report for anything that runs before exit.
	 *
	 * @param string $kind What the verdict was: `challenge`, `redirect` or `blocked`.
	 * @param string $why  What went wrong, for the log.
	 *
	 * @return void Never returns: the request ends here.
	 */
	function basic_firewall_refuse( $kind, $why ) {
		$GLOBALS['basic_firewall_early']['refused'] = $why;

		basic_firewall_warn( sprintf( 'a %s verdict on the wp-config.php path could not be answered (%s), so the request was refused.', $kind, $why ) );

		basic_firewall_send_debug_header();

		if ( ! headers_sent() ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- compared against a fixed list and replaced unless it matches exactly.
			$protocol = isset( $_SERVER['SERVER_PROTOCOL'] ) ? (string) $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.1';

			if ( ! in_array( $protocol, array( 'HTTP/1.0', 'HTTP/1.1', 'HTTP/2', 'HTTP/3' ), true ) ) {
				$protocol = 'HTTP/1.1';
			}

			header( $protocol . ' 503 Service Unavailable', true, 503 );

			$headers = array( 'Content-Type' => 'text/html; charset=utf-8' )
				+ basic_firewall_no_store_headers()
				+ array(
					'Retry-After'            => '60',
					'X-Content-Type-Options' => 'nosniff',
					'X-Robots-Tag'           => 'noindex, nofollow',
				);

			foreach ( $headers as $name => $value ) {
				header( $name . ': ' . $value, true );
			}
		}

		echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Verification required</title></head>"
			. "<body><main><h1>Verification required</h1><p>This request needs a verification step that could not be shown. Please try again shortly.</p></main></body></html>\n";

		exit;
	}

	/**
	 * The headers that keep a response out of every cache.
	 *
	 * The library's `NoStore::HEADERS` (kanopi/firewall#418) from the copy
	 * this path runs, when it has the class, so a refusal written here and
	 * one written by the library cannot differ. The same set written out
	 * otherwise, because this is the answer of last resort and must not
	 * depend on anything else having loaded -- including a library copy new
	 * enough to have the class, which a site's own Composer tree loaded above
	 * the snippet need not be. Outcome_Responder, which only runs beside a
	 * library the plugin's ^2.34.1 requirement admitted, uses the class alone.
	 *
	 * @return array<string, string>
	 */
	function basic_firewall_no_store_headers() {
		$fallback = array(
			'Cache-Control'     => 'private, no-store, no-cache, must-revalidate, max-age=0',
			'Pragma'            => 'no-cache',
			'Expires'           => '0',
			'Surrogate-Control' => 'no-store',
			'CDN-Cache-Control' => 'no-store',
		);

		$prefix = basic_firewall_library_prefix();
		$class  = null === $prefix ? null : $prefix . 'Kanopi\\Firewall\\Utility\\NoStore';

		if ( null !== $class && class_exists( $class ) && defined( $class . '::HEADERS' ) ) {
			$headers = constant( $class . '::HEADERS' );

			if ( is_array( $headers ) ) {
				return array_map( 'strval', $headers ) + $fallback;
			}
		}

		return $fallback;
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
	 * The namespace prefix of the library copy this path runs, or null for none.
	 *
	 * **The scoped copy first.** A release build carries the library under the
	 * plugin's own prefix, and the compiled file it writes names the prefixed
	 * classes. This used to reach for the unscoped name whenever it existed --
	 * which it does on any site whose wp-config.php loads a site-level
	 * Composer autoloader carrying kanopi/firewall for some other reason. The
	 * firewall was then built from the other copy, trusted proxies were set on
	 * the other copy's Request, and the request was handed to a firewall that
	 * could not read its own configuration: a fatal, or a fail-open nobody saw.
	 *
	 * One answer, asked once and used for every class this file names, so the
	 * firewall, the Request and the helpers always come from the same copy.
	 *
	 * @return string|null `Kanopi\BasicFirewall\Vendor\` for a scoped build,
	 *                     an empty string for an unscoped one.
	 */
	function basic_firewall_library_prefix() {
		foreach ( array( 'Kanopi\\BasicFirewall\\Vendor\\', '' ) as $prefix ) {
			if ( class_exists( $prefix . 'Kanopi\\Firewall\\Firewall' ) ) {
				return $prefix;
			}
		}

		return null;
	}

	/**
	 * Whether this is a multisite network, as far as wp-config.php has said.
	 *
	 * `MULTISITE` is what WordPress itself reads, and the network setup screen
	 * tells an administrator to define it -- with `SUBDOMAIN_INSTALL` -- above
	 * the line this file is required from. Either is enough, and so is the
	 * snippet saying so, for a network that defines them somewhere this file
	 * cannot see yet.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return bool
	 */
	function basic_firewall_is_multisite( array $options ) {
		if ( ! empty( $options['multisite'] ) ) {
			return true;
		}

		// Read as constant(), not is_multisite(): that is a WordPress function,
		// and there is no WordPress yet.
		if ( defined( 'MULTISITE' ) && constant( 'MULTISITE' ) ) {
			return true;
		}

		return defined( 'SUBDOMAIN_INSTALL' );
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
			// Absolute path to the site's Composer autoloader, for a site
			// whose vendor-dir is not beside the WordPress root. The plugin's
			// own vendor/ still wins; see basic_firewall_resolve_autoloader().
			// BASIC_FIREWALL_AUTOLOADER says the same once per environment.
			'autoloader'         => null,
			// Whether to run at all.
			'enabled'            => ! ( defined( 'BASIC_FIREWALL_ENABLED' ) && false === BASIC_FIREWALL_ENABLED ),
			// Addresses permitted to declare the client address.
			'trusted_proxies'    => defined( 'BASIC_FIREWALL_TRUSTED_PROXIES' ) ? BASIC_FIREWALL_TRUSTED_PROXIES : array(),
			// Directories a %file() token may read a secret from.
			'secret_directories' => defined( 'BASIC_FIREWALL_SECRET_DIRECTORIES' ) ? BASIC_FIREWALL_SECRET_DIRECTORIES : array(),
			// Runtime overrides, as Symfony property-access paths.
			'overrides'          => array(),
			// True on a multisite network, where this path steps aside for
			// the mu-plugin. MULTISITE and SUBDOMAIN_INSTALL say so as well.
			'multisite'          => false,
			// Seconds a "did not evaluate" warning stays quiet once logged.
			// See basic_firewall_warn_once().
			'warn_interval'      => 900,
			// Seconds the same fail-open stays quiet once logged, counting
			// the ones held back. See basic_firewall_warn_throttled().
			'fail_open_interval' => 60,
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
	 * @return array{enabled: bool, redact: list<string>, defer_login: bool}
	 */
	function basic_firewall_runtime( array $options ) {
		$runtime = array(
			'enabled'     => true,
			'redact'      => array(),
			'defer_login' => false,
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

		if ( true === ( $decoded['defer_login'] ?? false ) ) {
			$runtime['defer_login'] = true;
		}

		foreach ( is_array( $decoded['redact'] ?? null ) ? $decoded['redact'] : array() as $name ) {
			if ( is_string( $name ) && '' !== $name ) {
				$runtime['redact'][] = $name;
			}
		}

		return $runtime;
	}

	/**
	 * Whether this request carries something named like a WordPress login cookie.
	 *
	 * Asked of the plugin's own Role_Bypass, loaded by hand, so the two paths
	 * cannot disagree about which requests wait for the runner. If it cannot
	 * be loaded the answer is no, and the request is evaluated here as it
	 * would be with no role exempt -- a missed exemption, never a missed
	 * evaluation.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return bool
	 */
	function basic_firewall_carries_login_cookie( array $options ) {
		$class = 'Kanopi\\BasicFirewall\\Runtime\\Role_Bypass';

		if ( ! class_exists( $class, false ) ) {
			$file = rtrim( (string) $options['plugin_path'], '/' ) . '/src/Runtime/Role_Bypass.php';

			if ( ! is_readable( $file ) ) {
				return false;
			}

			require_once $file;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- only the cookie names are read, and only compared.
		return class_exists( $class, false ) && (bool) call_user_func( array( $class, 'carries_login_cookie' ), $_COOKIE );
	}

	/**
	 * Redact the site's own names from the log, as well as the library's.
	 *
	 * The same class the runner uses, loaded by hand for the reason
	 * Decision_Dispatcher is. One that cannot be loaded leaves the library's
	 * defaults in place, which is less redaction and never a failed request.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 * @param list<string>         $names   Names from the runtime sidecar.
	 *
	 * @return void
	 */
	function basic_firewall_apply_redaction( array $options, array $names ) {
		if ( array() === $names ) {
			return;
		}

		$class = 'Kanopi\\BasicFirewall\\Logging\\Redaction';

		try {
			if ( ! class_exists( $class, false ) ) {
				$file = rtrim( (string) $options['plugin_path'], '/' ) . '/src/Logging/Redaction.php';

				if ( ! is_readable( $file ) ) {
					return;
				}

				require_once $file;
			}

			call_user_func( array( $class, 'apply' ), $names );
		} catch ( \Throwable $e ) {
			return;
		}
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
	 * Kept for anything that called it before the resolver existed. It answers
	 * with the file basic_firewall_resolve_autoloader() would require, or null
	 * when that would require nothing.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return string|null
	 */
	function basic_firewall_autoloader( array $options ) {
		$resolved = basic_firewall_resolve_autoloader( basic_firewall_options( $options ) );

		return 'unreadable' === $resolved['source'] ? null : $resolved['file'];
	}

	/**
	 * Decide which Composer autoloader this path requires, if any.
	 *
	 * In this order, and the order is the point:
	 *
	 * 1. `plugin` -- the plugin's own `vendor/autoload.php`. The release zip
	 *    carries the library there, scoped under this plugin's prefix, and
	 *    the compiled file it writes names the prefixed classes. It wins over
	 *    anything a site names, for the reason the scoped copy wins in
	 *    basic_firewall_library_prefix(): a firewall built from some other
	 *    copy cannot read its own configuration.
	 * 2. `option` -- the `autoloader` the snippet passes. A site whose
	 *    Composer `vendor-dir` is somewhere this file cannot guess -- say
	 *    `web/wp-content/mu-plugins/vendor` -- says where here.
	 * 3. `constant` -- BASIC_FIREWALL_AUTOLOADER, for the same thing said once
	 *    per environment. The option beats it because it is the more local of
	 *    the two, which is how every other option here treats its constant:
	 *    trusted_proxies and secret_directories default to theirs, and a
	 *    value passed in the call replaces it.
	 * 4. `loaded` -- nothing to require, because the library is already
	 *    loadable: wp-config.php required the site's autoloader above the
	 *    snippet. Asked before the guessed locations, not after (#44). A
	 *    site whose wp-config.php loads one Composer tree while a different
	 *    `vendor/` sits beside the WordPress root used to have the second
	 *    required on top of the first, and classes could then resolve from
	 *    either tree -- the mixed-copy firewall #21 and #36 worked to rule
	 *    out. Whatever the site chose to load comes first.
	 * 5. `site` -- the Composer layouts this file can guess: a vendor
	 *    directory beside the WordPress root, where Bedrock and most
	 *    `composer create-project` sites keep it.
	 *
	 * A named autoloader that cannot be read is `unreadable`, and nothing
	 * after it is tried. Falling through to a guessed location would run the
	 * firewall from a vendor tree nobody chose -- or, more likely, run it from
	 * nowhere and report `no-autoloader` about a site that did name one -- and
	 * a path somebody wrote down being wrong is exactly what the status
	 * screens should say. `none` is nothing named, nothing found and nothing
	 * loaded.
	 *
	 * `named` is `option` or `constant` whenever the site named one, used or
	 * not, so a report of an unreadable file can say which line to correct.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return array{source: string, file: string|null, named: string|null}
	 */
	function basic_firewall_resolve_autoloader( array $options ) {
		$own   = rtrim( (string) $options['plugin_path'], '/' ) . '/vendor/autoload.php';
		$named = basic_firewall_named_autoloader( $options );

		if ( is_readable( $own ) ) {
			return array(
				'source' => 'plugin',
				'file'   => $own,
				'named'  => null === $named ? null : $named['source'],
			);
		}

		if ( null !== $named ) {
			return array(
				'source' => is_readable( $named['file'] ) ? $named['source'] : 'unreadable',
				'file'   => $named['file'],
				'named'  => $named['source'],
			);
		}

		/*
		 * Already loadable, so nothing more is required. Asked with autoloading
		 * on, so an autoloader wp-config.php registered above the snippet gets
		 * its say; the plugin's own tree, which would carry the scoped copy,
		 * was not there, so this cannot be preferring a foreign copy to it.
		 */
		if ( null !== basic_firewall_library_prefix() ) {
			return array(
				'source' => 'loaded',
				'file'   => null,
				'named'  => null,
			);
		}

		// A site-level Composer install, where the plugin is a dependency.
		if ( defined( 'ABSPATH' ) ) {
			foreach ( array( dirname( ABSPATH, 1 ) . '/vendor/autoload.php', ABSPATH . '../vendor/autoload.php' ) as $candidate ) {
				if ( is_readable( $candidate ) ) {
					return array(
						'source' => 'site',
						'file'   => $candidate,
						'named'  => null,
					);
				}
			}
		}

		return array(
			'source' => 'none',
			'file'   => null,
			'named'  => null,
		);
	}

	/**
	 * The autoloader the site named, and how it named it, or null for none.
	 *
	 * An empty or non-string value is not a name: a snippet passing
	 * `'autoloader' => ''` does not hide a constant, and a constant defined
	 * as something other than a path is treated as not defined.
	 *
	 * @param array<string, mixed> $options Bootstrap options.
	 *
	 * @return array{source: string, file: string}|null
	 */
	function basic_firewall_named_autoloader( array $options ) {
		$option = $options['autoloader'] ?? null;

		if ( is_string( $option ) && '' !== trim( $option ) ) {
			return array(
				'source' => 'option',
				'file'   => trim( $option ),
			);
		}

		$constant = defined( 'BASIC_FIREWALL_AUTOLOADER' ) ? constant( 'BASIC_FIREWALL_AUTOLOADER' ) : null;

		if ( is_string( $constant ) && '' !== trim( $constant ) ) {
			return array(
				'source' => 'constant',
				'file'   => trim( $constant ),
			);
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

		/*
		 * The Request of the copy the firewall is built from, and only that
		 * one. Setting it on the other copy's class leaves the firewall's own
		 * Request trusting nobody, so every visitor behind the proxy shares one
		 * address.
		 */
		$prefix = basic_firewall_library_prefix();

		foreach ( null === $prefix ? array() : array( $prefix . 'Symfony\\Component\\HttpFoundation\\Request' ) as $request_class ) {
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
		 * static analyser resolves it to one particular class: the prefix in
		 * front of it is decided at runtime.
		 */
		$token_class = implode( '\\', array( 'Kanopi', 'Firewall', 'Utility', 'TokenSubstitute' ) );
		$prefix      = basic_firewall_library_prefix();

		// The copy the firewall is built from; see basic_firewall_library_prefix().
		foreach ( null === $prefix ? array() : array( $prefix . $token_class ) as $class ) {
			$enable = array( $class, 'enableUnsafeProcessors' );

			if ( ! class_exists( $class ) || ! is_callable( $enable ) ) {
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
				call_user_func( $enable, array( 'file' ), $clean );
			} catch ( \Throwable $e ) {
				// An allowlist that does not resolve is treated as not having
				// opted in, rather than as permission for everything.
				return;
			}

			return;
		}
	}
}
