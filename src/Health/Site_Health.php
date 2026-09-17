<?php
/**
 * Site Health tests.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Health;

use Kanopi\BasicFirewall\Install\Activator;
use Kanopi\BasicFirewall\Install\Upgrader;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Runner;
use Kanopi\BasicFirewall\Runtime\Trusted_Proxies;

/**
 * The translation of `hook_requirements()` and the Drupal status report.
 *
 * This is where the plugin's whole failure posture lands. The firewall fails
 * open by design -- a misconfiguration must never be the reason a site is
 * unreachable -- and the entire justification for that choice is that the
 * failure is reported loudly instead. If these tests are quiet when something is
 * wrong, the fail-open becomes a silent no-op and the plugin is worse than not
 * installed.
 *
 * Anything at Error severity also raises an admin notice, because Site Health is
 * a page nobody visits until they already suspect something.
 */
final class Site_Health {

	/**
	 * Register the tests and the notice.
	 */
	public static function register(): void {
		add_filter( 'site_status_tests', array( self::class, 'add_tests' ) );
		add_action( 'admin_notices', array( self::class, 'render_notice' ) );
	}

	/**
	 * Add the firewall's tests.
	 *
	 * @param array<string, mixed> $tests Registered tests.
	 *
	 * @return array<string, mixed>
	 */
	public static function add_tests( array $tests ): array {
		foreach ( self::test_map() as $key => $label ) {
			$tests['direct'][ 'basic_firewall_' . $key ] = array(
				'label' => $label,
				'test'  => static fn (): array => self::render( $key ),
			);
		}

		return $tests;
	}

	/**
	 * The tests this plugin contributes.
	 *
	 * @return array<string, string>
	 */
	private static function test_map(): array {
		return array(
			'library'     => __( 'Basic Firewall library', 'basic-firewall' ),
			'backends'    => __( 'Basic Firewall backends', 'basic-firewall' ),
			'compiled'    => __( 'Basic Firewall compiled configuration', 'basic-firewall' ),
			'private_dir' => __( 'Basic Firewall private directory', 'basic-firewall' ),
			'bootstrap'   => __( 'Basic Firewall wp-config.php snippet', 'basic-firewall' ),
			'evaluation'  => __( 'Basic Firewall evaluation point', 'basic-firewall' ),
			'proxy'       => __( 'Basic Firewall client IP', 'basic-firewall' ),
			'mode'        => __( 'Basic Firewall operating mode', 'basic-firewall' ),
			'storage'     => __( 'Basic Firewall block list storage', 'basic-firewall' ),
			'logging'     => __( 'Basic Firewall logging', 'basic-firewall' ),
			'upgrade'     => __( 'Basic Firewall upgrades', 'basic-firewall' ),
		);
	}

	/**
	 * Every result, for the dashboard and the notice.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function results(): array {
		$results = array();

		foreach ( array_keys( self::test_map() ) as $key ) {
			$results[ $key ] = self::check( $key );
		}

		return $results;
	}

	/**
	 * Run one check.
	 *
	 * @param string $key Test key.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	public static function check( string $key ): array {
		return match ( $key ) {
			'library'     => self::check_library(),
			'backends'    => self::check_backends(),
			'compiled'    => self::check_compiled(),
			'private_dir' => self::check_private_dir(),
			'bootstrap'   => self::check_bootstrap(),
			'evaluation'  => self::check_evaluation(),
			'proxy'       => self::check_proxy(),
			'mode'        => self::check_mode(),
			'storage'     => self::check_storage(),
			'logging'     => self::check_logging(),
			'upgrade'     => self::check_upgrade(),
			default       => self::ok( __( 'Unknown test', 'basic-firewall' ), '' ),
		};
	}

	/**
	 * Is the library present and usable?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_library(): array {
		if ( ! Library_Loader::is_usable() ) {
			return self::critical(
				__( 'The firewall library is not usable, so no traffic is being evaluated', 'basic-firewall' ),
				(string) Library_Loader::failure()
			);
		}

		$capabilities = new Library_Capabilities();
		$missing      = $capabilities->unavailable();

		$description = sprintf(
			/* translators: 1: library version, 2: how it was loaded. */
			__( 'kanopi/firewall %1$s is loaded (%2$s).', 'basic-firewall' ),
			(string) Library_Loader::version(),
			(string) Library_Loader::mode()
		);

		if ( ! Library_Loader::is_collision_safe() ) {
			/*
			 * Recommended rather than an error. An unscoped vendor tree works
			 * perfectly until another plugin vendors the same library, and this
			 * is the only warning anybody will get before that happens.
			 */
			$description .= ' ' . __( 'This build shares the library\'s namespace with the rest of the site. If another plugin also bundles kanopi/firewall, whichever autoloader registers first wins and this plugin may run against a version it was not tested on. Release builds are namespace-scoped and immune to this.', 'basic-firewall' );
		}

		if ( array() !== $missing ) {
			$lines = array();

			foreach ( $missing as $item ) {
				$lines[] = sprintf( '<li><strong>%s</strong> — %s</li>', esc_html( $item['feature'] ), esc_html( $item['reason'] ) );
			}

			return self::recommended(
				__( 'Some firewall features are not available in the installed library', 'basic-firewall' ),
				$description . '<ul>' . implode( '', $lines ) . '</ul>'
			);
		}

		return self::ok( __( 'The firewall library is installed and complete', 'basic-firewall' ), $description );
	}

	/**
	 * Is there a compiled configuration?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_compiled(): array {
		$plugin   = Plugin::instance();
		$compiled = $plugin->compiled();

		if ( ! $compiled->exists() ) {
			return self::critical(
				__( 'There is no compiled configuration, so no rules are being enforced', 'basic-firewall' ),
				__( 'The firewall reads its rules from a compiled file, and that file is missing. Every request is currently being allowed through. Rebuild the firewall to recreate it.', 'basic-firewall' ),
				self::rebuild_action()
			);
		}

		$meta     = $compiled->meta();
		$problems = (array) ( $meta['problems'] ?? array() );

		if ( array() !== $problems ) {
			$lines = array();

			foreach ( $problems as $problem ) {
				$lines[] = '<li>' . esc_html( (string) $problem ) . '</li>';
			}

			return self::critical(
				__( 'The firewall compiled with problems, and is enforcing less than is configured', 'basic-firewall' ),
				'<ul>' . implode( '', $lines ) . '</ul>',
				self::rebuild_action()
			);
		}

		$failure = Runner::failure();

		if ( null !== $failure ) {
			return self::critical(
				__( 'The firewall could not evaluate this request', 'basic-firewall' ),
				esc_html( $failure ),
				self::rebuild_action()
			);
		}

		return self::ok(
			__( 'The firewall has a compiled configuration', 'basic-firewall' ),
			sprintf(
				/* translators: 1: rule count, 2: preset count. */
				esc_html__( '%1$d rule(s) and %2$d preset(s) are compiled and being enforced.', 'basic-firewall' ),
				count( (array) $plugin->settings()->get( 'rules', array() ) ),
				count( (array) $plugin->settings()->get( 'presets', array() ) )
			)
		);
	}

	/**
	 * Is the private directory actually private?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_private_dir(): array {
		$paths    = Plugin::instance()->paths();
		$problems = $paths->ensure();

		if ( array() !== $problems ) {
			return self::critical(
				__( 'The firewall cannot write to its private directory', 'basic-firewall' ),
				'<ul><li>' . implode( '</li><li>', array_map( 'esc_html', $problems ) ) . '</li></ul>'
			);
		}

		$probe = $paths->probe_reachability();

		if ( 'exposed' === $probe['status'] ) {
			/*
			 * Critical, and it is the one test most likely to fire on a stock
			 * install. WordPress has no private file system: .htaccess and
			 * web.config are inert on nginx, and index.php only stops a
			 * directory listing. What is exposed is the block list, the firewall
			 * logs and the compiled configuration.
			 */
			return self::critical(
				__( 'The firewall\'s private directory can be read over the web', 'basic-firewall' ),
				'<p>' . esc_html( $probe['message'] ) . '</p>'
				. '<p>' . esc_html__( 'WordPress has no private file directory, so the plugin writes .htaccess and web.config guards — neither of which nginx reads. The directory name carries a random suffix, which makes it hard to guess but is not a substitute for denying access.', 'basic-firewall' ) . '</p>'
				. '<p>' . esc_html__( 'Fix it either by denying access to the directory in your web server configuration, or by moving it outside the web root with the basic_firewall_private_path filter.', 'basic-firewall' ) . '</p>'
				. '<pre># nginx' . "\n" . 'location ~* /' . esc_html( basename( $paths->base() ) ) . '/ { deny all; return 404; }</pre>'
			);
		}

		if ( 'unknown' === $probe['status'] ) {
			return self::recommended(
				__( 'The firewall could not confirm its private directory is protected', 'basic-firewall' ),
				esc_html( $probe['message'] )
			);
		}

		return self::ok(
			__( 'The firewall\'s private directory is not readable over the web', 'basic-firewall' ),
			esc_html( $probe['message'] )
		);
	}

	/**
	 * Is anything running without the store it was configured with?
	 *
	 * Library 2.28.0 and 2.29.0 changed what happens when a backend cannot be
	 * reached. A log destination that does not exist, and Redis on a host
	 * without `ext-redis`, used to stop the firewall starting -- which in the
	 * default blocking mode is not log-only operation, it is no protection at
	 * all. Both now degrade instead, which is the right call and moves the
	 * problem: the site runs, and nothing says it is running without its logs.
	 *
	 * This is what says so. Recommended rather than critical, because the
	 * firewall is still evaluating and still refusing -- what is lost is the
	 * record of it, or in the storage case the durability of it, and the site
	 * being up is not the emergency.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_backends(): array {
		$degraded = Plugin::instance()->runner()->degraded_backends();

		if ( array() === $degraded ) {
			return self::ok(
				__( 'Every firewall backend is reachable', 'basic-firewall' ),
				esc_html__( 'Storage, logging and any rule that keeps its own state are all using what they were configured with.', 'basic-firewall' )
			);
		}

		$lines = '';

		foreach ( $degraded as $entry ) {
			$lines .= sprintf(
				'<li><strong>%s</strong> — %s<br><code>%s</code></li>',
				esc_html( (string) ( $entry['component'] ?? '' ) ),
				esc_html( (string) ( $entry['backend'] ?? '' ) ),
				esc_html( (string) ( $entry['error'] ?? '' ) )
			);
		}

		return self::recommended(
			sprintf(
				/* translators: %d: number of backends. */
				_n(
					'%d firewall backend is running without its store',
					'%d firewall backends are running without their stores',
					count( $degraded ),
					'basic-firewall'
				),
				count( $degraded )
			),
			'<p>' . esc_html__( 'The firewall is still evaluating and still refusing requests. What is degraded is what it does around that — writing a log, or keeping a block list somewhere it survives.', 'basic-firewall' ) . '</p>'
			. '<ul>' . $lines . '</ul>'
			. '<p>' . esc_html__( 'Earlier library versions refused to start for these, which on a blocking site meant no protection at all rather than reduced protection. They degrade now, which is why this check exists.', 'basic-firewall' ) . '</p>'
		);
	}

	/**
	 * Is the snippet in wp-config.php?
	 *
	 * Deliberately narrow, and deliberately separate from the evaluation point.
	 * That test answers "where does this run", which folds together three
	 * independent things -- the snippet, the mu-plugin loader and any page
	 * cache -- and so can report a healthy site while the one item somebody is
	 * actually looking for is missing. This answers one question.
	 *
	 * The runtime signal is the truth: a snippet sitting in a file nobody loads
	 * protects nothing. But when it has not run, the file is read as well,
	 * because "you never added it" and "you added it and it did not run" are
	 * different problems with different fixes, and guessing between them is
	 * what makes this hard to act on.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_bootstrap(): array {
		if ( self::early_path_active() ) {
			return self::ok(
				__( 'wp-config.php calls the firewall', 'basic-firewall' ),
				esc_html__( 'The bootstrap snippet is present and running, so requests are evaluated before WordPress loads. Nothing to add.', 'basic-firewall' )
			);
		}

		$in_file = self::snippet_is_in_wp_config();

		if ( true === $in_file ) {
			return self::critical(
				__( 'The wp-config.php snippet is in the file but did not run', 'basic-firewall' ),
				'<p>' . esc_html__( 'wp-config.php contains a call to the firewall bootstrap, but it did not execute on this request. The usual causes are a conditional around it that is false, an early exit or return above it, or the call sitting below the line that requires wp-settings.php — by which point WordPress has already booted and there is nothing left to skip.', 'basic-firewall' ) . '</p>'
				. '<p>' . esc_html__( 'The firewall is still running from its mu-plugin, so the site is protected. What is lost is everything the snippet was added for.', 'basic-firewall' ) . '</p>'
			);
		}

		$description = '<p>' . esc_html__( 'The firewall is running, but from an mu-plugin rather than from wp-config.php. That is later than it needs to be: a page cache serves from advanced-cache.php, which WordPress loads before any plugin, so a cache hit is never evaluated — and on a busy cached site that is most of your traffic.', 'basic-firewall' ) . '</p>'
			. '<p>' . esc_html__( 'Add this to wp-config.php, below the DB_NAME, DB_USER, DB_PASSWORD and DB_HOST definitions and immediately above the line that requires wp-settings.php:', 'basic-firewall' ) . '</p>'
			. '<pre>' . esc_html( self::bootstrap_snippet() ) . '</pre>';

		if ( false === $in_file ) {
			return self::recommended(
				__( 'wp-config.php does not call the firewall', 'basic-firewall' ),
				$description
			);
		}

		// The file could not be read, so absence is not proof of absence.
		return self::recommended(
			__( 'wp-config.php does not appear to call the firewall', 'basic-firewall' ),
			$description
			. '<p>' . esc_html__( 'wp-config.php itself could not be read to confirm this, so this is based only on the snippet not having run.', 'basic-firewall' ) . '</p>'
		);
	}

	/**
	 * Whether wp-config.php mentions the bootstrap, or null if it cannot be read.
	 *
	 * Both standard locations are tried: beside WordPress, and one level above
	 * it, which is where a wp-config.php lives on every install that keeps the
	 * core files in their own directory.
	 */
	private static function snippet_is_in_wp_config(): ?bool {
		$candidates = array(
			ABSPATH . 'wp-config.php',
			dirname( ABSPATH ) . '/wp-config.php',
		);

		foreach ( $candidates as $candidate ) {
			if ( ! is_readable( $candidate ) ) {
				continue;
			}

			$contents = file_get_contents( $candidate ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, and this runs before WP_Filesystem is guaranteed.

			if ( false === $contents ) {
				continue;
			}

			return false !== strpos( $contents, 'basic_firewall_evaluate' );
		}

		return null;
	}

	/**
	 * How early does the firewall run?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_evaluation(): array {
		$mu_installed = is_readable( WPMU_PLUGIN_DIR . '/basic-firewall-loader.php' );
		$mu_error     = get_option( Activator::MU_FAILURE_OPTION, '' );
		$early        = self::early_path_active();
		$cache        = self::detect_page_cache();

		if ( $early && ! self::early_report()['evaluated'] && 'disabled' !== self::early_report()['reason'] ) {
			/*
			 * The snippet is there and running, and this request still was not
			 * evaluated by it. Reported rather than folded into the healthy
			 * branch, because everything visible says the firewall runs before
			 * WordPress while in fact the mu-plugin is quietly picking up every
			 * request -- which is the exact configuration somebody added the
			 * snippet to avoid, and a page cache defeats it entirely.
			 *
			 * `disabled` is excluded on purpose. BASIC_FIREWALL_ENABLED stops
			 * both paths, so the sentence below -- that the mu-plugin is
			 * covering for this one -- would be false, and the operating mode
			 * test already reports that state and names the constant. Two
			 * checks describing one cause, one of them wrongly, is worse than
			 * the check that was missing.
			 */
			return self::critical(
				__( 'The wp-config.php snippet is present but is not evaluating requests', 'basic-firewall' ),
				'<p>' . esc_html__( 'wp-config.php calls the firewall bootstrap, but it returned without evaluating this request. Whatever protection you have is coming from the mu-plugin instead, which loads after advanced-cache.php — so on a cached site, a cache hit is not evaluated at all.', 'basic-firewall' ) . '</p>'
				. '<p>' . esc_html( self::early_reason_text( self::early_report()['reason'] ) ) . '</p>'
				. self::rebuild_action()
			);
		}

		if ( $early ) {
			$where = '<p>' . esc_html__( 'wp-config.php calls the firewall bootstrap, which is the earliest any PHP on this site can act. A page cache cannot serve a request without it being evaluated first.', 'basic-firewall' )
				. ' ' . (
					self::early_path_has_credentials()
						? esc_html__( 'The bootstrap sits below wp-config.php\'s DB_ constants, so database-backed block storage works on this path too.', 'basic-firewall' )
						: esc_html__( 'The bootstrap sits above wp-config.php\'s DB_ constants. That is fine for file storage, which needs no connection, but database-backed block storage cannot be reached from this path — move the snippet below them before switching to it.', 'basic-firewall' )
				) . '</p>';

			/*
			 * The fallback is reported even though it is not in use, because
			 * this branch used to return before the mu-plugin was ever looked
			 * at. A loader deleted by a deployment, a restore, or a host that
			 * rewrites wp-config.php left the site one overwrite away from
			 * evaluating at plugins_loaded, and nothing anywhere said so --
			 * the early path supersedes the loader, so every screen went on
			 * reporting the better answer.
			 */
			if ( ! $mu_installed ) {
				return self::recommended(
					__( 'The firewall evaluates before WordPress loads, but its fallback is missing', 'basic-firewall' ),
					$where
					. '<p>' . esc_html__( 'The mu-plugin loader is not installed. Nothing is wrong with the site as it stands — the wp-config.php path supersedes the loader, and is earlier than it. What is missing is what happens if that snippet goes away: a deployment that overwrites wp-config.php, a restore from a backup taken before it was added, or a host that regenerates the file. Without the loader the firewall drops to plugins_loaded, which still works and looks identical from these screens.', 'basic-firewall' ) . '</p>'
					. ( is_string( $mu_error ) && '' !== $mu_error ? '<p>' . esc_html( $mu_error ) . '</p>' : '' )
					. '<p>' . esc_html__( 'Deactivating and reactivating the plugin reinstalls it.', 'basic-firewall' ) . '</p>'
				);
			}

			return self::ok(
				__( 'The firewall evaluates before WordPress loads', 'basic-firewall' ),
				$where . '<p>' . esc_html__( 'The mu-plugin loader is installed as well, so evaluation stays early even if the wp-config.php snippet is ever removed.', 'basic-firewall' ) . '</p>'
			);
		}

		if ( ! $mu_installed ) {
			return self::critical(
				__( 'The firewall is running later than it should', 'basic-firewall' ),
				'<p>' . esc_html__( 'The mu-plugin loader is not installed, so the firewall only evaluates once all plugins have loaded. It still works, but it is doing more of WordPress\'s work before rejecting traffic it is going to reject anyway.', 'basic-firewall' ) . '</p>'
				. ( is_string( $mu_error ) && '' !== $mu_error ? '<p>' . esc_html( $mu_error ) . '</p>' : '' )
				. '<p>' . esc_html__( 'Deactivating and reactivating the plugin will try again.', 'basic-firewall' ) . '</p>'
			);
		}

		if ( null !== $cache ) {
			/*
			 * The important one. An mu-plugin loads after advanced-cache.php,
			 * which serves the cached response and exits -- so on a cached site
			 * the normal path never runs for a cache hit, which is most traffic.
			 */
			return self::recommended(
				__( 'A page cache is serving requests before the firewall sees them', 'basic-firewall' ),
				'<p>' . sprintf(
					/* translators: %s: the detected cache. */
					esc_html__( '%s serves cached pages from advanced-cache.php, which WordPress loads before any plugin — including the firewall\'s mu-plugin loader. A cache hit is therefore never evaluated, which is most of your traffic and exactly the traffic you have a firewall for.', 'basic-firewall' ),
					esc_html( $cache )
				) . '</p>'
				. '<p>' . esc_html__( 'Add this to wp-config.php, after any BASIC_FIREWALL_ constants and immediately before the line that requires wp-settings.php:', 'basic-firewall' ) . '</p>'
				. '<pre>' . esc_html( self::bootstrap_snippet() ) . '</pre>'
				. '<p>' . esc_html__( 'Placement matters: below the DB_NAME, DB_USER, DB_PASSWORD and DB_HOST definitions, and immediately above the wp-settings.php line. Below them, database-backed block storage keeps working on this path; above them, it cannot be reached and the firewall fails open.', 'basic-firewall' ) . '</p>'
			);
		}

		return self::ok(
			__( 'The firewall evaluates before plugins and the theme load', 'basic-firewall' ),
			esc_html__( 'The mu-plugin loader is installed, so requests are evaluated as early as a plugin can act. No page cache was detected in front of it.', 'basic-firewall' )
			. ' ' . esc_html__( 'If you later add one, this test will tell you to move the firewall earlier still.', 'basic-firewall' )
		);
	}

	/**
	 * Whether wp-config.php is calling the bootstrap.
	 */
	private static function early_path_active(): bool {
		return true === ( self::early_report()['called'] ?? false );
	}

	/**
	 * What the wp-config.php bootstrap recorded about its own run.
	 *
	 * The bootstrap is the only thing that can answer these questions, so it
	 * answers them as its first act and leaves the result here.
	 *
	 * The previous test was `defined( 'BASIC_FIREWALL_EVALUATED' ) &&
	 * function_exists( 'basic_firewall_evaluate' )`, and it was wrong in a way
	 * that mattered: `function_exists()` only proves the `require_once` line
	 * ran, and the constant is set by the mu-plugin runner as readily as by the
	 * bootstrap. A wp-config.php carrying the require without the call — half a
	 * pasted snippet — therefore reported a healthy early path that did not
	 * exist, about the single most consequential setting this plugin has.
	 *
	 * Public because it is a statement of fact rather than a judgement, and the
	 * CLI's `status` command needs the same answer. It had been reading
	 * `defined( 'BASIC_FIREWALL_EVALUATED' )` directly and inherited exactly the
	 * bug described above -- reporting the early path as active on a site whose
	 * wp-config.php said nothing about the firewall at all.
	 *
	 * @return array{called: bool, credentials: bool, evaluated: bool, reason: string|null}
	 */
	public static function early_report(): array {
		$report = $GLOBALS['basic_firewall_early'] ?? array();

		return array(
			'called'      => ! empty( $report['called'] ),
			'credentials' => ! empty( $report['credentials'] ),
			'evaluated'   => ! empty( $report['evaluated'] ),
			'reason'      => isset( $report['reason'] ) ? (string) $report['reason'] : null,
		);
	}

	/**
	 * Why the bootstrap ran but did not evaluate this request.
	 *
	 * @param string|null $reason Machine-readable reason recorded by the bootstrap.
	 */
	private static function early_reason_text( ?string $reason ): string {
		switch ( $reason ) {
			case 'disabled':
				return __( 'BASIC_FIREWALL_ENABLED is defined as false in wp-config.php, which switches the firewall off on both paths.', 'basic-firewall' );
			case 'no-compiled-file':
				return __( 'There is no compiled configuration at the path the snippet names. Either the private_path argument is wrong, or the firewall has never been built — the early path cannot build it, because that needs WordPress.', 'basic-firewall' );
			case 'no-autoloader':
				return __( 'The plugin\'s vendor autoloader could not be found, so the firewall library was never loaded.', 'basic-firewall' );
			case 'library-missing':
				return __( 'The firewall library class was not found after loading the autoloader, which usually means an incomplete install.', 'basic-firewall' );
			default:
				return __( 'The bootstrap returned without evaluating and did not say why.', 'basic-firewall' );
		}
	}

	/**
	 * Whether the bootstrap sits below wp-config.php's DB_ constants.
	 *
	 * A question about placement, and only that. The constants are read here
	 * after WordPress has loaded, so by now they are always defined -- what
	 * matters is whether they existed at the moment the bootstrap ran, which
	 * only the bootstrap is in a position to answer. It records the answer in a
	 * global as its first act.
	 */
	private static function early_path_has_credentials(): bool {
		return self::early_report()['credentials'];
	}

	/**
	 * Whether the early path can actually build a database connection.
	 *
	 * Placement *and* the sidecar naming the injection paths, because the
	 * option holding the same list needs a WordPress the early path has not
	 * got. Only meaningful when database storage is selected: file storage
	 * needs no connection, so no sidecar is written and its absence is correct
	 * rather than a fault. Asking this question of a file-storage site reported
	 * a placement problem that did not exist.
	 */
	private static function early_path_reaches_database(): bool {
		return self::early_path_has_credentials()
			&& is_readable( Plugin::instance()->paths()->connection_paths_file() );
	}

	/**
	 * Detect a page cache in front of the plugin.
	 */
	private static function detect_page_cache(): ?string {
		if ( ! defined( 'WP_CACHE' ) || ! WP_CACHE ) {
			return null;
		}

		$dropin = WP_CONTENT_DIR . '/advanced-cache.php';

		if ( ! is_readable( $dropin ) ) {
			return null;
		}

		$contents = (string) file_get_contents( $dropin ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, not a remote URL; WP_Filesystem is not loaded this early.

		foreach ( array(
			'WP Super Cache'  => 'wp-super-cache',
			'W3 Total Cache'  => 'w3-total-cache',
			'Batcache'        => 'batcache',
			'WP Rocket'       => 'wp-rocket',
			'LiteSpeed Cache' => 'litespeed',
		) as $name => $needle ) {
			if ( false !== stripos( $contents, $needle ) ) {
				return $name;
			}
		}

		return __( 'A page cache drop-in', 'basic-firewall' );
	}

	/**
	 * The wp-config.php snippet, with this site's real path.
	 */
	public static function bootstrap_snippet(): string {
		return "require_once ABSPATH . 'wp-content/plugins/basic-firewall/bootstrap.php';\n"
			. "basic_firewall_evaluate( array(\n"
			. "    'private_path' => '" . Plugin::instance()->paths()->base() . "',\n"
			. ') );';
	}

	/**
	 * Can the client IP be trusted?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_proxy(): array {
		$answer     = (string) Plugin::instance()->settings()->get( 'global.behind_proxy', 'unknown' );
		$configured = Trusted_Proxies::are_configured();

		if ( $configured ) {
			return self::ok(
				__( 'The firewall can trust the client IP address', 'basic-firewall' ),
				sprintf(
					/* translators: %s: comma-separated list of trusted proxies. */
					esc_html__( 'Trusted proxies are configured (%s), so a forwarding header is honoured only from those addresses.', 'basic-firewall' ),
					esc_html( implode( ', ', Trusted_Proxies::configured() ) )
				)
			);
		}

		if ( 'yes' === $answer ) {
			return self::critical(
				__( 'This site is declared to be behind a proxy, but no trusted proxies are configured', 'basic-firewall' ),
				'<p>' . esc_html__( 'Every visitor currently appears to come from the proxy. One visitor\'s offense blocks everybody, a per-IP rate limit counts the whole site as one client, and an allow rule for your own address never matches.', 'basic-firewall' ) . '</p>'
				. '<p>' . esc_html__( 'Add the addresses of the proxies that front this site to wp-config.php:', 'basic-firewall' ) . '</p>'
				. '<pre>' . esc_html( self::proxy_snippet() ) . '</pre>'
			);
		}

		if ( Trusted_Proxies::request_carries_forwarding_header() && 'no' === $answer ) {
			/*
			 * The contradiction. Somebody answered "no proxy", which silences
			 * the warning, and a forwarding header turned up anyway.
			 */
			return self::recommended(
				__( 'This site is declared not to be behind a proxy, but a forwarding header arrived anyway', 'basic-firewall' ),
				esc_html__( 'Either something is proxying this site after all — in which case address-based rules are evaluating the proxy — or a client sent the header speculatively and it can be ignored. Worth establishing which.', 'basic-firewall' )
			);
		}

		if ( 'no' === $answer ) {
			return self::ok(
				__( 'This site is not behind a proxy', 'basic-firewall' ),
				esc_html__( 'Nothing can forge a forwarding header through a proxy that does not exist, so the client address is the connecting address.', 'basic-firewall' )
			);
		}

		$local = Trusted_Proxies::detect_local_stack();

		$description = '<p>' . esc_html__( 'Nobody has said whether this site is behind a proxy or a CDN, and no trusted proxies are configured. Until that is answered, every rule that looks at an address may be evaluating your load balancer rather than your visitor.', 'basic-firewall' ) . '</p>';

		if ( null !== $local ) {
			$description .= '<p>' . sprintf(
				/* translators: %s: the detected local development stack. */
				esc_html__( '%s was detected. It routes every request through a router container, so PHP sees the router and the real client only in X-Forwarded-For — the same shape as production, and it is not configured for you.', 'basic-firewall' ),
				esc_html( $local['stack'] )
			) . '</p>'
			. '<pre>' . esc_html( self::proxy_snippet( $local ) ) . '</pre>';
		}

		return self::recommended(
			__( 'Nobody has said whether this site is behind a proxy', 'basic-firewall' ),
			$description
		);
	}

	/**
	 * The wp-config.php snippet for trusted proxies.
	 *
	 * @param array{stack: string, range: string}|null $local Detected local stack.
	 */
	public static function proxy_snippet( ?array $local = null ): string {
		if ( null === $local ) {
			return "define( 'BASIC_FIREWALL_TRUSTED_PROXIES', array( '10.0.0.0/8' ) );";
		}

		return "// Guarded so it cannot follow this file to a real environment:\n"
			. "// a wide range on real hosting lets anything on the private\n"
			. "// network forge a client address.\n"
			. "if ( getenv( 'IS_DDEV_PROJECT' ) === 'true' ) {\n"
			. "    define( 'BASIC_FIREWALL_TRUSTED_PROXIES', array( '" . $local['range'] . "' ) );\n"
			. '}';
	}

	/**
	 * Is anything actually being blocked?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_mode(): array {
		$settings = Plugin::instance()->settings();
		$mode     = (string) $settings->get( 'global.mode', 'log' );

		if ( ! Plugin::instance()->runner()->is_enabled() ) {
			return self::recommended(
				__( 'The firewall is switched off', 'basic-firewall' ),
				esc_html__( 'No rules are being evaluated. This is either the enabled setting, or BASIC_FIREWALL_ENABLED set to false in wp-config.php.', 'basic-firewall' )
			);
		}

		$forced = defined( 'BASIC_FIREWALL_MODE' ) ? (string) constant( 'BASIC_FIREWALL_MODE' ) : null;

		if ( null !== $forced && $forced !== $mode ) {
			return self::recommended(
				__( 'The operating mode is being overridden in wp-config.php', 'basic-firewall' ),
				sprintf(
					/* translators: 1: forced mode, 2: configured mode. */
					esc_html__( 'BASIC_FIREWALL_MODE forces %1$s, so the %2$s configured in the admin screens is being ignored. Nobody should have to wonder why the setting they saved has no effect.', 'basic-firewall' ),
					esc_html( $forced ),
					esc_html( $mode )
				)
			);
		}

		$bypass = (array) $settings->get( 'global.bypass_roles', array() );

		if ( array() !== $bypass ) {
			return self::recommended(
				__( 'Some roles are exempt from the firewall', 'basic-firewall' ),
				sprintf(
					/* translators: %s: comma-separated role names. */
					esc_html__( 'No rule runs for members of: %s. Anyone who can grant one of those roles can exempt themselves, and an account takeover is unfiltered from that point on. An allow rule scoped to an address range leaves the rest of the firewall at full strength.', 'basic-firewall' ),
					esc_html( implode( ', ', array_map( 'strval', $bypass ) ) )
				)
			);
		}

		if ( 'log' === $mode ) {
			return self::recommended(
				__( 'The firewall is in log-only mode and is not blocking anything', 'basic-firewall' ),
				esc_html__( 'Rules are evaluated and every would-be block is recorded, but nothing is rejected. This is the shipped default, on purpose — read the log for a few days, and switch to Block once it is clean.', 'basic-firewall' )
			);
		}

		if ( 'disabled' === $mode ) {
			return self::recommended(
				__( 'The firewall is set to evaluate nothing', 'basic-firewall' ),
				esc_html__( 'The operating mode is "disabled", so no rules run at all.', 'basic-firewall' )
			);
		}

		return self::ok(
			__( 'The firewall is blocking matching requests', 'basic-firewall' ),
			esc_html__( 'Rules are evaluated and matching requests are rejected.', 'basic-firewall' )
		);
	}

	/**
	 * Does the block list survive?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_storage(): array {
		$settings = Plugin::instance()->settings();
		$backend  = (string) $settings->get( 'storage.backend', 'file' );

		if ( 'memory' === $backend ) {
			return self::critical(
				__( 'Block list storage is set to in-memory, so nothing ever stays blocked', 'basic-firewall' ),
				esc_html__( 'Every block is discarded when the request ends. The firewall evaluates its rules and throws the result away, while the interface reports it as enabled. Choose file or database storage.', 'basic-firewall' )
			);
		}

		if ( 'database' === $backend && self::early_path_active() && ! self::early_path_reaches_database() ) {
			/*
			 * The module's one documented fail-open -- but checked rather than
			 * assumed. In WordPress the early path can reach the database, so
			 * this fires only when it demonstrably cannot: the bootstrap was
			 * required above the DB_ constants, or the sidecar naming the
			 * injection paths is missing.
			 */
			return self::critical(
				__( 'Database block list storage is not reachable from the wp-config.php evaluation path', 'basic-firewall' ),
				'<p>' . esc_html__( 'The firewall fails open on every request through that path while reporting itself as enabled and blocking.', 'basic-firewall' ) . '</p>'
				. '<p>' . esc_html__( 'The usual cause is placement: the bootstrap must be required below the DB_NAME, DB_USER, DB_PASSWORD and DB_HOST definitions and immediately above the line that requires wp-settings.php. Required above them, there are no credentials to read.', 'basic-firewall' ) . '</p>'
				. '<pre>' . esc_html( self::bootstrap_snippet() ) . '</pre>'
				. '<p>' . esc_html__( 'If the placement is already right, rebuild the firewall — the list of injection points is written beside the compiled file, and this reports a failure when that file is missing. Switching to file storage also resolves it.', 'basic-firewall' ) . '</p>'
			);
		}

		$listing = Plugin::instance()->blocked()->all();

		if ( 'file' === $backend && $listing['supported'] && count( $listing['clients'] ) > 100 ) {
			return self::recommended(
				__( 'The block list has grown large enough for file storage to be costing you', 'basic-firewall' ),
				sprintf(
					/* translators: %d: number of blocked clients. */
					esc_html__( '%d clients are blocked. File storage looks up the block list in time proportional to its size, so it gets slower exactly when the firewall is busiest, while database storage stays flat. Switching does not move the existing list — clients blocked under file storage will not be blocked after the switch.', 'basic-firewall' ),
					count( $listing['clients'] )
				)
			);
		}

		return self::ok(
			__( 'Block list storage is configured', 'basic-firewall' ),
			sprintf(
				/* translators: 1: storage backend, 2: number of blocked clients. */
				esc_html__( 'Using %1$s storage, with %2$s currently blocked.', 'basic-firewall' ),
				esc_html( $backend ),
				$listing['supported'] ? (string) count( $listing['clients'] ) : esc_html__( 'an unknown number', 'basic-firewall' )
			)
		);
	}

	/**
	 * Is anything going to be enormous?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_logging(): array {
		$handlers = (array) Plugin::instance()->settings()->get( 'logger', array() );
		$debug    = array();

		foreach ( $handlers as $handler ) {
			if ( is_array( $handler ) && ! empty( $handler['enabled'] ) && 'debug' === ( $handler['level'] ?? '' ) ) {
				$debug[] = (string) ( $handler['type'] ?? 'unknown' );
			}
		}

		if ( array() !== $debug ) {
			return self::recommended(
				__( 'A firewall log handler is set to debug', 'basic-firewall' ),
				sprintf(
					/* translators: %s: comma-separated handler types. */
					esc_html__( '%s is logging at debug level. That records what every condition compared against, which is roughly 100 KB per allowed request on a file handler — about 97 MB per thousand requests. It is the right level for working out why a rule does or does not match, and the wrong one to leave on. Set it, reproduce the request, set it back.', 'basic-firewall' ),
					esc_html( implode( ', ', $debug ) )
				)
			);
		}

		$enabled = array_filter( $handlers, static fn ( $h ): bool => is_array( $h ) && ! empty( $h['enabled'] ) );

		if ( array() === $enabled && ! (bool) Plugin::instance()->settings()->get( 'logging.to_wordpress', false ) ) {
			return self::recommended(
				__( 'The firewall is not logging anywhere', 'basic-firewall' ),
				esc_html__( 'No log handler is enabled and events are not being forwarded to WordPress, so there is no record of what the firewall has blocked. That is a supported configuration, but it means the log-only workflow — watch for a few days, then switch to blocking — is not available to you.', 'basic-firewall' )
			);
		}

		return self::ok(
			__( 'The firewall is logging', 'basic-firewall' ),
			sprintf(
				/* translators: %d: number of enabled log handlers. */
				esc_html__( '%d log handler(s) enabled.', 'basic-firewall' ),
				count( $enabled )
			)
		);
	}

	/**
	 * Did the upgrade routines finish?
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_upgrade(): array {
		$failure = Upgrader::failure();

		if ( null !== $failure ) {
			return self::critical(
				__( 'A Basic Firewall upgrade did not complete', 'basic-firewall' ),
				esc_html( $failure )
			);
		}

		return self::ok(
			__( 'Basic Firewall is fully upgraded', 'basic-firewall' ),
			esc_html__( 'All upgrade routines have run.', 'basic-firewall' )
		);
	}

	/**
	 * A link to the rebuild control, which lives on the Compiled screen.
	 */
	private static function rebuild_action(): string {
		return sprintf(
			'<p><a href="%s" class="button button-primary">%s</a></p>',
			esc_url( admin_url( 'admin.php?page=basic-firewall-compiled' ) ),
			esc_html__( 'Rebuild the firewall', 'basic-firewall' )
		);
	}

	/**
	 * Build a passing result.
	 *
	 * @param string $label       Headline.
	 * @param string $description Body, already escaped.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function ok( string $label, string $description ): array {
		return self::result( 'good', $label, $description, '' );
	}

	/**
	 * Build a recommendation.
	 *
	 * @param string $label       Headline.
	 * @param string $description Body, already escaped.
	 * @param string $actions     Action markup.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function recommended( string $label, string $description, string $actions = '' ): array {
		return self::result( 'recommended', $label, $description, $actions );
	}

	/**
	 * Build an error.
	 *
	 * @param string $label       Headline.
	 * @param string $description Body, already escaped.
	 * @param string $actions     Action markup.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function critical( string $label, string $description, string $actions = '' ): array {
		return self::result( 'critical', $label, $description, $actions );
	}

	/**
	 * Assemble a result.
	 *
	 * @param string $status      One of good, recommended, critical.
	 * @param string $label       Headline.
	 * @param string $description Body, already escaped.
	 * @param string $actions     Action markup.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function result( string $status, string $label, string $description, string $actions ): array {
		return array(
			'status'      => $status,
			'label'       => $label,
			'description' => '' === $description ? '' : ( 0 === strpos( $description, '<' ) ? $description : '<p>' . $description . '</p>' ),
			'actions'     => $actions,
		);
	}

	/**
	 * Render a result for Site Health's own format.
	 *
	 * @param string $key Test key.
	 *
	 * @return array<string, mixed>
	 */
	private static function render( string $key ): array {
		$result = self::check( $key );

		return array(
			'label'       => $result['label'],
			'status'      => $result['status'],
			'badge'       => array(
				'label' => __( 'Security', 'basic-firewall' ),
				'color' => 'red',
			),
			'description' => $result['description'],
			'actions'     => $result['actions'],
			'test'        => 'basic_firewall_' . $key,
		);
	}

	/**
	 * Raise an admin notice for anything at Error severity.
	 *
	 * Site Health is a page nobody visits until they already suspect something,
	 * and the whole justification for failing open is that the failure is loud.
	 */
	public static function render_notice(): void {
		if ( ! current_user_can( 'manage_basic_firewall' ) ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;

		// Not on Site Health itself, where the same thing is already on screen.
		if ( null !== $screen && 'site-health' === $screen->id ) {
			return;
		}

		$critical = array();

		foreach ( self::results() as $result ) {
			if ( 'critical' === $result['status'] ) {
				$critical[] = $result['label'];
			}
		}

		if ( array() === $critical ) {
			return;
		}

		printf(
			'<div class="notice notice-error"><p><strong>%s</strong></p><ul style="list-style:disc;margin-left:2em">%s</ul><p><a href="%s">%s</a></p></div>',
			esc_html__( 'Basic Firewall needs attention', 'basic-firewall' ),
			wp_kses_post( '<li>' . implode( '</li><li>', array_map( 'esc_html', $critical ) ) . '</li>' ),
			esc_url( admin_url( 'site-health.php' ) ),
			esc_html__( 'Open Site Health for the details', 'basic-firewall' )
		);
	}
}
