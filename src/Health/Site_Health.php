<?php
/**
 * Site Health tests.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Health;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Install\Activator;
use Kanopi\BasicFirewall\Install\Mu_Loader;
use Kanopi\BasicFirewall\Install\Upgrader;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Request_Tester;
use Kanopi\BasicFirewall\RuleType\Types\Rate_Limit;
use Kanopi\BasicFirewall\RuleType\Types\User_Agent;
use Kanopi\BasicFirewall\Runtime\Diagnostics;
use Kanopi\BasicFirewall\Runtime\Runner;
use Kanopi\BasicFirewall\Runtime\Trusted_Proxies;
use Kanopi\BasicFirewall\Support\Autoloader_Locator;
use Kanopi\BasicFirewall\Support\Site_Layout;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Utility\RequestPath;
use Symfony\Component\Yaml\Yaml;

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
		/*
		 * Lockdown and the panic switch first. While either is in force, every
		 * other entry describes a firewall that is not the one running, and the
		 * dashboard's Checks table is read top to bottom.
		 */
		return array(
			'lockdown'     => __( 'Basic Firewall lockdown', 'basic-firewall' ),
			'panic'        => __( 'Basic Firewall panic switch', 'basic-firewall' ),
			'library'      => __( 'Basic Firewall library', 'basic-firewall' ),
			'backends'     => __( 'Basic Firewall backends', 'basic-firewall' ),
			'compiled'     => __( 'Basic Firewall compiled configuration', 'basic-firewall' ),
			'verification' => __( 'Basic Firewall crawler verification', 'basic-firewall' ),
			'rate_keys'    => __( 'Basic Firewall rate limit keys', 'basic-firewall' ),
			'request_path' => __( 'Basic Firewall request path', 'basic-firewall' ),
			'private_dir'  => __( 'Basic Firewall private directory', 'basic-firewall' ),
			'bootstrap'    => __( 'Basic Firewall wp-config.php snippet', 'basic-firewall' ),
			'evaluation'   => __( 'Basic Firewall evaluation point', 'basic-firewall' ),
			'proxy'        => __( 'Basic Firewall client IP', 'basic-firewall' ),
			'mode'         => __( 'Basic Firewall operating mode', 'basic-firewall' ),
			'storage'      => __( 'Basic Firewall block list storage', 'basic-firewall' ),
			'cache'        => __( 'Basic Firewall cache', 'basic-firewall' ),
			'logging'      => __( 'Basic Firewall logging', 'basic-firewall' ),
			'records'      => __( 'Basic Firewall block records', 'basic-firewall' ),
			'upgrade'      => __( 'Basic Firewall upgrades', 'basic-firewall' ),
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
			'lockdown'    => self::check_lockdown(),
			'panic'       => self::check_panic(),
			'library'     => self::check_library(),
			'backends'    => self::check_backends(),
			'compiled'    => self::check_compiled(),
			'verification' => self::check_verification(),
			'rate_keys'    => self::check_rate_keys(),
			'request_path' => self::check_request_path(),
			'private_dir' => self::check_private_dir(),
			'bootstrap'   => self::check_bootstrap(),
			'evaluation'  => self::check_evaluation(),
			'proxy'       => self::check_proxy(),
			'mode'        => self::check_mode(),
			'storage'     => self::check_storage(),
			'cache'       => self::check_cache(),
			'logging'     => self::check_logging(),
			'records'     => self::check_records(),
			'upgrade'     => self::check_upgrade(),
			default       => self::ok( __( 'Unknown test', 'basic-firewall' ), '' ),
		};
	}

	/**
	 * Is the site refusing everyone but a list?
	 *
	 * Critical, and first. While lockdown is on, no other entry here describes
	 * what the site does to traffic: every rule is moot, because a client not
	 * on the allowlist never reaches one. It is also the loudest thing the
	 * firewall can do and the easiest to forget, exactly like the panic switch
	 * it is often reached through.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_lockdown(): array {
		if ( ! Plugin::instance()->runner()->is_locked_down() ) {
			return self::ok(
				__( 'The site is not in lockdown', 'basic-firewall' ),
				esc_html__( 'Every visitor is evaluated against the rules as usual.', 'basic-firewall' )
			);
		}

		$allow = (array) Plugin::instance()->settings()->get( 'global.lockdown_allow', array() );

		return self::critical(
			sprintf(
				/* translators: %d: number of allowlisted addresses. */
				_n(
					'The site is in lockdown, serving only %d allowlisted entry',
					'The site is in lockdown, serving only %d allowlisted entries',
					count( $allow ),
					'basic-firewall'
				),
				count( $allow )
			),
			esc_html__( 'Every client except the lockdown allowlist is being refused, and none of them is being recorded. Your rules are not being consulted while this is on. Switch it off on the General screen — or, if a panic file saying "lockdown" armed it, remove the file.', 'basic-firewall' ),
			sprintf(
				'<p><a href="%s">%s</a></p>',
				esc_url( Admin::url( 'basic-firewall-general' ) ),
				esc_html__( 'Open the General screen', 'basic-firewall' )
			)
		);
	}

	/**
	 * Is a panic file changing what the firewall does?
	 *
	 * Critical while one is active, and that is deliberate. The realistic
	 * failure is not somebody flipping it -- it is nobody noticing three weeks
	 * later that the site has been in log mode since the incident. The file is
	 * the whole record that it happened, and nobody reads the firewall's log
	 * for a warning they do not know to look for, so this is where it is said
	 * -- and, being critical, in an admin notice on every screen as well.
	 *
	 * A file that exists and changed nothing is only a recommendation. Nothing
	 * is being overridden, so calling it critical would overstate it; but
	 * somebody reached for the switch and it did not take, and they are
	 * watching the site rather than the log to find that out.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_panic(): array {
		$panic = Plugin::instance()->runner()->panic_switch();

		if ( null !== $panic && $panic['active'] ) {
			return self::critical(
				sprintf(
					/* translators: %s: operating mode the panic file forces. */
					__( 'A panic file is forcing the firewall into %s mode', 'basic-firewall' ),
					$panic['effective']
				),
				sprintf(
					/* translators: 1: forced mode, 2: configured mode, 3: file path. */
					esc_html__( 'The operating mode is %1$s because a panic file says so. The configured mode is %2$s, and it returns the moment the file is removed: %3$s', 'basic-firewall' ),
					'<strong>' . esc_html( $panic['effective'] ) . '</strong>',
					'<strong>' . esc_html( $panic['configured'] ) . '</strong>',
					'<code>' . esc_html( (string) $panic['path'] ) . '</code>'
				)
			);
		}

		if ( null !== $panic ) {
			return self::recommended(
				__( 'A panic file is present but is being ignored', 'basic-firewall' ),
				sprintf(
					/* translators: 1: file path, 2: what is wrong with it. */
					esc_html__( 'The panic file %1$s %2$s, so the firewall is running in its configured mode. A panic file has to name one of block, log, exception, disabled or lockdown.', 'basic-firewall' ),
					'<code>' . esc_html( (string) $panic['path'] ) . '</code>',
					esc_html( (string) $panic['problem'] )
				)
			);
		}

		return self::ok(
			__( 'No panic file is overriding the firewall', 'basic-firewall' ),
			'' === trim( (string) Plugin::instance()->settings()->get( 'global.panic_file', '' ) )
				? esc_html__( 'No panic file is configured. One can be set on the General screen, so the firewall can be turned down mid-incident without a deploy.', 'basic-firewall' )
				: esc_html__( 'A panic file is configured and nothing is at its path, so the configured mode is in force.', 'basic-firewall' )
		);
	}

	/**
	 * How many query parameters WordPress puts secrets in are sitting in the
	 * block list.
	 *
	 * Library 2.31.0 stopped block records keeping cookies and most headers,
	 * because the block list is the artifact operators paste into tickets and a
	 * record outlives the request by the length of the ban. It deliberately kept
	 * the whole query string, and that is the right default: for a scanner --
	 * the commonest reason anybody reads a block record -- the query string *is*
	 * the attack.
	 *
	 * It is also the bucket WordPress is unusual about. `wp-login.php` and
	 * `wp-activate.php` put working secrets in query strings, so a blocked
	 * request to a password reset link stores a usable password reset. The
	 * library cannot know that; WordPress can, which is why the check is here
	 * rather than a note in its documentation.
	 *
	 * Narrowing `query` is not offered as the fix, because an allowlist cannot
	 * express "everything except this" and enumerating the parameters a scanner
	 * might use is the thing allowlists are bad at. Clearing the affected
	 * records is the honest instrument, and it is the operator's call because it
	 * unblocks whoever is in them.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_records(): array {
		$listing = Plugin::instance()->blocked()->all();

		if ( ! $listing['supported'] ) {
			return self::ok(
				__( 'Block records cannot be enumerated on this backend', 'basic-firewall' ),
				esc_html__( 'Nothing to report, and nothing to check: this storage backend cannot list what it holds.', 'basic-firewall' )
			);
		}

		$holding = 0;
		$stale   = 0;

		foreach ( $listing['clients'] as $client ) {
			$request = ( $client['record']['request'] ?? null );
			$request = is_string( $request ) ? json_decode( $request, true ) : $request;

			if ( ! is_array( $request ) ) {
				continue;
			}

			if ( self::holds_secret_query( (array) ( $request['query'] ?? array() ) ) ) {
				++$holding;
			}

			// Written before the allowlist existed. Redaction happens on the way
			// in, so these are unaffected by the setting and expire with their
			// bans.
			if ( array() !== (array) ( $request['cookies'] ?? array() ) ) {
				++$stale;
			}
		}

		if ( 0 === $holding && 0 === $stale ) {
			return self::ok(
				__( 'No block record is holding a credential', 'basic-firewall' ),
				esc_html(
					sprintf(
						/* translators: %d: number of block records. */
						_n(
							'%d block record was checked for a session cookie and for the query parameters WordPress puts secrets in.',
							'%d block records were checked for session cookies and for the query parameters WordPress puts secrets in.',
							count( $listing['clients'] ),
							'basic-firewall'
						),
						count( $listing['clients'] )
					)
				)
			);
		}

		$description = '';

		if ( $holding > 0 ) {
			$description .= '<p>' . esc_html(
				sprintf(
					/* translators: %d: number of block records. */
					_n(
						'%d block record holds a query parameter of the kind WordPress uses for a secret — a password reset key, an activation key, or an API token somebody put in a URL.',
						'%d block records hold query parameters of the kind WordPress uses for a secret — a password reset key, an activation key, or an API token somebody put in a URL.',
						$holding,
						'basic-firewall'
					),
					$holding
				)
			) . '</p>';

			$description .= '<p>' . esc_html__( 'A password reset key in the block list is a working password reset, for as long as the ban lasts. The block list is also what gets pasted into a ticket.', 'basic-firewall' ) . '</p>';
		}

		if ( $stale > 0 ) {
			$description .= '<p>' . esc_html(
				sprintf(
					/* translators: %d: number of block records. */
					_n(
						'%d block record still holds the cookies the visitor sent, including their session cookie. It was written before the allowlist existed and is unaffected by it, because redaction happens on the way in.',
						'%d block records still hold the cookies the visitor sent, including their session cookies. They were written before the allowlist existed and are unaffected by it, because redaction happens on the way in.',
						$stale,
						'basic-firewall'
					),
					$stale
				)
			) . '</p>';
		}

		$description .= '<p>' . esc_html__( 'These expire with their bans. Clearing the block list removes them sooner, at the cost of unblocking whoever is currently in it.', 'basic-firewall' ) . '</p>';

		return self::recommended(
			__( 'Block records are holding credentials somebody sent', 'basic-firewall' ),
			$description,
			sprintf(
				'<p><a href="%s">%s</a></p>',
				esc_url( admin_url( 'admin.php?page=basic-firewall-blocked' ) ),
				esc_html__( 'Review the block list', 'basic-firewall' )
			)
		);
	}

	/**
	 * Whether a recorded query string carries something WordPress treats as a
	 * secret.
	 *
	 * Named rather than pattern-matched, and kept short. `_wpnonce` is
	 * deliberately absent: it is on a large share of admin URLs, it is bound to
	 * one user and one action, and flagging it would fire on every scan of
	 * `admin-ajax.php` until nobody read this check any more.
	 *
	 * @param array<array-key, mixed> $query Recorded query parameters.
	 */
	private static function holds_secret_query( array $query ): bool {
		$secrets = array(
			// wp-login.php?action=rp&key=... and wp-activate.php?key=...
			'key',
			'token',
			'access_token',
			'api_key',
			'apikey',
			'secret',
			'password',
			'pwd',
		);

		foreach ( array_keys( $query ) as $name ) {
			if ( in_array( strtolower( (string) $name ), $secrets, true ) ) {
				return true;
			}
		}

		return false;
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
			self::compiled_summary(
				(array) $plugin->settings()->get( 'rules', array() ),
				count( (array) $plugin->settings()->get( 'presets', array() ) )
			)
		);
	}

	/**
	 * What a clean compile holds, counted the way the compiler counts it.
	 *
	 * Every stored rule used to be counted as "compiled and being enforced".
	 * The compiler skips a disabled rule before anything else, so a site with
	 * one rule switched on and nine switched off was told ten were enforcing
	 * -- the reassuring direction to be wrong in, which is the one that goes
	 * unnoticed. An observe-only rule is compiled and evaluated but enforces
	 * nothing, so it is named as well. Only reached when the compile reported
	 * no problems, so every enabled rule is in the file.
	 *
	 * "Evaluated" rather than "enforced" for the rest too: in log mode nothing
	 * is enforced, and the operating mode has a test of its own.
	 *
	 * @param array<int|string, mixed> $rules   Stored rules.
	 * @param int                      $presets Enabled presets.
	 */
	private static function compiled_summary( array $rules, int $presets ): string {
		$enabled   = 0;
		$observing = 0;
		$disabled  = 0;

		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) ) {
				continue;
			}

			if ( empty( $rule['enabled'] ) ) {
				++$disabled;

				continue;
			}

			++$enabled;

			if ( ! empty( $rule['observe'] ) ) {
				++$observing;
			}
		}

		$summary = sprintf(
			/* translators: 1: enabled rule count, 2: preset count. */
			__( '%1$d enabled rule(s) and %2$d preset(s) are compiled and being evaluated.', 'basic-firewall' ),
			$enabled,
			$presets
		);

		if ( $observing > 0 ) {
			$summary .= ' ' . sprintf(
				/* translators: %d: observe-only rule count. */
				__( '%d of those rules observe only: their matches are logged and nothing is enforced.', 'basic-firewall' ),
				$observing
			);
		}

		if ( $disabled > 0 ) {
			$summary .= ' ' . sprintf(
				/* translators: %d: disabled rule count. */
				__( '%d disabled rule(s) are not compiled and are not evaluated.', 'basic-firewall' ),
				$disabled
			);
		}

		return esc_html( $summary );
	}

	/**
	 * Does every rule that says it verifies crawlers actually verify them?
	 *
	 * Critical rather than a recommendation, and the reason is the direction
	 * of the failure. Verification fails closed, so such a rule matches
	 * *nobody*: the operator believes genuine crawlers are let through, and
	 * they are instead judged by whatever rules follow -- blocked, if a rule
	 * below catches them. Nothing else in the interface would say so.
	 *
	 * Reachable only on a library older than 2.33.0, which switches
	 * verification off with the offline rule-sources flag, or older than
	 * 2.20.0, which has none. The rule screen refuses to save either, so a rule
	 * here arrived by import, WP-CLI, or a library downgrade.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_verification(): array {
		$verifying = array();
		$unusable  = array();

		foreach ( (array) Plugin::instance()->settings()->get( 'rules', array() ) as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['enabled'] ) || 'user_agent' !== ( $rule['type'] ?? '' ) || empty( $rule['settings']['verify'] ) ) {
				continue;
			}

			$name = (string) ( '' !== (string) ( $rule['label'] ?? '' ) ? $rule['label'] : ( $rule['id'] ?? '?' ) );

			$verifying[] = $name;

			if ( User_Agent::verification_unusable( (array) $rule['settings'] ) ) {
				$unusable[] = $name;
			}
		}

		if ( array() === $verifying ) {
			return self::ok(
				__( 'No rule verifies crawlers', 'basic-firewall' ),
				esc_html__( 'No user agent rule asks for reverse-DNS verification. An allow rule on the agent alone believes whatever the client typed — anyone can claim to be Googlebot — so verify any rule that lets crawlers through.', 'basic-firewall' )
			);
		}

		$capabilities = new Library_Capabilities();
		$names        = '<strong>' . esc_html( implode( ', ', $verifying ) ) . '</strong>';

		if ( ! $capabilities->has_identity_verification() ) {
			return self::critical(
				__( 'Rules that verify crawlers are not running', 'basic-firewall' ),
				sprintf(
					/* translators: %s: rule names. */
					esc_html__( 'These rules verify crawlers by reverse DNS: %s. The installed firewall library cannot, so they are skipped when the configuration is compiled rather than left to believe every client claiming to be a crawler.', 'basic-firewall' ),
					$names
				)
			);
		}

		if ( ! $capabilities->identity_verification_runs() ) {
			return self::critical(
				__( 'Rules that verify crawlers are matching nobody', 'basic-firewall' ),
				sprintf(
					/* translators: 1: rule names, 2: the wp-config.php line. */
					esc_html__( 'These rules verify crawlers by reverse DNS: %1$s. The installed firewall library switches verification off while rule lists are kept off the request path, so each of them currently matches nobody — a genuine crawler is treated as ordinary traffic. Update to kanopi/firewall 2.33.0, which gives verification its own switch, or add %2$s to wp-config.php.', 'basic-firewall' ),
					$names,
					"<code>define( 'BASIC_FIREWALL_SOURCES_OFFLINE', false );</code>"
				)
			);
		}

		/*
		 * Last, because it is the one problem the rule can fix for itself. The
		 * compiler skips these rather than compile them without verification,
		 * so a genuine crawler is judged by the rules below, as if unverified.
		 */
		if ( array() !== $unusable ) {
			return self::critical(
				__( 'Rules that verify crawlers have no domain to verify against', 'basic-firewall' ),
				sprintf(
					/* translators: %s: rule names. */
					esc_html__( 'These rules verify crawlers by reverse DNS but list no domain to accept: %s. Anything that is not a plain domain, such as *.googlebot.com or a URL, is dropped, so they are skipped when the configuration is compiled rather than left to believe every client claiming to be a crawler. Edit each rule and list a domain such as googlebot.com.', 'basic-firewall' ),
					'<strong>' . esc_html( implode( ', ', $unusable ) ) . '</strong>'
				)
			);
		}

		return self::ok(
			__( 'Rules that verify crawlers can verify them', 'basic-firewall' ),
			sprintf(
				/* translators: %s: rule names. */
				esc_html__( 'These rules verify crawlers by reverse DNS: %s. Each lookup is made on the request path the first time an address is seen, and a verdict is cached — so a local caching resolver on this host is what keeps a cache miss at a couple of milliseconds rather than a hundred.', 'basic-firewall' ),
				$names
			)
		);
	}

	/**
	 * Does a direct request for wp-login.php reach the rules as `/wp-login.php`?
	 *
	 * WordPress serves the login page, XML-RPC, cron and every admin screen as
	 * files of their own, and under the library's default path source each of
	 * them is `/` (#30). The compiled file fixes that with
	 * `path_source: script_name` and, in a subdirectory, `base_path`. This
	 * reads both back out of the compiled file -- the one the early path reads
	 * -- builds the request a web server sends for wp-login.php on this site,
	 * and asks the library's own resolver what `path` the rules would see.
	 *
	 * Critical when the key is missing (an old compiled file, or advanced YAML
	 * overriding it), when the base path is unusable, when wp-login.php does
	 * not resolve to itself, or when a page does not resolve to its own path --
	 * which is what a stale `base_path` looks like after a site moves, and
	 * means every front-end request is matched as `/index.php`. All of those
	 * leave rules that read as protection and match nothing. One request
	 * object each, no evaluation.
	 *
	 * A recommendation where WordPress has its own directory and something
	 * still names its files without that directory: see Site_Layout for why
	 * those are matched with the prefix.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_request_path(): array {
		$compiled = Plugin::instance()->compiled()->contents();

		try {
			$config = null === $compiled ? array() : Yaml::parse( $compiled );
		} catch ( \Throwable $e ) {
			$config = array();
		}

		$global = is_array( $config ) && is_array( $config['global'] ?? null ) ? $config['global'] : array();
		$source = $global['path_source'] ?? null;

		if ( RequestPath::SCRIPT_NAME !== $source ) {
			return self::critical(
				__( 'Rules see the wrong path for directly requested files', 'basic-firewall' ),
				'<p>' . esc_html(
					sprintf(
						/* translators: %s: the path_source value found, or "nothing". */
						__( 'The compiled configuration sets path_source to %s rather than script_name, so a direct request for wp-login.php, xmlrpc.php or an admin screen reaches the rules as /. Path conditions and rate limits on those pages are not matching, and a negated path condition matches all of them. Rebuild the firewall; if the advanced YAML sets path_source, remove it.', 'basic-firewall' ),
						is_scalar( $source ) ? (string) $source : __( 'nothing', 'basic-firewall' )
					)
				) . '</p>'
			);
		}

		$base = RequestPath::normaliseBasePath( $global['base_path'] ?? null );

		if ( null === $base ) {
			return self::critical(
				__( 'Rules see the wrong path for directly requested files', 'basic-firewall' ),
				'<p>' . esc_html__( 'The compiled configuration has a base_path the firewall library cannot use, so it matches against the wrong path. Rebuild the firewall; if the advanced YAML sets base_path, remove it.', 'basic-firewall' ) . '</p>'
			);
		}

		$prefix   = Site_Layout::core_prefix();
		$expected = $prefix . '/wp-login.php';
		$page     = '/basic-firewall-path-check/';

		try {
			$seen      = RequestPath::resolve( Request_Tester::site_request( $expected ), RequestPath::SCRIPT_NAME, $base );
			$page_seen = RequestPath::resolve( Request_Tester::site_request( $page ), RequestPath::SCRIPT_NAME, $base );
		} catch ( \Throwable $e ) {
			$seen      = null;
			$page_seen = null;
		}

		if ( $expected !== $seen || $page !== $page_seen ) {
			return self::critical(
				__( 'Rules see the wrong path for directly requested files', 'basic-firewall' ),
				'<p>' . esc_html(
					sprintf(
						/* translators: 1: the expected login path, 2: the path the firewall saw, 3: the expected page path, 4: the path the firewall saw for it. */
						__( 'A direct request for wp-login.php reached the rules as %2$s instead of %1$s, and a page at %3$s as %4$s. The compiled base_path does not match where this site is served, so path conditions and rate limits are matching the wrong thing. Rebuild the firewall; if this persists, report it with the plugin and PHP versions.', 'basic-firewall' ),
						$expected,
						null === $seen ? __( 'nothing', 'basic-firewall' ) : $seen,
						$page,
						null === $page_seen ? __( 'nothing', 'basic-firewall' ) : $page_seen
					)
				) . '</p>'
			);
		}

		if ( '' !== $prefix ) {
			$unprefixed = self::unprefixed_core_paths( (string) $compiled, $config, $prefix );

			$description = '<p>' . esc_html(
				sprintf(
					/* translators: 1: the directory WordPress is in, e.g. /wp, 2: the login path with it, e.g. /wp/wp-login.php. */
					__( 'WordPress has its own directory, %1$s, so its own files are matched with it: a direct request for the login page reaches the rules as %2$s, and admin screens as %1$s/wp-admin/…. A rule on /wp-login.php matches only the bare address, which WordPress redirects.', 'basic-firewall' ),
					$prefix,
					$expected
				)
			) . '</p>';

			if ( $unprefixed ) {
				return self::recommended(
					sprintf(
						/* translators: %s: the directory WordPress is in, e.g. /wp. */
						__( 'Some rules name WordPress\'s own files without %s', 'basic-firewall' ),
						$prefix
					),
					$description . '<p>' . esc_html(
						sprintf(
							/* translators: %s: the directory WordPress is in, e.g. /wp. */
							__( 'A rule or an enabled preset names /wp-login.php, /xmlrpc.php, /wp-cron.php or /wp-admin without %s, so it does not match those files on this site. The presets are written for WordPress at the root. Add rules for the prefixed paths, or match with ends with or contains.', 'basic-firewall' ),
							$prefix
						)
					) . '</p>'
				);
			}

			return self::ok( __( 'Rules see the path of a directly requested file', 'basic-firewall' ), $description );
		}

		return self::ok(
			__( 'Rules see the path of a directly requested file', 'basic-firewall' ),
			esc_html__( 'WordPress serves the login page, XML-RPC and every admin screen from files other than index.php. The firewall matches the file the web server ran, so a direct request for wp-login.php reaches the rules as /wp-login.php however its address is spelled, and path conditions and rate limits on it match.', 'basic-firewall' )
		);
	}

	/**
	 * Whether the compiled file or an enabled preset names a core file bare.
	 *
	 * Comment lines are skipped, because the presets' headers talk about the
	 * paths they cover. A regular expression's escaped dot counts as a mention.
	 *
	 * @param string       $compiled The compiled file's contents.
	 * @param array<mixed> $config   The compiled file, parsed.
	 * @param string       $prefix   WordPress's directory, e.g. `/wp`.
	 */
	private static function unprefixed_core_paths( string $compiled, array $config, string $prefix ): bool {
		$texts = array( $compiled );

		foreach ( (array) ( $config['configs'] ?? array() ) as $file ) {
			if ( is_string( $file ) && is_readable( $file ) ) {
				$texts[] = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a local preset file.
			}
		}

		$pattern = '#(?<!' . preg_quote( $prefix, '#' ) . ')/(?:wp-login\\\\?\.php|xmlrpc\\\\?\.php|wp-cron\\\\?\.php|wp-admin\b)#';

		foreach ( $texts as $text ) {
			$lines = preg_replace( '/^\s*#.*$/m', '', $text );

			if ( is_string( $lines ) && 1 === preg_match( $pattern, $lines ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Is every identity-keyed rate limit paired with an address-keyed one?
	 *
	 * A recommendation rather than critical: the rule works, and the
	 * configuration is occasionally deliberate -- an address limit can live in
	 * front of WordPress, where this cannot see it. But the two key shapes
	 * catch opposite attacks, and an identity-keyed limit records no offense,
	 * so on its own it leaves brute force unprotected and the block list empty
	 * while reading, on every screen, as a tightening.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_rate_keys(): array {
		$rules    = (array) Plugin::instance()->settings()->get( 'rules', array() );
		$unpaired = Rate_Limit::unpaired_identity_limits( $rules );

		if ( array() === $unpaired ) {
			return self::ok(
				__( 'Every rate limit counting an account also has one counting the address', 'basic-firewall' ),
				esc_html__( 'A limit that counts an account, a header or a field catches many clients against one account and misses one client working through many. None of the rate limits here is relying on one without the other.', 'basic-firewall' )
			);
		}

		$lines = array();

		foreach ( $unpaired as $id => $patterns ) {
			$lines[] = sprintf(
				'<li><strong>%s</strong> — <code>%s</code></li>',
				esc_html( (string) $id ),
				esc_html( implode( ', ', $patterns ) )
			);
		}

		return self::recommended(
			__( 'A rate limit counts an account, but nothing counts the address beside it', 'basic-firewall' ),
			'<p>' . esc_html__( 'These limits count something other than the client address:', 'basic-firewall' ) . '</p><ul>' . implode( '', $lines ) . '</ul><p>'
				. esc_html__( 'That catches many clients attacking one account, and misses one client working through a list of accounts — each name gets a fresh allowance, which is the attack an address-keyed limit catches. It also records no offense, so nothing reaches the block list. Add a separate rate limit rule on the same pattern that counts the address. It has to be a separate rule: within one, only the first line whose pattern matches is used.', 'basic-firewall' )
				. '</p>',
			sprintf(
				'<p><a href="%s">%s</a></p>',
				esc_url( Admin::url( 'basic-firewall-rules' ) ),
				esc_html__( 'Open the rules', 'basic-firewall' )
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

		$late = $paths->late_filter();

		if ( null !== $late ) {
			/*
			 * Ahead of the reachability probe, because it changes what that
			 * probe is about: whoever added the filter believes the files live
			 * where it says, and they do not.
			 */
			return self::recommended(
				__( 'The basic_firewall_private_path filter is added too late to take effect', 'basic-firewall' ),
				'<p>' . sprintf(
					/* translators: 1: directory the filter names, 2: directory in use. */
					esc_html__( 'The filter names %1$s, but the firewall is using %2$s. It settles the directory at muplugins_loaded, before any ordinary plugin or theme loads, so a filter added from one of those is never consulted.', 'basic-firewall' ),
					'<code>' . esc_html( $late ) . '</code>',
					'<code>' . esc_html( $paths->base() ) . '</code>'
				) . '</p>'
				. '<p>' . esc_html__( 'Move the add_filter() call into a file in wp-content/mu-plugins, then rebuild the firewall. Until then every request reads and writes the directory in use, so the site is protected — just not where you asked.', 'basic-firewall' ) . '</p>'
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
		if ( is_multisite() ) {
			return self::check_bootstrap_on_a_network();
		}

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
	 * The snippet on a multisite network, where it does nothing.
	 *
	 * The bootstrap steps aside on a network, because it runs before
	 * WordPress knows which site a request is for and each site has its own
	 * rules. So its absence is the healthy state, and its presence is worth a
	 * word: somebody added it expecting the protection it gives a single site,
	 * and on a network it gives none.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_bootstrap_on_a_network(): array {
		$why = '<p>' . esc_html__( 'On a multisite network the firewall evaluates from its mu-plugin, once WordPress has worked out which site a request is for, so each site is held to its own rules. The wp-config.php path runs before that is known, so it steps aside on a network rather than apply one site\'s rules to all of them.', 'basic-firewall' ) . '</p>';

		if ( self::early_path_active() || true === self::snippet_is_in_wp_config() ) {
			return self::recommended(
				__( 'wp-config.php calls the firewall, which does nothing on a multisite network', 'basic-firewall' ),
				$why
				. '<p>' . esc_html__( 'The call returns without evaluating anything, so it costs a little on every request and protects nothing. Remove the require_once line and the basic_firewall_evaluate() call from wp-config.php. A page cache in front of the network still serves cache hits without the firewall seeing them.', 'basic-firewall' ) . '</p>'
			);
		}

		return self::ok(
			__( 'Each site of the network evaluates against its own rules', 'basic-firewall' ),
			$why
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
		$cache        = self::detect_page_cache();

		// On a network the bootstrap steps aside, so it is never where this
		// runs; check_bootstrap() says what to do about a snippet left in.
		$early = self::early_path_active() && ! is_multisite();

		if ( $early && ! self::early_report()['evaluated'] && ! in_array( self::early_report()['reason'], array( 'disabled', 'switched-off', 'deferred-login' ), true ) ) {
			/*
			 * The snippet is there and running, and this request still was not
			 * evaluated by it. Reported rather than folded into the healthy
			 * branch, because everything visible says the firewall runs before
			 * WordPress while in fact the mu-plugin is quietly picking up every
			 * request -- which is the exact configuration somebody added the
			 * snippet to avoid, and a page cache defeats it entirely.
			 *
			 * `disabled` and `switched-off` are excluded on purpose.
			 * BASIC_FIREWALL_ENABLED and the "Enable the firewall" setting both
			 * stop both paths, so the sentence below -- that the mu-plugin is
			 * covering for this one -- would be false, and the operating mode
			 * test already reports that state. Two checks describing one
			 * cause, one of them wrongly, is worse than the check that was
			 * missing.
			 *
			 * `deferred-login` too: a role is exempt and this request -- an
			 * admin screen, almost always -- carries a login cookie, so it was
			 * handed to the runner on purpose. Requests without one are
			 * evaluated by the snippet as usual.
			 */
			return self::critical(
				__( 'The wp-config.php snippet is present but is not evaluating requests', 'basic-firewall' ),
				'<p>' . esc_html__( 'wp-config.php calls the firewall bootstrap, but it returned without evaluating this request. Whatever protection you have is coming from the mu-plugin instead, which loads after advanced-cache.php — so on a cached site, a cache hit is not evaluated at all.', 'basic-firewall' ) . '</p>'
				. '<p>' . esc_html( self::early_reason_text( self::early_report()['reason'] ) ) . '</p>'
				. self::early_reason_action( self::early_report()['reason'] )
			);
		}

		if ( $early && ! self::early_report()['responder'] && 'exception' === self::effective_mode() ) {
			/*
			 * The bootstrap answers `exception` mode verdicts itself, with the
			 * plugin's own responder, because the mu-plugin runs after
			 * advanced-cache.php. Without that responder it refuses each of
			 * them with a plain 503 rather than serve the page (#34): no
			 * challenge a visitor could solve, no redirect, no block page.
			 * Safe, but not what the rules say, which is why it is critical.
			 */
			return self::critical(
				__( 'Exception mode cannot answer challenges, redirects or blocks properly on the wp-config.php path', 'basic-firewall' ),
				'<p>' . esc_html__( 'The operating mode is exception, so the firewall hands each block, redirect and challenge to the plugin to answer rather than sending it itself. The wp-config.php bootstrap could not find the plugin\'s responder, so it refuses each of those requests with a plain "verification required" page instead: a challenged visitor has no challenge to solve, and a redirect rule sends nobody anywhere.', 'basic-firewall' ) . '</p>'
				. '<p>' . esc_html__( 'Reinstall the plugin so src/Runtime/Outcome_Responder.php is present, or switch the operating mode to Block, where the library answers every refusal itself.', 'basic-firewall' ) . '</p>'
			);
		}

		$anomaly = self::web_request_anomaly();

		if ( null !== $anomaly ) {
			return $anomaly;
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

			$stale = self::stale_mu_loader( $where );

			if ( null !== $stale ) {
				return $stale;
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

		$stale = self::stale_mu_loader( '' );

		if ( null !== $stale ) {
			return $stale;
		}

		if ( null !== $cache && is_multisite() ) {
			/*
			 * The same gap, without the snippet as the answer: on a network
			 * the wp-config.php path steps aside, so recommending it would be
			 * recommending a line that does nothing.
			 */
			return self::recommended(
				__( 'A page cache is serving requests before the firewall sees them', 'basic-firewall' ),
				'<p>' . sprintf(
					/* translators: %s: the detected cache. */
					esc_html__( '%s serves cached pages from advanced-cache.php, which WordPress loads before any plugin — including the firewall\'s mu-plugin loader. A cache hit is therefore never evaluated.', 'basic-firewall' ),
					esc_html( $cache )
				) . '</p>'
				. '<p>' . esc_html__( 'On a single site the wp-config.php snippet closes this gap. On a multisite network it cannot: it runs before WordPress knows which site a request is for, so it steps aside and each site is evaluated from the mu-plugin. Put anything that must see every request in front of the cache — at the CDN or the web server.', 'basic-firewall' ) . '</p>'
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
	 * A result for a recent web request that went wrong, or null.
	 *
	 * Everything else this check says is about the request rendering it --
	 * an administrator's, which a login cookie may have sent down another
	 * path, and which on a host with several web servers may not even have
	 * reached the one a visitor did. The runner saves the last anomalous web
	 * request's report (see Diagnostics), and this raises it while it is
	 * recent: critical for a request let through unfiltered, a verdict the
	 * early path handed on, or rules that could not be built, in a mode that
	 * refuses; recommended for an early path that did not evaluate, or a
	 * request that saw another configuration from the one last compiled.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}|null
	 */
	private static function web_request_anomaly(): ?array {
		$report = Diagnostics::recent_anomaly();

		if ( null === $report ) {
			return null;
		}

		$early  = (array) ( $report['early'] ?? array() );
		$runner = (array) ( $report['runner'] ?? array() );
		$mode   = (string) ( $report['mode']['runner'] ?? $report['mode']['early'] ?? self::effective_mode() );
		$when   = sprintf(
			/* translators: 1: how long ago, 2: request method, 3: URL path. */
			esc_html__( '%1$s ago, a web request (%2$s %3$s) ', 'basic-firewall' ),
			esc_html( human_time_diff( (int) ( $report['time'] ?? 0 ) ) ),
			esc_html( (string) ( $report['method'] ?? '' ) ),
			'<code>' . esc_html( (string) ( $report['path'] ?? '' ) ) . '</code>'
		);
		$capture = '<p>' . esc_html__( 'Run `wp basic-firewall early-report` for the full report, and look for lines starting "Basic Firewall [warning]:" in the PHP error log.', 'basic-firewall' ) . '</p>';

		switch ( $report['anomaly'] ?? null ) {
			case 'fail-open':
				$failure = null !== ( $early['failure'] ?? null )
					/* translators: 1: exception class and message, 2: file and line. */
					? sprintf( __( 'On the wp-config.php path: %1$s, thrown at %2$s.', 'basic-firewall' ), (string) $early['failure'], (string) ( $early['failure_origin'] ?? '?' ) )
					/* translators: 1: failure code, 2: what it was about. */
					: sprintf( __( 'On the mu-plugin path: %1$s (%2$s).', 'basic-firewall' ), (string) ( $runner['failure'] ?? '' ), (string) ( $runner['failure_detail'] ?? '' ) );
				$body = '<p>' . $when . esc_html__( 'went through unfiltered, because the firewall failed while evaluating it. The firewall fails open by design, so the site stays up, but no rule protected that request.', 'basic-firewall' ) . '</p>'
					. '<p>' . esc_html( $failure ) . '</p>' . $capture;

				return in_array( $mode, array( 'block', 'exception' ), true )
					? self::critical( __( 'The firewall recently let a request through because it failed', 'basic-firewall' ), $body )
					: self::recommended( __( 'The firewall recently let a request through because it failed', 'basic-firewall' ), $body );

			case 'early-verdict-deferred':
				return self::critical(
					__( 'The wp-config.php path recently reached a verdict it did not answer', 'basic-firewall' ),
					'<p>' . $when . sprintf(
						/* translators: %s: the verdict, e.g. challenge. */
						esc_html__( 'was given a %s verdict on the wp-config.php path, which was not answered there. It was refused with a plain page instead of what the rule asked for, and on a site with a page cache it may have been served the page first.', 'basic-firewall' ),
						esc_html( (string) ( $runner['early_verdict'] ?? $early['outcome'] ?? '?' ) )
					) . '</p>'
					. ( null !== ( $early['refused'] ?? null ) ? '<p>' . esc_html( (string) $early['refused'] ) . '</p>' : '' )
					. $capture
				);

			case 'failed-rules':
				/*
				 * A rule the library could not construct is skipped, so on
				 * that request part of the configuration was not enforced --
				 * for a block rule, a fail-open for exactly the traffic it
				 * names. Critical where the mode refuses, as a fail-open is.
				 * The compiled-configuration check reports rules the compiler
				 * itself left out; these compiled and then failed to build on
				 * a web request, which that check, run from this request,
				 * cannot see.
				 */
				$lines = '';

				foreach ( array(
					'early'  => __( 'On the wp-config.php path', 'basic-firewall' ),
					'runner' => __( 'On the mu-plugin path', 'basic-firewall' ),
				) as $half => $where ) {
					$names = array_map( 'strval', (array) ( ( 'early' === $half ? $early : $runner )['failed_rules'] ?? array() ) );

					if ( array() !== $names ) {
						$lines .= '<li>' . esc_html( $where ) . ': <code>' . implode( '</code>, <code>', array_map( 'esc_html', $names ) ) . '</code></li>';
					}
				}

				/*
				 * Said, because it is sampled: asking builds every rule, so it
				 * is asked at most once a minute per server, with
				 * BASIC_FIREWALL_DEBUG, or on a failure -- not on every
				 * request, and a report without it is not a clean one.
				 */
				$sampled = (string) ( $early['failed_rules_sampled'] ?? $runner['failed_rules_sampled'] ?? '' );

				if ( '' !== $sampled ) {
					$lines .= '<li>' . esc_html(
						sprintf(
							/* translators: %s: why the request was sampled: interval, debug or failure. */
							__( 'Found on a sampled request (%s). The rules are checked at most once a minute per web server, with BASIC_FIREWALL_DEBUG on, or when a request fails — not on every request.', 'basic-firewall' ),
							$sampled
						)
					) . '</li>';
				}

				$body = '<p>' . $when . esc_html__( 'was evaluated by a firewall that could not construct some of its rules, so those rules did not run. The library skips a rule whose constructor fails rather than stopping, so everything else went on working — which is why nothing else looks wrong.', 'basic-firewall' ) . '</p>'
					. '<ul>' . $lines . '</ul>'
					. '<p>' . esc_html__( 'A rule that fails on web requests and not here usually depends on something only the web servers lack: a storage or reputation host they cannot reach, a PHP extension, a file. The library logs each one with its reason, as "Firewall rule could not be constructed and is NOT active".', 'basic-firewall' ) . '</p>'
					. $capture;

				return in_array( $mode, array( 'block', 'exception' ), true )
					? self::critical( __( 'The firewall recently ran without some of its rules', 'basic-firewall' ), $body )
					: self::recommended( __( 'The firewall recently ran without some of its rules', 'basic-firewall' ), $body );

			case 'mismatch':
				/*
				 * Recommended rather than critical: the request was evaluated,
				 * by a firewall built from a file, just not necessarily the
				 * file the settings produced. Overrides -- a panic file,
				 * BASIC_FIREWALL_MODE, lockdown -- never reach here; they are
				 * in the report as what they are.
				 */
				$lines = '';

				foreach ( (array) ( $report['mismatch'] ?? array() ) as $line ) {
					$lines .= '<li><code>' . esc_html( (string) $line ) . '</code></li>';
				}

				return self::recommended(
					__( 'A recent web request saw a different firewall configuration from the one last compiled', 'basic-firewall' ),
					'<p>' . $when . esc_html__( 'was evaluated with a mode or a compiled file that does not match what the settings last compiled:', 'basic-firewall' ) . '</p>'
					. '<ul>' . $lines . '</ul>'
					. '<p>' . esc_html__( 'That is the signature of a stale copy of the compiled file on a web server that did not do the compile — the private directory not shared between servers, or storage that has not caught up — so that server enforces an older configuration than the one these screens describe.', 'basic-firewall' ) . '</p>'
					. $capture,
					self::rebuild_action()
				);

			case 'not-evaluated':
				$reason = isset( $early['reason'] ) ? (string) $early['reason'] : null;

				return self::recommended(
					__( 'The wp-config.php snippet recently did not evaluate a web request', 'basic-firewall' ),
					'<p>' . $when . esc_html__( 'was not evaluated by the wp-config.php snippet, so the mu-plugin evaluated it instead — after advanced-cache.php, where a page cache serves pages without evaluating them.', 'basic-firewall' ) . '</p>'
					. '<p>' . esc_html( self::early_reason_text( $reason ) ) . '</p>'
					. $capture,
					self::early_reason_action( $reason )
				);
		}

		return null;
	}

	/**
	 * A result for an installed loader that is out of date, or null.
	 *
	 * Out of date means the loader that ran this request states an older
	 * version than the plugin ships, or the last attempt to refresh it failed.
	 * Both are free to ask -- a constant and a network option -- which matters
	 * because this runs behind the admin notice on every admin screen.
	 *
	 * Recommended rather than critical: an older loader still loads the
	 * firewall at muplugins_loaded. What it lacks is whatever the release that
	 * changed it fixed.
	 *
	 * @param string $where What the calling branch has already said about where evaluation happens.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}|null
	 */
	private static function stale_mu_loader( string $where ): ?array {
		$failure = Mu_Loader::refresh_failure();

		if ( null === $failure && ! Mu_Loader::running_is_stale() ) {
			return null;
		}

		$running = Mu_Loader::running_version();
		$after   = ' ' . esc_html__( 'The plugin replaces it on its own when it is updated, when it is activated, and on the first admin, cron or WP-CLI request after the version changes, so this usually clears without anybody doing anything.', 'basic-firewall' );

		if ( Mu_Loader::running_is_stale() ) {
			$description = $where . '<p>' . sprintf(
				/* translators: 1: installed loader version, or "an unversioned copy", 2: shipped loader version. */
				esc_html__( 'The mu-plugin loader in the mu-plugins directory is %1$s, and this release of the plugin ships %2$s.', 'basic-firewall' ),
				esc_html(
					'' === (string) $running
						? __( 'an unversioned copy', 'basic-firewall' )
						/* translators: %s: version number. */
						: sprintf( __( 'version %s', 'basic-firewall' ), $running )
				),
				/* translators: %s: version number. */
				esc_html( sprintf( __( 'version %s', 'basic-firewall' ), Mu_Loader::VERSION ) )
			) . $after . '</p>';
		} else {
			$description = $where . '<p>' . esc_html__( 'The mu-plugin loader in the mu-plugins directory differs from the copy this release of the plugin ships.', 'basic-firewall' ) . $after . '</p>';
		}

		if ( null !== $failure ) {
			$description .= '<p>' . esc_html( $failure ) . '</p>'
				. '<p>' . sprintf(
					/* translators: %s: the mu-plugin file path. */
					esc_html__( 'Make the mu-plugins directory writable by PHP and reload this page, or copy mu-plugin/basic-firewall-loader.php from the plugin over %s by hand.', 'basic-firewall' ),
					'<code>' . esc_html( Mu_Loader::instance()->path() ) . '</code>'
				) . '</p>';
		} elseif ( Mu_Loader::refresh_disabled() ) {
			$description .= '<p>' . esc_html__( 'BASIC_FIREWALL_MU_LOADER_REFRESH is false in wp-config.php, so the plugin will not replace it. Deploy the new copy of mu-plugin/basic-firewall-loader.php yourself.', 'basic-firewall' ) . '</p>';
		}

		return self::recommended(
			__( 'The mu-plugin loader is out of date', 'basic-firewall' ),
			$description
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
	 * `responder` is whether the bootstrap can answer an `exception` mode
	 * verdict itself, before a page cache runs. It defaults to true when the
	 * bootstrap did not say, so a report from a bootstrap that predates the
	 * question is not read as a failure.
	 *
	 * `autoloader` is which Composer autoloader the bootstrap used and where
	 * it came from -- `plugin`, `option`, `constant`, `site`, `loaded`, or
	 * `unreadable` and `none` when it found nothing to use -- so a failure can
	 * name the file it is about, and `named` is whether the snippet's option
	 * or the constant named one. Null from a bootstrap that did not get that
	 * far, or predates the question.
	 *
	 * @return array{called: bool, credentials: bool, evaluated: bool, reason: string|null, responder: bool, autoloader: array{source: string, file: string|null, named: string|null}|null}
	 */
	public static function early_report(): array {
		$report = $GLOBALS['basic_firewall_early'] ?? array();

		$autoloader = null;

		if ( isset( $report['autoloader']['source'] ) && is_string( $report['autoloader']['source'] ) ) {
			$autoloader = array(
				'source' => $report['autoloader']['source'],
				'file'   => isset( $report['autoloader']['file'] ) && is_string( $report['autoloader']['file'] ) ? $report['autoloader']['file'] : null,
				'named'  => isset( $report['autoloader']['named'] ) && is_string( $report['autoloader']['named'] ) ? $report['autoloader']['named'] : null,
			);
		}

		return array(
			'called'      => ! empty( $report['called'] ),
			'credentials' => ! empty( $report['credentials'] ),
			'evaluated'   => ! empty( $report['evaluated'] ),
			'reason'      => isset( $report['reason'] ) ? (string) $report['reason'] : null,
			'responder'   => ! isset( $report['responder'] ) || ! empty( $report['responder'] ),
			'autoloader'  => $autoloader,
		);
	}

	/**
	 * The operating mode requests are actually evaluated in.
	 *
	 * BASIC_FIREWALL_MODE first, because it wins over the setting on both
	 * paths.
	 */
	private static function effective_mode(): string {
		if ( defined( 'BASIC_FIREWALL_MODE' ) && is_string( constant( 'BASIC_FIREWALL_MODE' ) ) ) {
			return (string) constant( 'BASIC_FIREWALL_MODE' );
		}

		return (string) Plugin::instance()->settings()->get( 'global.mode', 'log' );
	}

	/**
	 * Why the bootstrap ran but did not evaluate this request.
	 *
	 * Public because `wp basic-firewall status` prints the same sentence: a
	 * runbook reading a reason code is a runbook that has to look it up.
	 *
	 * @param string|null $reason Machine-readable reason recorded by the bootstrap.
	 */
	public static function early_reason_text( ?string $reason ): string {
		switch ( $reason ) {
			case 'disabled':
				return __( 'BASIC_FIREWALL_ENABLED is defined as false in wp-config.php, which switches the firewall off on both paths.', 'basic-firewall' );
			case 'deferred-login':
				return __( 'A role is exempt from the firewall and this request carries a WordPress login cookie, so it was left for the mu-plugin, which can check whose it is. Requests without one are evaluated before WordPress as usual.', 'basic-firewall' );
			case 'multisite':
				return __( 'This is a multisite network, where the wp-config.php path steps aside and each site is evaluated from the mu-plugin against its own rules.', 'basic-firewall' );
			case 'switched-off':
				return __( '"Enable the firewall" is unticked on the General screen, which switches the firewall off on both paths.', 'basic-firewall' );
			case 'no-compiled-file':
				return __( 'There is no compiled configuration at the path the snippet names. Either the private_path argument is wrong, or the firewall has never been built — the early path cannot build it, because that needs WordPress.', 'basic-firewall' );
			case 'no-autoloader':
				return __( 'No Composer autoloader was found, so the firewall library was never loaded. The bootstrap looks in the plugin\'s own vendor directory and in a vendor directory beside the WordPress root. If this site installs the plugin with Composer and its composer.json sets vendor-dir somewhere else, add an \'autoloader\' line with that path to the basic_firewall_evaluate() call — or define BASIC_FIREWALL_AUTOLOADER — or require the site\'s autoloader in wp-config.php above the snippet.', 'basic-firewall' );
			case 'autoloader-unreadable':
				return self::unreadable_autoloader_text();
			case 'library-missing':
				return __( 'The firewall library class was not found after loading the autoloader, which usually means an incomplete install.', 'basic-firewall' );
			default:
				return __( 'The bootstrap returned without evaluating and did not say why.', 'basic-firewall' );
		}
	}

	/**
	 * What to say about a named autoloader that cannot be read.
	 *
	 * Names the file and where it was named, because the fix is to correct
	 * that one line, and "an autoloader could not be read" does not say which
	 * of two places to look in.
	 */
	private static function unreadable_autoloader_text(): string {
		$autoloader = self::early_report()['autoloader'];
		$file       = (string) ( $autoloader['file'] ?? '' );

		if ( 'constant' === ( $autoloader['named'] ?? null ) ) {
			return sprintf(
				/* translators: %s: the path BASIC_FIREWALL_AUTOLOADER names. */
				__( 'BASIC_FIREWALL_AUTOLOADER names %s as the Composer autoloader, and that file cannot be read, so the firewall library was never loaded. Correct the path, or remove the constant if the plugin\'s own vendor directory or one beside the WordPress root should be used instead.', 'basic-firewall' ),
				$file
			);
		}

		return sprintf(
			/* translators: %s: the path the snippet's autoloader option names. */
			__( 'The snippet\'s \'autoloader\' option names %s as the Composer autoloader, and that file cannot be read, so the firewall library was never loaded. Correct the path, or remove the line if the plugin\'s own vendor directory or one beside the WordPress root should be used instead.', 'basic-firewall' ),
			$file
		);
	}

	/**
	 * What to offer beside the reason the bootstrap did not evaluate.
	 *
	 * A rebuild answers a missing compiled file and nothing about a missing
	 * autoloader, which is fixed in wp-config.php -- so for that the snippet
	 * is printed, with the autoloader line when this site needs one.
	 *
	 * @param string|null $reason Machine-readable reason recorded by the bootstrap.
	 */
	private static function early_reason_action( ?string $reason ): string {
		if ( in_array( $reason, array( 'no-autoloader', 'autoloader-unreadable' ), true ) ) {
			return '<pre>' . esc_html( self::bootstrap_snippet() ) . '</pre>';
		}

		return self::rebuild_action();
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
	 *
	 * And with the site's Composer autoloader when the bootstrap could not
	 * find it unaided: a site-level install whose vendor-dir is somewhere
	 * other than beside the WordPress root. Without that line the snippet
	 * printed here was one that could never evaluate on exactly that site.
	 */
	public static function bootstrap_snippet(): string {
		$autoloader = self::snippet_autoloader();

		return "require_once ABSPATH . 'wp-content/plugins/basic-firewall/bootstrap.php';\n"
			. "basic_firewall_evaluate( array(\n"
			. "    'private_path' => '" . Plugin::instance()->paths()->base() . "',\n"
			. ( null === $autoloader ? '' : "    'autoloader'   => " . $autoloader . ",\n" )
			. ') );';
	}

	/**
	 * The autoloader line's value as PHP source, or null when none is needed.
	 *
	 * Read from where the library running this request was actually
	 * declared, not from composer.json: that file may not be deployed, and
	 * what it says is not necessarily what was installed. Only asked on a
	 * `site-composer` install, which is never scoped, so the class names here
	 * are the library's and Composer's own.
	 */
	private static function snippet_autoloader(): ?string {
		$mode = (string) Library_Loader::mode();

		if ( 'site-composer' !== $mode || ! class_exists( Firewall::class ) ) {
			return null;
		}

		try {
			$file = ( new \ReflectionClass( Firewall::class ) )->getFileName();
		} catch ( \Throwable $e ) {
			return null;
		}

		/*
		 * Composer 2's list of loaders by vendor directory. A site still on
		 * Composer 1 has no such method, and the locator falls back to
		 * walking up from the class file.
		 *
		 * Named by a string assembled at runtime, because the question is
		 * about the site's Composer, and a literal would be rewritten under
		 * the vendor prefix in a scoped build -- the reason Library_Loader
		 * assembles its class names too.
		 */
		$vendor_dirs = array();
		$loader      = implode( '\\', array( 'Composer', 'Autoload', 'ClassLoader' ) );
		$registered  = array( $loader, 'getRegisteredLoaders' );

		if ( class_exists( $loader, false ) && is_callable( $registered ) ) {
			$loaders     = call_user_func( $registered );
			$vendor_dirs = is_array( $loaders ) ? array_map( 'strval', array_keys( $loaders ) ) : array();
		}

		return Autoloader_Locator::snippet_expression(
			$mode,
			false === $file ? null : $file,
			$vendor_dirs,
			ABSPATH,
			BASIC_FIREWALL_DIR
		);
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
				. ' ' . esc_html__( 'To tell who a request belongs to, every request carrying a WordPress login cookie is evaluated once WordPress has validated it, after plugins load, rather than before — including on the wp-config.php path. A page cache that serves pages to logged-in visitors would serve those requests before the firewall sees them; the common ones do not by default.', 'basic-firewall' )
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

		if ( 'redis' === $backend ) {
			$capabilities = new Library_Capabilities();

			if ( ! $capabilities->has_redis_storage_class() ) {
				return self::recommended(
					__( 'Redis block list storage is selected, but the installed library cannot provide it', 'basic-firewall' ),
					esc_html__( 'The firewall is recording blocks in file storage instead, so a client is still remembered on this web node. Update kanopi/firewall to 2.22.0 or later, or choose file or database storage on the Storage screen so the setting says what is happening.', 'basic-firewall' )
				);
			}

			/*
			 * Critical, as in-memory storage is, because it amounts to the same
			 * thing. Since library 2.29.0 the backend degrades rather than
			 * failing without `ext-redis` -- which keeps the site up and leaves
			 * a block list that stores nothing, while every other screen says
			 * storage is configured. Asked of this PHP directly, rather than
			 * waiting for the degraded-backends check, because that one only
			 * knows once a firewall has been built in this request.
			 */
			if ( ! Library_Capabilities::has_redis_extension() ) {
				return self::critical(
					__( 'Redis block list storage is selected, but this server has no redis extension', 'basic-firewall' ),
					'<p>' . esc_html__( 'Every rule is still evaluated and a matching request is still refused, but no client is recorded: repeat offenders are never recognised and escalation never happens. The library lists ext-redis as a suggestion rather than a requirement, so it installs without it.', 'basic-firewall' ) . '</p>'
					. '<p>' . esc_html__( 'Ask your host to enable ext-redis, or choose file or database storage on the Storage screen. If only some web nodes lack it, this result is from the one that answered.', 'basic-firewall' ) . '</p>'
				);
			}
		}

		if ( 'database' === $backend && self::early_path_active() && ! is_multisite() && ! self::early_path_reaches_database() ) {
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
	 * Is the firewall caching where it was told to?
	 *
	 * Two backends can be chosen and then stop working without anybody
	 * touching the setting: an object-cache.php drop-in removed, APCu disabled
	 * in a PHP rebuild. They fail differently, and the difference decides the
	 * severity. Without a persistent object cache the runner hands the library
	 * nothing and it caches in files -- slower, and still cached. Without APCu
	 * the library cannot build the pool the compiled file names and runs agent
	 * detection uncached, which is roughly 600 ms on every request that reaches
	 * a user agent rule.
	 *
	 * @return array{status: string, label: string, description: string, actions: string}
	 */
	private static function check_cache(): array {
		$backend = Cache_Backend::configured();

		if ( 'object_cache' === $backend && ! Cache_Backend::has_persistent_object_cache() ) {
			return self::recommended(
				__( 'The firewall is set to cache in the object cache, but this site has no persistent one', 'basic-firewall' ),
				esc_html__( 'WordPress\'s default object cache forgets everything when the request ends, so the firewall caches in files instead — still cached, but on the storage this setting was chosen to avoid. Restore the object-cache.php drop-in, or choose files or APCu on the Storage screen so the setting says what is happening.', 'basic-firewall' )
			);
		}

		if ( 'apcu' === $backend && ! Cache_Backend::has_apcu() ) {
			return self::critical(
				__( 'The firewall is set to cache in APCu, which is not enabled on this server', 'basic-firewall' ),
				esc_html__( 'The library cannot build the pool the compiled configuration names, so agent detection runs uncached — roughly 600 ms on every request that reaches a user agent rule — rather than falling back to files. Enable APCu, or choose files on the Storage screen. If only some web nodes lack it, this result is from the one that answered.', 'basic-firewall' )
			);
		}

		$directory = Cache_Backend::directory();

		if ( 'filesystem' === $backend && null !== $directory && ! wp_is_writable( $directory ) ) {
			return self::recommended(
				__( 'The firewall\'s cache directory is not writable', 'basic-firewall' ),
				sprintf(
					/* translators: %s: directory path. */
					esc_html__( '%s cannot be written to, so agent detection runs uncached — roughly 600 ms on every request that reaches a user agent rule. Rebuild the firewall to have the directory created, or name one the web server can write.', 'basic-firewall' ),
					esc_html( $directory )
				),
				self::rebuild_action()
			);
		}

		return self::ok(
			__( 'The firewall is caching where it was told to', 'basic-firewall' ),
			sprintf(
				/* translators: %s: where the cache is, as a phrase. */
				esc_html__( 'Parsed user agents and verified crawlers are cached in %s.', 'basic-firewall' ),
				esc_html( Cache_Backend::describe() )
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

		if ( array() === $enabled ) {
			return self::recommended(
				__( 'The firewall is not logging anywhere', 'basic-firewall' ),
				esc_html__( 'No log handler is enabled, so there is no record of what the firewall has blocked beyond whatever listens to the basic_firewall_decision action. That is a supported configuration, but it means the log-only workflow — watch for a few days, then switch to blocking — is not available to you.', 'basic-firewall' )
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
		if ( 'evaluation' === $key ) {
			/*
			 * Opening Site Health is one of the occasions the loader is
			 * compared with the shipped one byte for byte, and refreshed if it
			 * differs. Here rather than in the check, because the check also
			 * runs behind the admin notice on every admin screen, and reading
			 * both files there would be a cost on every page for an answer
			 * the constants already give.
			 */
			Mu_Loader::refresh_installed();
		}

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
