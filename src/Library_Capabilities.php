<?php
/**
 * What the installed library can actually do.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

use Kanopi\Crs\CrsEngine;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Plugins\AbuseIpdb;
use Kanopi\Firewall\Plugins\Crs;
use Symfony\Component\HttpFoundation\Request;

/**
 * Detects installed library features rather than assuming them.
 *
 * The library's documentation has historically run ahead of its releases, so
 * the plugin asks what is present instead of trusting a version number. Two
 * kinds of check, and the difference between them is the interesting part:
 *
 * **Does the class exist?** Cheap, and enough for most features. A rule type
 * whose plugin class is absent is not offered and its screen 404s.
 *
 * **Does it behave?** For the Core Rule Set, the class existing is not evidence
 * that it works, because it has shipped broken in both directions:
 *
 * - library v2.8.0 **inverted the verdict**, so every ordinary request matched
 *   and real attacks passed. Fixed in v2.8.1.
 * - `crs-engine` 0.1.0 parsed the rules but **detected almost nothing**, so the
 *   plugin looked fine and protected nothing. Fixed by `crs-engine` 1.0.0.
 *
 * The second is the more dangerous, because nothing looks wrong. So the probe
 * evaluates both an unmistakable SQL injection payload *and* a clean request: an
 * engine that flags neither is inert, and an engine that flags both is inverted.
 * Trusting either would leave a site believing it had coverage it did not.
 *
 * The probe is expensive, so its result is cached against the library version
 * and re-run when that changes.
 */
final class Library_Capabilities {

	/**
	 * Option holding cached probe results.
	 */
	public const PROBE_OPTION = 'basic_firewall_library_probe';

	/**
	 * Whether the library is installed at all.
	 */
	public function is_installed(): bool {
		return Library_Loader::is_usable();
	}

	/**
	 * Whether the interstitial challenge flow is available.
	 */
	public function has_challenge(): bool {
		return interface_exists( ChallengeProviderInterface::class );
	}

	/**
	 * Whether the AbuseIPDB reputation plugin is available.
	 *
	 * A class_exists() check is enough here, unlike the Core Rule Set: there is
	 * no separate engine package whose version could disagree, and the plugin
	 * fails open by design, so a misbehaving release degrades to "matches
	 * nothing" rather than to blocking legitimate traffic.
	 */
	public function has_abuse_ipdb(): bool {
		return class_exists( AbuseIpdb::class );
	}

	/**
	 * Whether the library can redirect or mark a request rather than refuse it.
	 *
	 * Added in library 2.26.0, which split refusing from recording: a honeypot
	 * can record without refusing, and a lockdown can refuse without recording.
	 * With it come two response actions this plugin did not previously have.
	 *
	 * Detected on the method rather than the version, because a version string
	 * is what the library is called and a method is what it can do. On an older
	 * library the two responses are not offered on the rule screen and a rule
	 * carrying one is skipped at compile time with a warning -- rather than
	 * compiled into a response the library does not understand, which it would
	 * treat as no match at all.
	 */
	public function has_soft_responses(): bool {
		$base = self::plugin_base_class();

		return method_exists( $base, 'getRedirectLocation' ) && method_exists( $base, 'getMarkName' );
	}

	/**
	 * The library's plugin base class, assembled rather than named.
	 *
	 * A `::class` constant lets static analysis resolve the class and fold every
	 * method_exists() against it to a constant -- which is exactly wrong here,
	 * because the whole point of these checks is that the installed library
	 * varies. Analysed against 2.26 they all read as "always true"; run against
	 * 2.24 they are not.
	 *
	 * @return class-string
	 */
	private static function plugin_base_class(): string {
		$bare = implode( '\\', array( 'Kanopi', 'Firewall', 'Plugins', 'AbstractPluginBase' ) );

		/*
		 * Both spellings, scoped first.
		 *
		 * Assembling only the unscoped name fixed the static analysis and broke
		 * every scoped release: in a scoped build that class does not exist, so
		 * has_soft_responses() answered false and the compiler skipped every
		 * redirect and mark rule as "needs 2.26.0 or later" -- on a build
		 * running 2.26.0. The skip was at least loud, which is why it was found
		 * in a minute rather than in a support ticket.
		 *
		 * Scoped first for the same reason Library_Loader does it: it is the
		 * answer in a release build, and asking for it costs nothing in a
		 * development one.
		 */
		$scoped = implode( '\\', array( 'Kanopi', 'BasicFirewall', 'Vendor' ) ) . '\\' . $bare;

		/**
		 * Whichever spelling this build actually has.
		 *
		 * @var class-string $resolved
		 */
		$resolved = class_exists( $scoped ) ? $scoped : $bare;

		return $resolved;
	}

	/**
	 * Whether a rule can refuse without recording, or record without refusing.
	 *
	 * The same 2.26.0 change, checked separately because it is useful on its own:
	 * `record: false` on a block is what a deliberate lockdown needs, so that
	 * lifting it does not leave a block list full of customers each on an
	 * escalating ban nobody asked for.
	 */
	public function has_record_control(): bool {
		return method_exists( self::plugin_base_class(), 'recordsOffenses' );
	}

	/**
	 * Whether a single rule can be set to observe instead of enforce.
	 *
	 * Added in library 2.20.0, older than the version this plugin requires --
	 * checked anyway, because a site whose own Composer autoloader wins the race
	 * can hand this plugin an older library than it shipped with. Without the
	 * method the `mode` key is inert, and a rule saved as observing would
	 * enforce on live traffic while the screen said it was only watching: the
	 * one direction this must never fail in. So the box is not offered, and the
	 * compiler skips an observing rule rather than letting it enforce.
	 */
	public function has_observe_mode(): bool {
		return method_exists( self::plugin_base_class(), 'isObserveMode' );
	}

	/**
	 * Whether a rule can declare when it is awake.
	 *
	 * Added in library 2.27.0. Without it the `active` key is inert and a rule
	 * saved with a window would run around the clock -- the wrong direction for
	 * a block rule somebody meant to run only after hours, and for an allow
	 * rule meant to open only for a maintenance window. So the window is not
	 * offered, and the compiler skips a rule that has one.
	 */
	public function has_rule_schedule(): bool {
		return method_exists( self::plugin_base_class(), 'isActiveNow' );
	}

	/**
	 * Whether a user agent rule can verify a crawler by reverse DNS.
	 *
	 * Added in library 2.20.0. Detected rather than assumed for the reason
	 * observe mode is: a site's own Composer autoloader can hand this plugin an
	 * older library, and on one without the verifier a stored `verify` key is
	 * ignored. On an allow rule that is the worst direction there is -- the rule
	 * lets through everyone who *says* they are Googlebot while the screen says
	 * it checks. So the setting is not offered, and the compiler skips a rule
	 * that asks for it.
	 */
	public function has_identity_verification(): bool {
		return class_exists( self::library_class( 'Utility', 'ReverseDnsVerifier' ) );
	}

	/**
	 * Whether a rule can say for itself that its verification goes online.
	 *
	 * Added in library 2.33.0, and the difference between verification working
	 * and not. Before it, the verifier read `KANOPI_FIREWALL_SOURCES_OFFLINE` --
	 * the switch this plugin turns on so that a rule-list refresh never lands on
	 * a visitor's request -- and the same switch reached the two DNS lookups.
	 * Every verifying rule therefore matched nobody on a default install, with
	 * nothing but a debug line to say so (kanopi/firewall#391).
	 *
	 * With `metadata.verify_offline` a rule overrides the constant, and the
	 * compiler writes `false` on every rule that verifies: somebody who ticked
	 * the box asked for the lookups, and keeping rule lists off the request path
	 * is a separate decision that should not quietly revoke it.
	 */
	public function has_verification_switch(): bool {
		return method_exists( self::plugin_base_class(), 'verificationOffline' );
	}

	/**
	 * Whether a verifying rule would actually verify anybody on this site.
	 *
	 * Always, on a library with the per-rule switch. On an older one, only
	 * where the site has opted out of offline rule sources -- and the opt-out is
	 * read the way both evaluation paths read it: only an explicit `false`.
	 */
	public function identity_verification_runs(): bool {
		if ( ! $this->has_identity_verification() ) {
			return false;
		}

		if ( $this->has_verification_switch() ) {
			return true;
		}

		return defined( 'BASIC_FIREWALL_SOURCES_OFFLINE' ) && false === constant( 'BASIC_FIREWALL_SOURCES_OFFLINE' );
	}

	/**
	 * A library class, in whichever spelling this build has.
	 *
	 * Assembled for the reasons plugin_base_class() gives: a `::class` constant
	 * would be folded to a constant answer by static analysis, and would name
	 * only the spelling that exists in one kind of build.
	 *
	 * @param string ...$segments The class name below `Kanopi\Firewall`.
	 *
	 * @return class-string
	 */
	private static function library_class( string ...$segments ): string {
		$bare   = implode( '\\', array_merge( array( 'Kanopi', 'Firewall' ), $segments ) );
		$scoped = implode( '\\', array( 'Kanopi', 'BasicFirewall', 'Vendor' ) ) . '\\' . $bare;

		/**
		 * Whichever spelling this build actually has.
		 *
		 * @var class-string $resolved
		 */
		$resolved = class_exists( $scoped ) ? $scoped : $bare;

		return $resolved;
	}

	/**
	 * Whether the Core Rule Set is present and actually detecting.
	 */
	public function has_working_crs(): bool {
		return 'working' === $this->crs_probe()['result'];
	}

	/**
	 * The cached Core Rule Set probe, running it if needed.
	 *
	 * @return array{result: string, reason: string, version: string}
	 */
	public function crs_probe(): array {
		$version = (string) ( Library_Loader::version() ?? 'unknown' );
		$cached  = get_option( self::PROBE_OPTION, array() );

		if ( is_array( $cached ) && ( $cached['version'] ?? null ) === $version && isset( $cached['result'] ) ) {
			return $cached;
		}

		$probe            = $this->run_crs_probe();
		$probe['version'] = $version;

		update_option( self::PROBE_OPTION, $probe, false );

		return $probe;
	}

	/**
	 * Actually probe the Core Rule Set.
	 *
	 * @return array{result: string, reason: string}
	 */
	private function run_crs_probe(): array {
		if ( ! class_exists( Crs::class ) ) {
			return array(
				'result' => 'absent',
				'reason' => __( 'The installed firewall library does not ship the Core Rule Set plugin.', 'basic-firewall' ),
			);
		}

		if ( ! class_exists( CrsEngine::class ) ) {
			return array(
				'result' => 'absent',
				'reason' => __( 'The Core Rule Set plugin is present but the kanopi/crs-engine package that evaluates the rules is not installed.', 'basic-firewall' ),
			);
		}

		try {
			$plugin = new Crs(
				array( 'name' => 'capability_probe' ),
				array(
					'mode'              => 'block',
					'paranoia'          => 1,
					'anomaly_threshold' => array(
						'inbound'  => 5,
						'outbound' => 4,
					),
				)
			);

			// An unmistakable SQL injection. If this does not score, the engine
			// is inert whatever it reports about itself.
			$attack = Request::create( '/?id=1%27%20UNION%20SELECT%201,2,3--' );
			$attack->headers->set( 'User-Agent', 'Mozilla/5.0' );

			// An ordinary request. If this scores, the verdict is inverted.
			$clean = Request::create( '/about-us' );
			$clean->headers->set( 'User-Agent', 'Mozilla/5.0' );

			$attack_matched = (bool) $plugin->evaluate( $attack );
			$clean_matched  = (bool) $plugin->evaluate( $clean );
		} catch ( \Throwable $e ) {
			return array(
				'result' => 'error',
				'reason' => sprintf(
					/* translators: %s: error message. */
					__( 'The Core Rule Set could not be evaluated: %s', 'basic-firewall' ),
					$e->getMessage()
				),
			);
		}

		if ( $attack_matched && ! $clean_matched ) {
			return array(
				'result' => 'working',
				'reason' => __( 'The Core Rule Set detected a test attack payload and allowed a clean request.', 'basic-firewall' ),
			);
		}

		if ( $attack_matched && $clean_matched ) {
			return array(
				'result' => 'inverted',
				'reason' => __( 'The Core Rule Set matched an ordinary request as well as an attack payload. This release inverts the verdict — enabling it would reject legitimate traffic and let real attacks through. The rule type is not offered.', 'basic-firewall' ),
			);
		}

		return array(
			'result' => 'inert',
			'reason' => __( 'The Core Rule Set did not detect an unmistakable SQL injection payload. This release parses the rules but detects almost nothing, so enabling it would give the appearance of coverage without any. The rule type is not offered.', 'basic-firewall' ),
		);
	}

	/**
	 * Everything unavailable, with the reason, for the status report.
	 *
	 * @return list<array{feature: string, reason: string}>
	 */
	public function unavailable(): array {
		$missing = array();

		if ( ! $this->has_challenge() ) {
			$missing[] = array(
				'feature' => __( 'Challenges', 'basic-firewall' ),
				'reason'  => __( 'The installed library does not ship the interstitial challenge flow.', 'basic-firewall' ),
			);
		}

		if ( ! $this->has_abuse_ipdb() ) {
			$missing[] = array(
				'feature' => __( 'IP reputation (AbuseIPDB)', 'basic-firewall' ),
				'reason'  => __( 'The installed library does not ship the AbuseIPDB plugin.', 'basic-firewall' ),
			);
		}

		if ( ! $this->has_soft_responses() ) {
			$missing[] = array(
				'feature' => __( 'Redirect and mark responses', 'basic-firewall' ),
				'reason'  => __( 'The installed library cannot redirect a request or mark it without refusing it. Those responses need kanopi/firewall 2.26.0 or later, and are not offered.', 'basic-firewall' ),
			);
		}

		if ( ! $this->has_record_control() ) {
			$missing[] = array(
				'feature' => __( 'Refusing without recording', 'basic-firewall' ),
				'reason'  => __( 'The installed library always records a block in the durable block list. Refusing without recording — what a temporary lockdown needs, so lifting it does not leave every visitor banned — needs kanopi/firewall 2.26.0 or later.', 'basic-firewall' ),
			);
		}

		if ( ! $this->has_identity_verification() ) {
			$missing[] = array(
				'feature' => __( 'Crawler verification', 'basic-firewall' ),
				'reason'  => __( 'The installed library cannot verify a crawler by reverse DNS, so a user agent rule can only take the client at its word. Needs kanopi/firewall 2.20.0 or later.', 'basic-firewall' ),
			);
		}

		$crs = $this->crs_probe();

		if ( 'working' !== $crs['result'] ) {
			$missing[] = array(
				'feature' => __( 'OWASP Core Rule Set', 'basic-firewall' ),
				'reason'  => $crs['reason'],
			);
		}

		return $missing;
	}

	/**
	 * Discard cached probe results. Used after a library update.
	 */
	public function flush(): void {
		delete_option( self::PROBE_OPTION );
	}
}
