<?php
/**
 * The AbuseIPDB IP reputation rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\Firewall\Plugins\AbuseIpdb;

/**
 * Matches on the AbuseIPDB confidence score for the client address.
 *
 * Four things are worth knowing before relying on this rule.
 *
 * **It fails open.** A timeout, a rejected key or an exhausted quota counts as
 * "no match" and evaluation carries on. A third-party outage must not become an
 * outage here. Addresses that must be blocked regardless of what AbuseIPDB
 * thinks belong in an IP address rule, which consults nothing.
 *
 * **Quota is the real constraint.** The free tier allows 1,000 checks a day,
 * which one call per request would exhaust before lunch. Verdicts are cached per
 * address -- clean results included -- so the cost is roughly one lookup per
 * unique visitor per day. Failed lookups are cached too, for a much shorter
 * window: without that, an outage makes every request wait out the full timeout,
 * which is availability on paper and a crawling site in practice.
 *
 * **Private and reserved addresses are never looked up**, so local and intranet
 * traffic spends nothing.
 *
 * **Addresses AbuseIPDB marks as known-good never match**, whatever they score.
 * Search engine crawlers accumulate reports, and blocking one would remove the
 * site from search results.
 */
final class Abuse_Ipdb extends Rule_Type_Base {

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'abuse_ipdb';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'IP reputation (AbuseIPDB)', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Matches when AbuseIPDB has reported the client address with at least your confidence score. Needs a free API key. One cached lookup per visitor per day, and it fails open.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return AbuseIpdb::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return 20;
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return array(
			// 75 is AbuseIPDB's own "confident enough to act on" mark. Below
			// about 25 the rule starts turning away real people whose home
			// address was previously used by somebody else.
			'threshold'    => 75,
			'api_key'      => '',
			'cache_ttl'    => 86400,
			'timeout'      => 5,
			'max_age_days' => 90,
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed>  $settings Described by the interface.
	 * @param array<string, string> $errors Described by the interface.
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		$threshold = (int) ( $settings['threshold'] ?? 75 );

		if ( $threshold < 1 || $threshold > 100 ) {
			$errors['threshold'] = __( 'The confidence score runs from 1 to 100.', 'basic-firewall' );
			$threshold           = 75;
		}

		$key = trim( (string) ( $settings['api_key'] ?? '' ) );

		if ( '' === $key ) {
			$errors['api_key'] = __( 'This rule needs an AbuseIPDB API key. Without one every lookup fails, and because the rule fails open it would match nothing at all.', 'basic-firewall' );
		}

		return array(
			'threshold'    => $threshold,
			'api_key'      => $key,
			'cache_ttl'    => max( 60, (int) ( $settings['cache_ttl'] ?? 86400 ) ),
			'timeout'      => max( 1, (int) ( $settings['timeout'] ?? 5 ) ),
			'max_age_days' => max( 1, (int) ( $settings['max_age_days'] ?? 90 ) ),
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry    = $this->base_entry( $rule );
		$settings = $rule['settings'] ?? array();

		$entry['config'] = array(
			'api_key'      => (string) ( $settings['api_key'] ?? '' ),
			'threshold'    => (int) ( $settings['threshold'] ?? 75 ),
			'cache_ttl'    => (int) ( $settings['cache_ttl'] ?? 86400 ),
			'timeout'      => (int) ( $settings['timeout'] ?? 5 ),
			'max_age_days' => (int) ( $settings['max_age_days'] ?? 90 ),

			/*
			 * Pointed at the private directory rather than left to the library's
			 * system-temporary fallback. A temp directory is cleared
			 * periodically, and each time it is, the rule starts spending quota
			 * from scratch. Entries are named by hash, so client addresses
			 * cannot be read from a directory listing.
			 */
			'cache_dir'    => Plugin::instance()->paths()->base() . '/abuseipdb',
		);

		return $entry;
	}

	/**
	 * {@inheritDoc}
	 */
	public function secret_settings(): array {
		return array( 'api_key' );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function summarize( array $settings ): array {
		return array(
			sprintf(
				/* translators: %d: confidence score. */
				__( 'Matches an address reported with a confidence score of %d or more.', 'basic-firewall' ),
				(int) ( $settings['threshold'] ?? 75 )
			),
		);
	}
}
