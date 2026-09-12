<?php
/**
 * The OWASP Core Rule Set rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\Firewall\Plugins\Crs as LibraryCrs;

/**
 * Evaluates the request against the OWASP Core Rule Set.
 *
 * The one rule type that will reject legitimate traffic if enabled carelessly,
 * so it ships in monitor mode and the screen says why.
 *
 * **How a request gets rejected.** Every CRS rule that matches contributes
 * points by severity -- critical 5, error 4, warning 3, notice 2 -- and rule
 * 949110 rejects the request once the total reaches the inbound anomaly
 * threshold, which defaults to 5. So a single critical finding reaches the
 * default threshold on its own.
 *
 * **Handling a false positive.** Take the rule IDs from the `contributing_rules`
 * field of the log entry and silence those. Do **not** use `rule_id` for this:
 * on a score-based block it is always `949110`, the rule that compares the
 * accumulated score against the threshold rather than the rule that detected
 * anything. Disabling it switches off score-based blocking for the entire rule
 * set. The same applies to the `blocking_evaluation` category.
 *
 * Prefer silencing specific IDs over raising the threshold, and prefer either
 * over disabling a whole category -- a category removes far more coverage than
 * people usually intend.
 *
 * **Cost.** Real work on every request, roughly 3-4 ms once the rule cache is
 * warm. Give it a high weight so cheap checks deal with obvious traffic first.
 */
final class Crs extends Rule_Type_Base {

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'crs';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'OWASP Core Rule Set', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Evaluates the request against the full OWASP Core Rule Set. Broad coverage, real per-request cost, and it will reject legitimate traffic unless tuned. Starts in monitor mode.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return LibraryCrs::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return 100;
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return array(
			// Monitor, always. The rule set is evaluated and matches are logged,
			// but nothing is rejected until somebody has read the log.
			'mode'          => 'monitor',
			'paranoia'      => 1,
			'inbound'       => 5,
			'outbound'      => 4,
			'disabled_rules' => array(),
			'disabled_categories' => array(),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		$mode = (string) ( $settings['mode'] ?? 'monitor' );

		if ( ! in_array( $mode, array( 'monitor', 'block' ), true ) ) {
			$mode = 'monitor';
		}

		$paranoia = (int) ( $settings['paranoia'] ?? 1 );

		if ( $paranoia < 1 || $paranoia > 4 ) {
			$errors['paranoia'] = __( 'Paranoia runs from 1 to 4. Level 1 is the recommended starting point.', 'basic-firewall' );
			$paranoia           = 1;
		}

		$disabled = array();

		foreach ( self::lines_to_list( $settings['disabled_rules'] ?? array() ) as $id ) {
			if ( ! ctype_digit( $id ) ) {
				$errors['disabled_rules'] = sprintf(
					/* translators: %s: the rejected entry. */
					__( '%s is not a rule ID. Take these from the contributing_rules field of a log entry.', 'basic-firewall' ),
					$id
				);

				continue;
			}

			/*
			 * 949110 is the rule that compares the accumulated score against the
			 * threshold, not a rule that detected anything. Disabling it turns
			 * off score-based blocking for the entire rule set, which is almost
			 * never what somebody silencing a false positive intends.
			 */
			if ( '949110' === $id ) {
				$errors['disabled_rules'] = __( 'Rule 949110 is the one that compares the accumulated score against your threshold, not a rule that detected anything. Disabling it switches off score-based blocking for the whole rule set. Silence the IDs from contributing_rules instead.', 'basic-firewall' );

				continue;
			}

			$disabled[] = $id;
		}

		$categories = array();

		foreach ( self::lines_to_list( $settings['disabled_categories'] ?? array() ) as $category ) {
			if ( 'blocking_evaluation' === $category ) {
				$errors['disabled_categories'] = __( 'The blocking_evaluation category is what performs the score comparison. Disabling it switches off score-based blocking for the whole rule set.', 'basic-firewall' );

				continue;
			}

			$categories[] = $category;
		}

		return array(
			'mode'                => $mode,
			'paranoia'            => $paranoia,
			'inbound'             => max( 1, (int) ( $settings['inbound'] ?? 5 ) ),
			'outbound'            => max( 1, (int) ( $settings['outbound'] ?? 4 ) ),
			'disabled_rules'      => $disabled,
			'disabled_categories' => $categories,
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function compile( array $rule ): array {
		$entry    = $this->base_entry( $rule );
		$settings = $rule['settings'] ?? array();

		$config = array(
			'mode'     => (string) ( $settings['mode'] ?? 'monitor' ),
			'paranoia' => (int) ( $settings['paranoia'] ?? 1 ),
			'anomaly_threshold' => array(
				/*
				 * The `inbound` / `outbound` key names, not the old severity
				 * names. Before library v2.9.0 only the severity names were
				 * read, so these keys fell back to defaults silently and a tuned
				 * threshold stopped applying with nothing reporting it.
				 */
				'inbound'  => (int) ( $settings['inbound'] ?? 5 ),
				'outbound' => (int) ( $settings['outbound'] ?? 4 ),
			),
		);

		if ( array() !== ( $settings['disabled_rules'] ?? array() ) ) {
			$config['disabled_rules'] = array_values( $settings['disabled_rules'] );
		}

		if ( array() !== ( $settings['disabled_categories'] ?? array() ) ) {
			$config['disabled_categories'] = array_values( $settings['disabled_categories'] );
		}

		$entry['config'] = $config;

		return $entry;
	}

	/**
	 * The class existing is not evidence that it works.
	 *
	 * This plugin has shipped broken in both directions: v2.8.0 inverted the
	 * verdict so every ordinary request matched and real attacks passed, and
	 * crs-engine 0.1.0 parsed the rules but detected almost nothing -- which
	 * looked fine and protected nothing. So availability is a behavioural probe
	 * rather than a class_exists(), run once per library version and cached.
	 *
	 * {@inheritDoc}
	 */
	public function is_available(): bool {
		return ( new \Kanopi\BasicFirewall\Library_Capabilities() )->has_working_crs();
	}

	/**
	 * {@inheritDoc}
	 */
	public function summarize( array $settings ): array {
		$lines = array(
			'monitor' === ( $settings['mode'] ?? 'monitor' )
				? __( 'Monitor only — matches are logged, nothing is rejected.', 'basic-firewall' )
				: __( 'Blocking — requests reaching the threshold are rejected.', 'basic-firewall' ),
			sprintf(
				/* translators: 1: paranoia level, 2: inbound anomaly threshold. */
				__( 'Paranoia %1$d, inbound threshold %2$d.', 'basic-firewall' ),
				(int) ( $settings['paranoia'] ?? 1 ),
				(int) ( $settings['inbound'] ?? 5 )
			),
		);

		if ( array() !== ( $settings['disabled_rules'] ?? array() ) ) {
			$lines[] = sprintf(
				/* translators: %d: number of silenced rule IDs. */
				__( '%d rule ID(s) silenced.', 'basic-firewall' ),
				count( $settings['disabled_rules'] )
			);
		}

		return $lines;
	}
}
