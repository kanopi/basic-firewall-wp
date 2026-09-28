<?php
/**
 * Whether a scheduled rule is awake, and when that changes.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

use Kanopi\Firewall\Utility\Schedule;

/**
 * Answers the two questions the library cannot answer for somebody reading the
 * rule list: is this rule awake *now*, and when does that next change.
 *
 * A sleeping rule matches nothing, which from the outside looks exactly like a
 * broken one. So the rule list says which it is directly, rather than leaving
 * the reader to work out what time it is in another timezone.
 *
 * Whether the rule is awake at a given instant is asked of the library's own
 * `Schedule`, which is what decides at runtime. A second implementation here
 * would agree with it until it did not, and the one that matters is the
 * library's. Only the forward search is this class's own, because the library
 * has no reason to offer one.
 *
 * Free of WordPress, so the unit suite can pin down the daylight-saving cases:
 * everything is wall-clock time in the rule's own zone. On a spring-forward day
 * a window crossing the gap is shorter, and on a fall-back day one crossing the
 * repeated hour is longer. That is followed rather than corrected for, because
 * a rule about business hours should follow the clock on the wall of the
 * business.
 */
final class Rule_Window {

	/**
	 * How far ahead a change is looked for, in days.
	 *
	 * A window can be every day, so eight days is a full week plus the day in
	 * hand -- enough to find the next edge of any weekly schedule -- and a
	 * bound, so a schedule that never opens answers rather than spinning.
	 */
	private const HORIZON_DAYS = 8;

	/**
	 * The state of a rule's window at an instant, or null for no window.
	 *
	 * @param array<string, mixed> $declaration The rule's `active` block, as
	 *                                          Rule_Type_Base::schedule_declaration()
	 *                                          builds it.
	 * @param \DateTimeImmutable   $now         The instant to ask about.
	 *
	 * @return array{awake: bool, next: \DateTimeImmutable|null, ended: bool, timezone: \DateTimeZone, problem: string|null}|null
	 */
	public static function at( array $declaration, \DateTimeImmutable $now ): ?array {
		if ( array() === $declaration ) {
			return null;
		}

		try {
			$schedule = Schedule::fromMetadata( $declaration );
		} catch ( \InvalidArgumentException $e ) {
			/*
			 * The library does not guess at a window it cannot read -- the
			 * rule fails to start, which is neither awake nor asleep. Said as
			 * its own state so the rule list does not report a rule that is
			 * not running as one that is merely waiting.
			 */
			return array(
				'awake'    => false,
				'next'     => null,
				'ended'    => false,
				'timezone' => new \DateTimeZone( 'UTC' ),
				'problem'  => $e->getMessage(),
			);
		}

		if ( null === $schedule || $schedule->isAlwaysActive() ) {
			return null;
		}

		$zone  = $schedule->getTimezone();
		$awake = $schedule->isActiveAt( $now );
		$until = self::boundary( $declaration['until'] ?? null, $zone, true );

		/*
		 * A window whose last day has passed will not open again, and saying
		 * "asleep" about it would suggest it might. Worth its own word: it is
		 * the rule somebody added for last year's campaign and forgot.
		 */
		if ( ! $awake && null !== $until && $now >= $until ) {
			return array(
				'awake'    => false,
				'next'     => null,
				'ended'    => true,
				'timezone' => $zone,
				'problem'  => null,
			);
		}

		return array(
			'awake'    => $awake,
			'next'     => self::next_change( $schedule, $declaration, $now, $awake ),
			'ended'    => false,
			'timezone' => $zone,
			'problem'  => null,
		);
	}

	/**
	 * The first minute after `$now` at which the rule's state differs.
	 *
	 * Walked a minute at a time, which is the granularity a window is written
	 * in. A rule waiting on a `from` date weeks away starts the walk there
	 * rather than walking every minute until then: it cannot wake earlier.
	 *
	 * @param Schedule             $schedule    The parsed window.
	 * @param array<string, mixed> $declaration The declaration, for its dates.
	 * @param \DateTimeImmutable   $now         The instant to look forward from.
	 * @param bool                 $awake       Whether it is awake at `$now`.
	 */
	private static function next_change( Schedule $schedule, array $declaration, \DateTimeImmutable $now, bool $awake ): ?\DateTimeImmutable {
		$zone   = $schedule->getTimezone();
		$local  = $now->setTimezone( $zone );
		$cursor = $local->setTime( (int) $local->format( 'G' ), (int) $local->format( 'i' ) );

		$from = self::boundary( $declaration['from'] ?? null, $zone, false );

		if ( ! $awake && null !== $from && $from > $cursor ) {
			$cursor = $from->modify( '-1 minute' );
		}

		$limit = self::HORIZON_DAYS * 24 * 60;

		for ( $step = 1; $step <= $limit; $step++ ) {
			$candidate = $cursor->modify( sprintf( '+%d minutes', $step ) );

			if ( $schedule->isActiveAt( $candidate ) !== $awake ) {
				return $candidate;
			}
		}

		return null;
	}

	/**
	 * A `from` or `until` date as an instant, read the way the library reads it.
	 *
	 * A bare date for `until` closes at the end of that day, because the other
	 * reading makes a one-day campaign run for no time at all.
	 *
	 * @param mixed         $value The configured boundary.
	 * @param \DateTimeZone $zone  The rule's zone.
	 * @param bool          $until Whether this is the closing boundary.
	 */
	private static function boundary( $value, \DateTimeZone $zone, bool $until ): ?\DateTimeImmutable {
		$written = is_string( $value ) ? trim( $value ) : '';

		if ( 1 === preg_match( '/^\d{4}-\d{2}-\d{2}$/', $written ) ) {
			$day = \DateTimeImmutable::createFromFormat( '!Y-m-d', $written, $zone );

			if ( false === $day ) {
				return null;
			}

			return $until ? $day->modify( '+1 day' ) : $day;
		}

		if ( 1 === preg_match( '/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}$/', $written ) ) {
			$stamp = \DateTimeImmutable::createFromFormat( '!Y-m-d H:i', str_replace( 'T', ' ', $written ), $zone );

			return false === $stamp ? null : $stamp;
		}

		return null;
	}
}
