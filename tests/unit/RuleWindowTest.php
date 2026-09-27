<?php
/**
 * Tests for rule activity windows.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Rule_Window;
use Kanopi\Firewall\Utility\Schedule;
use PHPUnit\Framework\TestCase;

/**
 * What the rule list says about a scheduled rule, and what the window compiles to.
 *
 * A sleeping rule matches nothing, which from the outside looks exactly like a
 * broken one, so the list has to say which it is and when that changes -- and
 * be right about it across a daylight-saving transition, where the obvious
 * arithmetic is wrong.
 *
 * Every declaration here names its timezone, so nothing reaches WordPress for
 * the site's.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Rule_Window
 * @covers \Kanopi\BasicFirewall\RuleType\Rule_Type_Base::schedule_declaration
 */
final class RuleWindowTest extends TestCase {

	/**
	 * No days, no hours and no dates is no window.
	 */
	public function test_nothing_chosen_is_no_window(): void {
		$this->assertSame( array(), Rule_Type_Base::schedule_declaration( array( 'timezone' => 'UTC' ) ) );
		$this->assertNull( Rule_Window::at( array(), self::instant( '2026-09-21 12:00' ) ) );
	}

	/**
	 * A timezone on its own is not a window either.
	 *
	 * It parses, and leaves the rule awake at all times, which is never what
	 * somebody who opened the window part of the form meant.
	 */
	public function test_a_timezone_alone_is_not_a_window(): void {
		$this->assertSame(
			array(),
			Rule_Type_Base::schedule_declaration(
				array(
					'timezone' => 'Europe/London',
					'days'     => array(),
					'hours'    => '',
				)
			)
		);
	}

	/**
	 * Every day ticked is no restriction, and is not written as seven days.
	 */
	public function test_every_day_is_no_restriction(): void {
		$declaration = Rule_Type_Base::schedule_declaration(
			array(
				'timezone' => 'UTC',
				'days'     => array( 'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun' ),
				'hours'    => '09:00-17:00',
			)
		);

		$this->assertArrayNotHasKey( 'days', $declaration );
		$this->assertSame( '09:00-17:00', $declaration['hours'] );
	}

	/**
	 * Several ranges typed on one line compile to a list the library accepts.
	 *
	 * Handed over as typed, the library reads the line as one malformed range
	 * and the rule does not start.
	 */
	public function test_several_ranges_compile_to_a_list(): void {
		$declaration = Rule_Type_Base::schedule_declaration(
			array(
				'timezone' => 'UTC',
				'hours'    => '06:00-09:00, 17:00-20:00',
			)
		);

		$this->assertSame( array( '06:00-09:00', '17:00-20:00' ), $declaration['hours'] );

		$schedule = Schedule::fromMetadata( $declaration );

		$this->assertInstanceOf( Schedule::class, $schedule );
		$this->assertTrue( $schedule->isActiveAt( self::instant( '2026-09-21 07:00' ) ) );
		$this->assertTrue( $schedule->isActiveAt( self::instant( '2026-09-21 18:00' ) ) );
		$this->assertFalse( $schedule->isActiveAt( self::instant( '2026-09-21 12:00' ) ) );
	}

	/**
	 * One range stays a string, so a file compiled before reads the same.
	 */
	public function test_one_range_stays_a_string(): void {
		$declaration = Rule_Type_Base::schedule_declaration(
			array(
				'timezone' => 'UTC',
				'hours'    => ' 18:00-06:00 ',
			)
		);

		$this->assertSame( '18:00-06:00', $declaration['hours'] );
	}

	/**
	 * Awake, the next change is when it goes to sleep.
	 */
	public function test_the_next_change_is_found(): void {
		$window = Rule_Window::at( self::hours( '09:00-17:00' ), self::instant( '2026-09-21 12:00' ) );

		$this->assertNotNull( $window );
		$this->assertTrue( $window['awake'] );
		$this->assertSame( '2026-09-21 17:00', self::utc( $window['next'] ) );
	}

	/**
	 * Asleep, the next change is when it wakes.
	 */
	public function test_the_change_out_of_sleep_is_found(): void {
		$window = Rule_Window::at( self::hours( '09:00-17:00' ), self::instant( '2026-09-21 20:00' ) );

		$this->assertNotNull( $window );
		$this->assertFalse( $window['awake'] );
		$this->assertSame( '2026-09-22 09:00', self::utc( $window['next'] ) );
	}

	/**
	 * A range can run over midnight.
	 */
	public function test_a_range_can_run_over_midnight(): void {
		$this->assertTrue( Rule_Window::at( self::hours( '18:00-06:00' ), self::instant( '2026-09-21 23:00' ) )['awake'] ?? false );
		$this->assertTrue( Rule_Window::at( self::hours( '18:00-06:00' ), self::instant( '2026-09-22 05:00' ) )['awake'] ?? false );
		$this->assertFalse( Rule_Window::at( self::hours( '18:00-06:00' ), self::instant( '2026-09-22 12:00' ) )['awake'] ?? true );
	}

	/**
	 * The window is read in its own zone, and the change reported in it.
	 */
	public function test_the_window_is_read_in_its_own_zone(): void {
		$declaration = array(
			'timezone' => 'America/Los_Angeles',
			'hours'    => '09:00-17:00',
		);

		// 17:00 UTC is 10:00 in Los Angeles, inside the window.
		$window = Rule_Window::at( $declaration, self::instant( '2026-09-21 17:00' ) );

		$this->assertNotNull( $window );
		$this->assertTrue( $window['awake'] );
		$this->assertSame( 'America/Los_Angeles', $window['timezone']->getName() );
		$this->assertSame( '17:00', $window['next']?->setTimezone( $window['timezone'] )->format( 'H:i' ) );

		// 02:00 UTC is 19:00 the evening before, outside it.
		$this->assertFalse( Rule_Window::at( $declaration, self::instant( '2026-09-21 02:00' ) )['awake'] ?? true );
	}

	/**
	 * Days are honoured, and a rule asleep until Monday says Monday.
	 */
	public function test_days_are_honoured(): void {
		$declaration = array(
			'timezone' => 'UTC',
			'days'     => array( 'mon' ),
		);

		// 2026-09-26 is a Saturday.
		$window = Rule_Window::at( $declaration, self::instant( '2026-09-26 12:00' ) );

		$this->assertNotNull( $window );
		$this->assertFalse( $window['awake'] );
		$this->assertSame( '2026-09-28 00:00', self::utc( $window['next'] ) );
	}

	/**
	 * Spring forward makes a window crossing the gap shorter, not broken.
	 *
	 * In America/Los_Angeles on 2026-03-08 local time jumps from 02:00 to 03:00,
	 * so a 01:00-03:00 window has no 02:00 to be awake in -- and it closes at
	 * the jump, an hour of real time after it opened rather than two.
	 */
	public function test_spring_forward_shortens_the_window(): void {
		$declaration = array(
			'timezone' => 'America/Los_Angeles',
			'hours'    => '01:00-03:00',
		);

		// 09:30 UTC is 01:30 local, before the jump.
		$window = Rule_Window::at( $declaration, self::instant( '2026-03-08 09:30' ) );

		$this->assertNotNull( $window );
		$this->assertTrue( $window['awake'] );
		$this->assertSame( '2026-03-08 10:00', self::utc( $window['next'] ), 'The window closes at the jump, 03:00 local.' );

		// 10:30 UTC is 03:30 local: 02:30 never happened.
		$this->assertFalse( Rule_Window::at( $declaration, self::instant( '2026-03-08 10:30' ) )['awake'] ?? true );
	}

	/**
	 * Fall back makes a window crossing the repeated hour longer.
	 *
	 * On 2026-11-01 in America/Los_Angeles 01:30 happens twice, and both are
	 * 01:30 locally, so both are inside a window covering it.
	 */
	public function test_fall_back_lengthens_the_window(): void {
		$declaration = array(
			'timezone' => 'America/Los_Angeles',
			'hours'    => '01:00-02:00',
		);

		// 08:30 UTC is the first 01:30 local, 09:30 UTC the second.
		$this->assertTrue( Rule_Window::at( $declaration, self::instant( '2026-11-01 08:30' ) )['awake'] ?? false );
		$this->assertTrue( Rule_Window::at( $declaration, self::instant( '2026-11-01 09:30' ) )['awake'] ?? false );
	}

	/**
	 * A rule waiting on a date weeks away says when it wakes.
	 *
	 * Beyond the week a minute-by-minute search would look ahead, which is why
	 * the search starts at the date instead.
	 */
	public function test_a_distant_start_date_is_found(): void {
		$window = Rule_Window::at(
			array(
				'timezone' => 'UTC',
				'from'     => '2026-11-24',
			),
			self::instant( '2026-09-21 12:00' )
		);

		$this->assertNotNull( $window );
		$this->assertFalse( $window['awake'] );
		$this->assertSame( '2026-11-24 00:00', self::utc( $window['next'] ) );
	}

	/**
	 * A window whose last day has passed says it has ended, not that it sleeps.
	 */
	public function test_a_past_end_date_has_ended(): void {
		$window = Rule_Window::at(
			array(
				'timezone' => 'UTC',
				'until'    => '2025-12-02',
			),
			self::instant( '2026-09-21 12:00' )
		);

		$this->assertNotNull( $window );
		$this->assertTrue( $window['ended'] );
		$this->assertNull( $window['next'] );
	}

	/**
	 * A window the library cannot read is reported as such, never as awake.
	 *
	 * @dataProvider unusable_hours
	 *
	 * @param string $hours The configured hours.
	 */
	public function test_an_unreadable_window_is_not_awake( string $hours ): void {
		$window = Rule_Window::at( self::hours( $hours ), self::instant( '2026-09-21 12:00' ) );

		$this->assertNotNull( $window, 'An unreadable window was reported as no window at all.' );
		$this->assertFalse( $window['awake'] );
		$this->assertNotNull( $window['problem'] );
	}

	/**
	 * Cases for test_an_unreadable_window_is_not_awake().
	 *
	 * @return array<string, array{string}>
	 */
	public static function unusable_hours(): array {
		return array(
			'words'             => array( 'business hours' ),
			'one sided'         => array( '09:00-' ),
			'impossible hour'   => array( '25:00-26:00' ),
			'impossible minute' => array( '09:70-17:00' ),
			'no length'         => array( '09:00-09:00' ),
		);
	}

	/**
	 * A UTC declaration with these hours.
	 *
	 * @param string $hours Hours.
	 *
	 * @return array<string, string>
	 */
	private static function hours( string $hours ): array {
		return array(
			'timezone' => 'UTC',
			'hours'    => $hours,
		);
	}

	/**
	 * An instant, in UTC.
	 *
	 * @param string $when `Y-m-d H:i`.
	 */
	private static function instant( string $when ): \DateTimeImmutable {
		return new \DateTimeImmutable( $when, new \DateTimeZone( 'UTC' ) );
	}

	/**
	 * An instant, formatted in UTC.
	 *
	 * @param \DateTimeImmutable|null $when The instant.
	 */
	private static function utc( ?\DateTimeImmutable $when ): ?string {
		return $when?->setTimezone( new \DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i' );
	}
}
