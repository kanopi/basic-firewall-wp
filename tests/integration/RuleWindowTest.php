<?php
/**
 * Rule activity windows, on the screens and in the compiled file.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Rules_Screen;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Utility\Schedule;
use Symfony\Component\Yaml\Yaml;

/**
 * A rule that is on only when it should be.
 *
 * Two ways this went wrong, and both looked fine:
 *
 * - Several hour ranges were typed on one line and handed to the library as
 *   typed. It reads one string as one range, refuses the line as malformed, and
 *   the rule does not start at all.
 * - A sleeping rule matches nothing, which from the rule list looks exactly
 *   like a broken one. The list now says which it is, and until when.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rules_Screen
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\RuleType\Rule_Window
 */
final class RuleWindowTest extends Settings_Snapshot {

	/**
	 * Request globals, put back after each test.
	 *
	 * @var array{get: array<mixed>, post: array<mixed>, user: int}
	 */
	private array $globals;

	/**
	 * Remember the request globals.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->globals = array(
			'get'  => $_GET, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'post' => $_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'user' => get_current_user_id(),
		);
	}

	/**
	 * Put them back, and drop any notices a screen queued.
	 */
	protected function tearDown(): void {
		delete_transient( 'basic_firewall_notices_' . get_current_user_id() );
		remove_all_filters( 'wp_redirect' );

		$_GET  = $this->globals['get'];
		$_POST = $this->globals['post'];
		wp_set_current_user( $this->globals['user'] );

		parent::tearDown();
	}

	/**
	 * The rule screen offers the window.
	 */
	public function test_the_rule_screen_offers_a_window(): void {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		$_GET = array( 'type' => 'url' );

		ob_start();
		( new Rule_Edit_Screen() )->render();
		$rendered = (string) ob_get_clean();

		foreach ( array( 'schedule_timezone', 'schedule_days[]', 'schedule_hours', 'schedule_from', 'schedule_until' ) as $field ) {
			$this->assertStringContainsString( sprintf( 'name="%s"', $field ), $rendered );
		}
	}

	/**
	 * Several ranges save, and compile to something the library will start.
	 */
	public function test_several_ranges_save_and_compile(): void {
		$this->given_rules( array() );

		$saved = $this->submit_rule(
			array(
				'schedule_timezone' => 'UTC',
				'schedule_days'     => array( 'mon', 'fri' ),
				'schedule_hours'    => '06:00-09:00, 17:00-20:00',
			)
		);

		$this->assertTrue( $saved, 'A window with two ranges was refused: ' . $this->queued_notices() );

		$this->assertSame( '06:00-09:00, 17:00-20:00', $this->stored_rules()[0]['schedule']['hours'], 'Stored as typed.' );

		$active = $this->compiled_rule( 'test_rule' )['metadata']['active'] ?? null;

		$this->assertIsArray( $active );
		$this->assertSame( array( '06:00-09:00', '17:00-20:00' ), $active['hours'], 'Compiled as a list.' );
		$this->assertSame( array( 'mon', 'fri' ), $active['days'] );
		$this->assertInstanceOf( Schedule::class, Schedule::fromMetadata( $active ), 'The library would not start the rule.' );
	}

	/**
	 * A range the library cannot read is refused, in the library's words.
	 */
	public function test_an_unreadable_range_is_refused(): void {
		$this->given_rules( array() );

		$this->assertFalse( $this->submit_rule( array( 'schedule_hours' => 'business hours' ) ) );
		$this->assertSame( array(), $this->stored_rules() );
		$this->assertStringContainsString( 'HH:MM-HH:MM', $this->queued_notices() );
	}

	/**
	 * A range that starts and ends together is refused rather than never waking.
	 */
	public function test_an_empty_range_is_refused(): void {
		$this->given_rules( array() );

		$this->assertFalse( $this->submit_rule( array( 'schedule_hours' => '09:00-09:00' ) ) );
		$this->assertSame( array(), $this->stored_rules() );
		$this->assertStringContainsString( 'starts and ends at the same time', $this->queued_notices() );
	}

	/**
	 * A timezone on its own compiles no window.
	 */
	public function test_a_timezone_alone_compiles_no_window(): void {
		$this->given_rules( array( $this->rule( 'windowed', array( 'timezone' => 'Europe/London' ) ) ) );

		$this->assertArrayNotHasKey( 'active', $this->compiled_rule( 'windowed' )['metadata'] ?? array() );
	}

	/**
	 * An imported window the library cannot read is skipped, and said.
	 *
	 * The library fails such a rule at startup anyway. Skipping it here is what
	 * puts its name on the Status screen, instead of leaving it to be noticed
	 * by its absence.
	 */
	public function test_an_imported_unreadable_window_is_skipped_and_reported(): void {
		$this->given_rules( array( $this->rule( 'windowed', array( 'hours' => '25:00-26:00' ) ) ) );

		$outcome = Plugin::instance()->compiled()->rebuild();

		$this->assertStringContainsString( '"windowed"', implode( "\n", $outcome['problems'] ) );
		$this->assertNull( $this->compiled_rule( 'windowed' ) );
	}

	/**
	 * The rule list says a sleeping rule is asleep, and when it wakes.
	 */
	public function test_the_rule_list_says_a_sleeping_rule_is_asleep(): void {
		$this->given_rules( array( $this->rule( 'windowed', array( 'days' => array( self::not_today() ) ) ) ) );

		$rendered = $this->rule_list();

		$this->assertStringContainsString( 'asleep now', $rendered );
		$this->assertStringContainsString( 'until', $rendered );
	}

	/**
	 * A rule with no window says nothing about windows.
	 *
	 * Every rule would otherwise gain a note saying it is awake, which is what
	 * every rule has always been.
	 */
	public function test_an_unscheduled_rule_says_nothing_about_windows(): void {
		$this->given_rules( array( $this->rule( 'always' ) ) );

		$rendered = $this->rule_list();

		$this->assertStringNotContainsString( 'asleep now', $rendered );
		$this->assertStringNotContainsString( 'awake now', $rendered );
	}

	/**
	 * Observing is still said on a scheduled rule.
	 *
	 * "Block — awake now" over a rule that refuses nobody would be the list
	 * misleading whoever opened it to check.
	 */
	public function test_observing_is_still_said_on_a_scheduled_rule(): void {
		$rule            = $this->rule( 'windowed', array( 'days' => array( self::not_today() ) ) );
		$rule['observe'] = true;

		$this->given_rules( array( $rule ) );

		$rendered = $this->rule_list();

		$this->assertStringContainsString( 'observing only', $rendered );
		$this->assertStringContainsString( 'asleep now', $rendered );
	}

	/**
	 * A day of the week that is not today, in UTC.
	 */
	private static function not_today(): string {
		$keys  = array( 'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun' );
		$today = (int) ( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( 'N' );

		// N is 1-7 and the list is 0-6, so this is always two days from today.
		return $keys[ ( $today + 1 ) % 7 ];
	}

	/**
	 * Render the rule list.
	 */
	private function rule_list(): string {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		$_GET = array();

		ob_start();
		( new Rules_Screen() )->render();

		return (string) ob_get_clean();
	}

	/**
	 * Post the rule form for a new URL rule.
	 *
	 * @param array<string, mixed> $fields Fields over the defaults.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	private function submit_rule( array $fields ): bool {
		$this->as_administrator();

		$_GET  = array( 'type' => 'url' );
		$_POST = $fields + array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-rule' ),
			'label'                => 'Test rule',
			'rule_id'              => 'test_rule',
			'enabled'              => '1',
			'response'             => 'block',
			'weight'               => '0',
			'expiration'           => '3600',
			'settings'             => array(
				'match_type' => 'any',
				'conditions' => array(
					array(
						'variable' => 'path',
						'operator' => 'contains',
						'value'    => '/probe',
					),
				),
			),
		);

		// A successful save redirects and exits; stop it at the redirect.
		add_filter(
			'wp_redirect',
			static function (): void {
				throw new \RuntimeException( 'redirected' );
			}
		);

		try {
			( new Rule_Edit_Screen() )->handle();
		} catch ( \RuntimeException $e ) {
			return 'redirected' === $e->getMessage();
		}

		return false;
	}

	/**
	 * Act as an administrator, who holds the plugin's capability.
	 */
	private function as_administrator(): void {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'number' => 1,
				'fields' => 'ID',
			)
		);

		if ( array() === $admins ) {
			$this->markTestSkipped( 'This site has no administrator to act as.' );
		}

		wp_set_current_user( (int) $admins[0] );
	}

	/**
	 * The notices the screen queued, as one string.
	 */
	private function queued_notices(): string {
		$queue = get_transient( 'basic_firewall_notices_' . get_current_user_id() );

		return implode( "\n", array_column( is_array( $queue ) ? $queue : array(), 'message' ) );
	}

	/**
	 * The stored rules.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function stored_rules(): array {
		Plugin::instance()->settings()->flush();

		return array_values( (array) Plugin::instance()->settings()->get( 'rules', array() ) );
	}

	/**
	 * One rule's entry in the compiled file, or null when it is not there.
	 *
	 * @param string $id Rule identifier.
	 *
	 * @return array<string, mixed>|null
	 */
	private function compiled_rule( string $id ): ?array {
		Plugin::instance()->compiled()->rebuild();

		$compiled = Yaml::parseFile( Plugin::instance()->paths()->compiled_file() );

		foreach ( (array) ( $compiled['plugins'] ?? array() ) as $entry ) {
			if ( is_array( $entry ) && ( $entry['metadata']['name'] ?? null ) === $id ) {
				return $entry;
			}
		}

		return null;
	}

	/**
	 * Install a rule set and compile it.
	 *
	 * @param list<array<string, mixed>> $rules Rules.
	 */
	private function given_rules( array $rules ): void {
		$this->given_settings( array( 'enabled' => true ) );
		Plugin::instance()->settings()->set( 'rules', $rules );
		Plugin::instance()->compiled()->rebuild();
	}

	/**
	 * A URL rule with a window.
	 *
	 * @param string               $id       Identifier.
	 * @param array<string, mixed> $schedule The window.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $id, array $schedule = array() ): array {
		return array(
			'id'              => $id,
			'type'            => 'url',
			'label'           => ucfirst( $id ),
			'enabled'         => true,
			'observe'         => false,
			'response'        => 'block',
			'weight'          => 0,
			'status_code'     => 403,
			'record'          => 'default',
			'redirect_to'     => '',
			'redirect_status' => 302,
			'mark_as'         => '',
			'mark_header'     => '',
			'expiration'      => 0,
			'schedule'        => $schedule + array(
				'timezone' => 'UTC',
				'days'     => array(),
				'hours'    => '',
				'from'     => '',
				'until'    => '',
			),
			'settings'        => array(
				'match_type' => 'any',
				'sources'    => array(),
				'conditions' => array(
					array(
						'variable' => 'path',
						'operator' => 'contains',
						'value'    => '/probe',
					),
				),
			),
		);
	}
}
