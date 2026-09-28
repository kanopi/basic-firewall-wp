<?php
/**
 * Per-rule observe mode.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Rules_Screen;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Request_Tester;

/**
 * One rule tried on live traffic, while every other rule keeps enforcing.
 *
 * Without it the choices were enforcing a rule nobody had measured, or putting
 * the whole firewall into log mode and switching every other rule off with it
 * -- which is why unsure rules got left disabled, where they say nothing at all.
 *
 * The property everything rests on is the direction it fails in. A rule the
 * screen says is observing must never refuse anybody: that is the case pinned
 * here with its control beside it, because a rule that simply never matched
 * would satisfy the first half on its own.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Rule_Type_Base
 * @covers \Kanopi\BasicFirewall\Request_Tester
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rules_Screen
 */
final class ObserveModeTest extends Settings_Snapshot {

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
	 * An observing rule compiles the mode the library reads.
	 */
	public function test_an_observing_rule_compiles_the_mode(): void {
		$this->assertSame( 'log', $this->metadata_for( $this->rule( 'trial', 'block', true ) )['mode'] ?? null );
	}

	/**
	 * An enforcing rule writes no mode at all.
	 *
	 * `block` and `enforce` are both accepted upstream and both mean what an
	 * absent key means, so writing one would put a value in an exported
	 * document that changes nothing.
	 */
	public function test_an_enforcing_rule_writes_no_mode(): void {
		$this->assertArrayNotHasKey( 'mode', $this->metadata_for( $this->rule( 'trial', 'block', false ) ) );
	}

	/**
	 * Observing is written whatever the rule would otherwise have done.
	 */
	public function test_observing_is_independent_of_the_response(): void {
		foreach ( array( 'challenge', 'allow', 'redirect', 'mark', 'record' ) as $response ) {
			$this->assertSame(
				'log',
				$this->metadata_for( $this->rule( 'watch', $response, true ) )['mode'] ?? null,
				sprintf( 'An observing %s rule compiled without the mode.', $response )
			);
		}
	}

	/**
	 * An observed match does not refuse the request.
	 */
	public function test_an_observed_match_does_not_refuse(): void {
		$this->given_rules( array( $this->rule( 'trial', 'block', true ) ) );

		$this->assertNotSame( 'block', $this->test_request( '/probe' )['verdict'], 'An observing rule refused the request.' );
	}

	/**
	 * The same rule set to enforce does refuse.
	 */
	public function test_the_same_rule_enforcing_does_refuse(): void {
		$this->given_rules( array( $this->rule( 'trial', 'block', false ) ) );

		$this->assertSame( 'block', $this->test_request( '/probe' )['verdict'] );
	}

	/**
	 * Every other rule keeps enforcing.
	 *
	 * The difference between this and switching the whole firewall to log mode.
	 */
	public function test_other_rules_keep_enforcing(): void {
		$this->given_rules(
			array(
				$this->rule( 'trial', 'block', true ),
				$this->rule( 'established', 'block', false, '/probe' ),
			)
		);

		$result = $this->test_request( '/probe' );

		$this->assertSame( 'block', $result['verdict'] );
	}

	/**
	 * The tester reports an observed match rather than calling it allowed.
	 *
	 * An observed match is treated as no match, so the request really is
	 * allowed -- and saying only that tells somebody testing the rule they just
	 * set to observe that it does not work, at the moment it is working.
	 */
	public function test_an_observed_match_is_reported_distinctly_from_allowed(): void {
		$this->given_rules( array( $this->rule( 'trial', 'block', true ) ) );

		$result = $this->test_request( '/probe' );

		$this->assertSame( 'observe', $result['verdict'] );
		$this->assertSame( 'trial', $result['rule'], 'The rule that matched is named.' );
	}

	/**
	 * A request no observing rule matches is plainly allowed.
	 */
	public function test_an_unmatched_request_is_still_allowed(): void {
		$this->given_rules( array( $this->rule( 'trial', 'block', true ) ) );

		$this->assertSame( 'allow', $this->test_request( '/ordinary' )['verdict'] );
	}

	/**
	 * The rule screen offers the box.
	 */
	public function test_the_rule_screen_offers_observing(): void {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		$_GET = array( 'type' => 'url' );

		ob_start();
		( new Rule_Edit_Screen() )->render();
		$rendered = (string) ob_get_clean();

		$this->assertStringContainsString( 'name="observe"', $rendered );
	}

	/**
	 * Ticking the box stores an observing rule, and clearing it enforces again.
	 */
	public function test_observing_saves_and_can_be_turned_off_again(): void {
		$this->given_rules( array() );

		$this->assertTrue( $this->submit_url_rule( array( 'observe' => '1' ) ), 'The rule was not saved.' );
		$this->assertTrue( $this->stored_rules()[0]['observe'] );

		$_GET = array( 'rule' => 'test_rule' );

		$this->assertTrue( $this->submit_url_rule( array(), 'test_rule' ), 'The edit was not saved.' );
		$this->assertFalse( $this->stored_rules()[0]['observe'], 'Clearing the box left the rule observing.' );
	}

	/**
	 * The rule list says a rule is observing, and is quiet when it is not.
	 *
	 * A row reading "Block" on a rule that refuses nobody is the listing
	 * misleading whoever opened it to check what the firewall does.
	 */
	public function test_the_rule_list_says_the_rule_is_observing(): void {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		$this->given_rules(
			array(
				$this->rule( 'trial', 'block', true ),
				$this->rule( 'established', 'challenge', false ),
			)
		);

		$_GET = array();

		ob_start();
		( new Rules_Screen() )->render();
		$rendered = (string) ob_get_clean();

		$this->assertStringContainsString( 'Block — observing only', $rendered );
		$this->assertStringNotContainsString( 'Challenge — observing only', $rendered );
	}

	/**
	 * Post the rule form for a URL rule.
	 *
	 * @param array<string, string> $fields  Fields over the defaults.
	 * @param string                $editing The identifier being edited, or '' for a new rule.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	private function submit_url_rule( array $fields, string $editing = '' ): bool {
		$this->as_administrator();

		$_GET  = '' === $editing ? array( 'type' => 'url' ) : array( 'rule' => $editing );
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
	 * The stored rules.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function stored_rules(): array {
		Plugin::instance()->settings()->flush();

		return array_values( (array) Plugin::instance()->settings()->get( 'rules', array() ) );
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
	 * Ask the tester about a path.
	 *
	 * @param string $path The path.
	 *
	 * @return array{verdict: string, status: int|null, rule: string|null, message: string, log: list<string>, error: string|null}
	 */
	private function test_request( string $path ): array {
		return ( new Request_Tester() )->test(
			array(
				'path' => $path,
				'ip'   => '203.0.113.10',
			)
		);
	}

	/**
	 * The metadata one rule compiles to.
	 *
	 * @param array<string, mixed> $rule The rule.
	 *
	 * @return array<string, mixed>
	 */
	private function metadata_for( array $rule ): array {
		$type = Plugin::instance()->rule_types()->get( 'url' );

		$this->assertNotNull( $type );

		return (array) ( $type->compile( $rule )['metadata'] ?? array() );
	}

	/**
	 * A URL rule matching a path.
	 *
	 * @param string $id       Identifier.
	 * @param string $response Response.
	 * @param bool   $observe  Whether it only observes.
	 * @param string $path     Path fragment.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $id, string $response, bool $observe, string $path = '/probe' ): array {
		return array(
			'id'              => $id,
			'type'            => 'url',
			'label'           => ucfirst( $id ),
			'enabled'         => true,
			'observe'         => $observe,
			'response'        => $response,
			'weight'          => 0,
			'status_code'     => 403,
			'record'          => 'default',
			'redirect_to'     => 'redirect' === $response ? '/elsewhere' : '',
			'redirect_status' => 302,
			'mark_as'         => '',
			'mark_header'     => '',
			'expiration'      => 0,
			'settings'        => array(
				'match_type' => 'any',
				'sources'    => array(),
				'conditions' => array(
					array(
						'variable' => 'path',
						'operator' => 'contains',
						'value'    => $path,
					),
				),
			),
		);
	}
}
