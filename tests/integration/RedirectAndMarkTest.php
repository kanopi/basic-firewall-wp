<?php
/**
 * Redirect, mark and record rules, from the screen through to the tester.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Request_Tester;

/**
 * The three responses that do not simply refuse, and the ways they went wrong.
 *
 * Each of them serves the request or sends it elsewhere, which is what made
 * them easy to get wrong without anybody noticing:
 *
 * - The request tester reported a working redirect rule as "could not be
 *   tested", because a redirect in `exception` mode is an exception it did not
 *   know by name; and it reported a record or mark rule that had just fired as
 *   "no rule matched", because both serve the request by design.
 * - The rule screen only rendered the destination field once a rule had been
 *   *saved* as a redirect, so the first save of a new redirect rule stored one
 *   naming nowhere -- which the library throws on whenever the rule matches.
 *
 * @covers \Kanopi\BasicFirewall\Request_Tester
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 */
final class RedirectAndMarkTest extends Settings_Snapshot {

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
	 * A redirect rule is reported as a redirect, not as an error.
	 */
	public function test_a_redirected_request_is_reported_as_redirected(): void {
		$this->given_rules(
			array(
				$this->url_rule(
					'bounce',
					'redirect',
					'/deprecated-api',
					array(
						'redirect_to'     => '/api/v2',
						'redirect_status' => 308,
					)
				),
			)
		);

		$result = $this->test_request( '/deprecated-api' );

		$this->assertSame( 'redirect', $result['verdict'], (string) $result['message'] );
		$this->assertSame( 308, $result['status'], 'The status the visitor would receive.' );
		$this->assertStringContainsString( '/api/v2', $result['message'], 'And where they would go.' );
	}

	/**
	 * A mark rule is reported as marked, not merely allowed.
	 *
	 * "Allowed" is true and useless: it is exactly what the screen says when the
	 * rule did not match at all.
	 */
	public function test_a_marked_request_is_reported_distinctly_from_allowed(): void {
		$this->given_rules( array( $this->url_rule( 'suspicious', 'mark', '/xmlrpc.php', array( 'mark_as' => 'probe' ) ) ) );

		$result = $this->test_request( '/xmlrpc.php' );

		$this->assertSame( 'mark', $result['verdict'] );
		$this->assertSame( 'suspicious', $result['rule'], 'The rule that noticed is named.' );
		$this->assertStringContainsString( 'probe', $result['message'], 'And the mark it left.' );
	}

	/**
	 * A request outside a mark rule is plainly allowed.
	 */
	public function test_a_request_outside_the_mark_rule_is_still_allowed(): void {
		$this->given_rules( array( $this->url_rule( 'suspicious', 'mark', '/xmlrpc.php', array( 'mark_as' => 'probe' ) ) ) );

		$this->assertSame( 'allow', $this->test_request( '/ordinary' )['verdict'] );
	}

	/**
	 * A blocked request that a mark rule also matched is reported as blocked.
	 *
	 * Marking runs before the terminal responses and on a request that is about
	 * to be refused, deliberately -- a mark that only appeared on requests
	 * nobody refused could not be correlated with a block. Both fire, and the
	 * tester has to report the one that decides what happens.
	 */
	public function test_a_block_outranks_a_mark_on_the_same_request(): void {
		$this->given_rules(
			array(
				$this->url_rule( 'noticed', 'mark', '/admin-probe', array( 'mark_as' => 'probe' ) ),
				$this->url_rule( 'refused', 'block', '/admin-probe', array( 'status_code' => 403 ) ),
			)
		);

		$this->assertSame( 'block', $this->test_request( '/admin-probe' )['verdict'] );
	}

	/**
	 * A record rule is reported as recorded, not as "no rule matched".
	 *
	 * Testing a honeypot and being told it did nothing, at the moment it has
	 * just caught you, reads as the rule being broken.
	 */
	public function test_a_recorded_request_is_reported_as_recorded(): void {
		$this->given_rules( array( $this->url_rule( 'honeypot', 'record', '/wp-trap' ) ) );

		$result = $this->test_request( '/wp-trap' );

		$this->assertSame( 'record', $result['verdict'] );
		$this->assertSame( 'honeypot', $result['rule'] );
	}

	/**
	 * An imported redirect naming nowhere is skipped, and says so.
	 *
	 * The screen refuses one. An import, WP-CLI or a hand-edited option does
	 * not go through the screen, and the library only complains when the rule
	 * matches -- by throwing, on the very request the rule was written for.
	 */
	public function test_a_redirect_naming_nowhere_is_not_compiled(): void {
		$this->given_rules(
			array(
				$this->url_rule( 'nowhere', 'redirect', '/old', array( 'redirect_to' => '' ) ),
				$this->url_rule( 'offsite', 'redirect', '/older', array( 'redirect_to' => '//evil.example/' ) ),
				$this->url_rule( 'fine', 'redirect', '/oldest', array( 'redirect_to' => '/new' ) ),
			)
		);

		$outcome  = Plugin::instance()->compiled()->rebuild();
		$compiled = (string) file_get_contents( Plugin::instance()->paths()->compiled_file() ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file this test just wrote.
		$problems = implode( "\n", $outcome['problems'] );

		$this->assertStringContainsString( '"nowhere"', $problems );
		$this->assertStringContainsString( '"offsite"', $problems );
		$this->assertStringNotContainsString( '"fine"', $problems );
		$this->assertStringNotContainsString( 'name: nowhere', $compiled );
		$this->assertStringNotContainsString( 'evil.example', $compiled );
		$this->assertStringContainsString( 'redirect_to: /new', $compiled );
	}

	/**
	 * Choosing Redirect or Mark on a new rule offers their fields at once.
	 *
	 * Only the saved response's rows used to render, so the destination could
	 * not be typed until the rule had already been saved without one.
	 */
	public function test_the_rule_screen_offers_every_response_field_before_the_first_save(): void {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		$_GET = array( 'type' => 'url' );

		ob_start();
		( new Rule_Edit_Screen() )->render();
		$rendered = (string) ob_get_clean();

		foreach ( array( 'redirect_to', 'redirect_status', 'mark_as', 'mark_header', 'record', 'challenge_provider' ) as $field ) {
			$this->assertStringContainsString( sprintf( 'name="%s"', $field ), $rendered, sprintf( '%s is missing from a new block rule.', $field ) );
		}

		foreach ( array( 'response:redirect', 'response:mark', 'response:challenge', 'response:!redirect|mark' ) as $condition ) {
			$this->assertStringContainsString( sprintf( 'data-bfw-show-when="%s"', $condition ), $rendered );
		}
	}

	/**
	 * A redirect rule with nowhere to go is not saved.
	 */
	public function test_the_rule_screen_refuses_a_redirect_naming_nowhere(): void {
		$this->given_rules( array() );

		$this->submit_new_url_rule(
			array(
				'response'    => 'redirect',
				'redirect_to' => '',
			)
		);

		$this->assertSame( array(), $this->stored_rules(), 'A redirect naming nowhere was saved.' );
		$this->assertStringContainsString( 'somewhere to send the visitor', $this->queued_notices() );
	}

	/**
	 * Nor is one written like a path that leaves the site.
	 */
	public function test_the_rule_screen_refuses_a_scheme_relative_redirect(): void {
		$this->given_rules( array() );

		$this->submit_new_url_rule(
			array(
				'response'    => 'redirect',
				'redirect_to' => '//evil.example/',
			)
		);

		$this->assertSame( array(), $this->stored_rules() );
		$this->assertStringContainsString( 'another site', $this->queued_notices() );
	}

	/**
	 * A mark name the site's code could not address is not saved.
	 */
	public function test_the_rule_screen_refuses_an_unaddressable_mark(): void {
		$this->given_rules( array() );

		$this->submit_new_url_rule(
			array(
				'response'    => 'mark',
				'mark_as'     => 'not.this one',
				'mark_header' => 'X Bad',
			)
		);

		$notices = $this->queued_notices();

		$this->assertSame( array(), $this->stored_rules() );
		$this->assertStringContainsString( 'firewall.mark.NAME', $notices );
		$this->assertStringContainsString( 'header name', $notices );
	}

	/**
	 * A redirect into its own conditions is saved, with a warning.
	 *
	 * Warned rather than refused: an allow rule earlier in the order can make
	 * the combination legitimate.
	 */
	public function test_a_redirect_into_its_own_conditions_is_saved_with_a_warning(): void {
		$this->given_rules( array() );

		$saved = $this->submit_new_url_rule(
			array(
				'response'    => 'redirect',
				'redirect_to' => '/old-api/gone',
			),
			'/old-api'
		);

		$this->assertTrue( $saved, 'A valid redirect rule was not saved.' );
		$this->assertCount( 1, $this->stored_rules() );
		$this->assertStringContainsString( 'loop', $this->queued_notices() );
	}

	/**
	 * Values only another response reads are not kept.
	 *
	 * Every row is on the page now, so a block rule is posted with whatever the
	 * redirect and mark fields hold. Keeping them would leave a destination in
	 * the exported document that nothing acts on.
	 */
	public function test_values_another_response_reads_are_not_stored(): void {
		$this->given_rules( array() );

		$saved = $this->submit_new_url_rule(
			array(
				'response'           => 'block',
				'redirect_to'        => '/left-over',
				'mark_as'            => 'left-over',
				'challenge_provider' => 'altcha',
			)
		);

		$this->assertTrue( $saved );

		$rule = $this->stored_rules()[0];

		$this->assertSame( '', $rule['redirect_to'] );
		$this->assertSame( '', $rule['mark_as'] );
		$this->assertSame( '', $rule['challenge_provider'] );
	}

	/**
	 * Post the rule form for a new URL rule matching one path.
	 *
	 * @param array<string, string> $fields Fields over the defaults.
	 * @param string                $path   The path the rule matches.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	private function submit_new_url_rule( array $fields, string $path = '/trap' ): bool {
		$this->as_administrator();

		$_GET  = array( 'type' => 'url' );
		$_POST = $fields + array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-rule' ),
			'label'                => 'Test rule',
			'rule_id'              => 'test_rule',
			'enabled'              => '1',
			'weight'               => '0',
			'expiration'           => '3600',
			'settings'             => array(
				'match_type' => 'any',
				'conditions' => array(
					array(
						'variable' => 'path',
						'operator' => 'starts_with',
						'value'    => $path,
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
	 * A URL rule matching one path.
	 *
	 * @param string               $id       Identifier.
	 * @param string               $response Response.
	 * @param string               $path     Path fragment.
	 * @param array<string, mixed> $extra    Extra rule keys.
	 *
	 * @return array<string, mixed>
	 */
	private function url_rule( string $id, string $response, string $path, array $extra = array() ): array {
		return $extra + array(
			'id'              => $id,
			'type'            => 'url',
			'label'           => ucfirst( $id ),
			'enabled'         => true,
			'response'        => $response,
			'weight'          => 0,
			'status_code'     => 0,
			'record'          => 'default',
			'redirect_to'     => '',
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
