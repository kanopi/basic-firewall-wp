<?php
/**
 * Composable rate limit keys, and the pairing they require.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;

/**
 * A rate limit that counts an account, and what it has to be kept beside.
 *
 * `/wp-login.php 5 300 post.log` reads as a tightening and is half of one. It
 * catches a botnet against one account, misses one client walking a list of
 * usernames -- each name gets a fresh budget -- and records no offense, so on
 * its own it leaves brute force unprotected and the block list empty. The screen
 * says so when it is saved, and Site Health for as long as it stays that way.
 *
 * The refusals pinned here are the keys that would do worse than nothing: a
 * component the library cannot resolve, or a field name it lower-cases out of
 * existence, puts every request in one bucket -- one visitor spending the
 * allowance for the whole site.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Rate_Limit
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class RateLimitKeyTest extends Settings_Snapshot {

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
	 * A limit's key compiles onto that limit, and only there.
	 */
	public function test_a_key_compiles_onto_its_limit(): void {
		$type = Plugin::instance()->rule_types()->get( 'rate_limit' );

		$this->assertNotNull( $type );

		$config = $type->compile( $this->rule( 'accounts', array( '/wp-login.php 5 300 post.log', '/xmlrpc.php 10 60' ) ) )['config'];

		$this->assertSame( array( 'post.log' ), $config[0]['key'] ?? null );
		$this->assertArrayNotHasKey( 'key', $config[1], 'A line without a key counts what it always counted.' );
	}

	/**
	 * A component the library cannot resolve is refused.
	 */
	public function test_an_unresolvable_component_is_refused(): void {
		$this->given_rules( array() );

		$this->assertFalse( $this->submit( 'accounts', '/wp-login.php 5 300 pots.log' ) );
		$this->assertSame( array(), $this->stored_rules() );
		$this->assertStringContainsString( 'pots.log', $this->notices() );
	}

	/**
	 * A form field named with capitals is refused.
	 */
	public function test_a_capitalised_field_name_is_refused(): void {
		$this->given_rules( array() );

		$this->assertFalse( $this->submit( 'accounts', '/my-account 5 300 post.userName' ) );
		$this->assertSame( array(), $this->stored_rules() );
		$this->assertStringContainsString( 'capital letters', $this->notices() );
	}

	/**
	 * The same pattern twice in one rule is refused.
	 *
	 * The obvious way to pair an account limit with an address limit, and the
	 * one that does nothing: only the first matching line is ever used.
	 */
	public function test_the_same_pattern_twice_in_one_rule_is_refused(): void {
		$this->given_rules( array() );

		$this->assertFalse( $this->submit( 'accounts', "/wp-login.php 5 300 post.log\n/wp-login.php 50 300" ) );
		$this->assertStringContainsString( 'listed twice', $this->notices() );
	}

	/**
	 * Saving an identity-keyed limit alone warns, and saves.
	 */
	public function test_an_identity_keyed_limit_alone_warns(): void {
		$this->given_rules( array() );

		$this->assertTrue( $this->submit( 'accounts', '/wp-login.php 5 300 post.log' ) );

		$notices = $this->notices();

		$this->assertStringContainsString( 'never ban anyone', $notices );
		$this->assertStringContainsString( '/wp-login.php', $notices );
	}

	/**
	 * With an address-keyed companion in another rule, it does not.
	 */
	public function test_an_identity_keyed_limit_with_a_companion_does_not_warn(): void {
		$this->given_rules( array( $this->rule( 'addresses', array( '/wp-login.php 50 300' ) ) ) );

		$this->assertTrue( $this->submit( 'accounts', '/wp-login.php 5 300 post.log' ) );
		$this->assertStringNotContainsString( 'never ban anyone', $this->notices() );
	}

	/**
	 * Recording an identity-keyed limit warns about whose address gets banned.
	 */
	public function test_recording_an_identity_keyed_limit_warns(): void {
		$this->given_rules( array( $this->rule( 'addresses', array( '/wp-login.php 50 300' ) ) ) );

		$this->assertTrue( $this->submit( 'accounts', '/wp-login.php 5 300 post.log', 'yes' ) );
		$this->assertStringContainsString( 'victim', $this->notices() );
	}

	/**
	 * Site Health names an unpaired identity-keyed limit.
	 */
	public function test_site_health_names_an_unpaired_limit(): void {
		$this->given_rules( array( $this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) ) ) );

		$result = Site_Health::check( 'rate_keys' );

		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( 'accounts', $result['description'] );
		$this->assertStringContainsString( '/wp-login.php', $result['description'] );
	}

	/**
	 * And is satisfied once the address is counted beside it.
	 */
	public function test_site_health_is_satisfied_by_a_companion(): void {
		$this->given_rules(
			array(
				$this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) ),
				$this->rule( 'addresses', array( '/wp-login.php 50 300' ) ),
			)
		);

		$this->assertSame( 'good', Site_Health::check( 'rate_keys' )['status'] );
	}

	/**
	 * The rule list says what a limit counts.
	 */
	public function test_the_summary_says_what_is_counted(): void {
		$type = Plugin::instance()->rule_types()->get( 'rate_limit' );

		$this->assertNotNull( $type );

		$summary = implode( ' ', $type->summarize( $this->rule( 'accounts', array( '/wp-login.php 5 300 post.log' ) )['settings'] ) );

		$this->assertStringContainsString( 'counting post.log', $summary );
	}

	/**
	 * The queued notices, as one string.
	 */
	private function notices(): string {
		$queue = get_transient( 'basic_firewall_notices_' . get_current_user_id() );

		return is_array( $queue ) ? implode( "\n", array_column( $queue, 'message' ) ) : '';
	}

	/**
	 * Post the rule form for a new rate limit rule.
	 *
	 * @param string $id     Identifier.
	 * @param string $paths  The limits, as typed.
	 * @param string $record The record choice.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	private function submit( string $id, string $paths, string $record = 'default' ): bool {
		$this->as_administrator();

		delete_transient( 'basic_firewall_notices_' . get_current_user_id() );

		$_GET  = array( 'type' => 'rate_limit' );
		$_POST = array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-rule' ),
			'label'                => ucfirst( $id ),
			'rule_id'              => $id,
			'enabled'              => '1',
			'response'             => 'block',
			'record'               => $record,
			'weight'               => '0',
			'expiration'           => '600',
			'settings'             => array(
				'paths'          => $paths,
				'default_limit'  => '60',
				'default_window' => '60',
				'status_code'    => '429',
				'storage'        => array( 'backend' => 'file' ),
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
	 * A rate limit rule.
	 *
	 * @param string       $id    Identifier.
	 * @param list<string> $lines Limits, as typed.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $id, array $lines ): array {
		return array(
			'id'              => $id,
			'type'            => 'rate_limit',
			'label'           => ucfirst( $id ),
			'enabled'         => true,
			'observe'         => false,
			'response'        => 'block',
			'weight'          => 0,
			'status_code'     => 0,
			'record'          => 'default',
			'redirect_to'     => '',
			'redirect_status' => 302,
			'mark_as'         => '',
			'mark_header'     => '',
			'expiration'      => 600,
			'settings'        => array(
				'paths'                => $lines,
				'default_limit'        => 60,
				'default_window'       => 60,
				'limit_unlisted_paths' => false,
				'status_code'          => 429,
				'storage'              => array( 'backend' => 'file' ),
			),
		);
	}
}
