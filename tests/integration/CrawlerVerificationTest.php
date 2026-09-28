<?php
/**
 * Reverse-DNS crawler verification.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Plugins\AbstractPluginBase;

/**
 * Verifying that a crawler is the crawler it claims to be.
 *
 * An allow rule on `bot equals true` is a skeleton key: the user agent is
 * whatever the client typed, so anyone sending `Googlebot/2.1` is let past
 * every rule below it. Verification closes that with the round trip the crawler
 * operators document -- reverse-resolve, check the hostname is in a domain the
 * operator named, forward-resolve and confirm it comes back.
 *
 * The compiled file is where this has to be right, because the plugin writes
 * these keys and never reads them back. A key written under the wrong name is
 * not a broken rule, it is an allow rule that quietly stops verifying.
 *
 * And one key matters more than its size suggests. Before kanopi/firewall
 * 2.33.0 the verifier followed the offline rule-sources flag, which both
 * evaluation paths turn on -- so on a default install every verifying rule
 * matched nobody. `verify_offline: false` is how that stays fixed.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\User_Agent
 * @covers \Kanopi\BasicFirewall\Library_Capabilities
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 */
final class CrawlerVerificationTest extends Settings_Snapshot {

	/**
	 * Request globals, put back after each test.
	 *
	 * @var array{get: array<mixed>, post: array<mixed>, user: int}
	 */
	private array $globals;

	/**
	 * Remember the request globals, and skip where the library cannot verify.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! ( new Library_Capabilities() )->has_identity_verification() ) {
			$this->markTestSkipped( 'The installed library cannot verify crawlers.' );
		}

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

		if ( isset( $this->globals ) ) {
			$_GET  = $this->globals['get'];
			$_POST = $this->globals['post'];
			wp_set_current_user( $this->globals['user'] );
		}

		parent::tearDown();
	}

	/**
	 * A verifying rule compiles both keys the library reads.
	 */
	public function test_a_verifying_rule_compiles_both_keys(): void {
		$metadata = $this->metadata_for( $this->rule( true, array( 'googlebot.com', 'search.msn.com' ) ) );

		$this->assertSame( 'reverse-dns', $metadata['verify'] ?? null );
		$this->assertSame( array( 'googlebot.com', 'search.msn.com' ), $metadata['verify_suffixes'] ?? null );
	}

	/**
	 * A verifying rule says for itself that its lookups go online.
	 *
	 * The regression this pins is the library's own, fixed in 2.33.0: the
	 * offline rule-sources flag used to reach the two DNS lookups as well, and
	 * this plugin turns that flag on for every request.
	 */
	public function test_a_verifying_rule_is_not_switched_off_by_offline_sources(): void {
		if ( ! ( new Library_Capabilities() )->has_verification_switch() ) {
			$this->markTestSkipped( 'The installed library has no per-rule verification switch.' );
		}

		$metadata = $this->metadata_for( $this->rule( true, array( 'googlebot.com' ) ) );

		$this->assertFalse( $metadata['verify_offline'] ?? null );

		/*
		 * And the library reads it that way, whatever the constant says. Asked
		 * of the same static the verifier and firewall-doctor both ask, rather
		 * than of a copy of its logic.
		 */
		$this->assertSame(
			array(
				'offline' => false,
				'source'  => 'metadata',
			),
			AbstractPluginBase::verificationOffline( $metadata )
		);
	}

	/**
	 * The control: without the key, the offline flag decides.
	 *
	 * Without this, a library that ignored the constant altogether would
	 * satisfy the case above.
	 */
	public function test_without_the_switch_the_offline_flag_decides(): void {
		if ( ! ( new Library_Capabilities() )->has_verification_switch() ) {
			$this->markTestSkipped( 'The installed library has no per-rule verification switch.' );
		}

		$metadata = $this->metadata_for( $this->rule( true, array( 'googlebot.com' ) ) );
		unset( $metadata['verify_offline'] );

		$decided = AbstractPluginBase::verificationOffline( $metadata );

		if ( defined( 'KANOPI_FIREWALL_SOURCES_OFFLINE' ) ) {
			$this->assertSame( 'constant', $decided['source'] );
			$this->assertSame( (bool) constant( 'KANOPI_FIREWALL_SOURCES_OFFLINE' ), $decided['offline'] );
		} else {
			$this->assertSame( 'default', $decided['source'] );
		}
	}

	/**
	 * A rule that does not verify writes none of the keys.
	 */
	public function test_a_rule_without_verification_writes_no_key(): void {
		$metadata = $this->metadata_for( $this->rule( false, array( 'googlebot.com' ) ) );

		$this->assertArrayNotHasKey( 'verify', $metadata );
		$this->assertArrayNotHasKey( 'verify_suffixes', $metadata );
		$this->assertArrayNotHasKey( 'verify_offline', $metadata );
	}

	/**
	 * Verification with no domains never compiles as a plain agent match.
	 *
	 * The compiler skips such a rule before it is compiled. Should anything
	 * compile it anyway, it compiles as verification against an empty list,
	 * which the library reads as "match nobody" -- never as the same rule
	 * without verification, which on an allow rule believes every client
	 * claiming to be a crawler.
	 */
	public function test_verification_without_domains_never_compiles_unverified(): void {
		$metadata = $this->metadata_for( $this->rule( true, array() ) );

		$this->assertSame( 'reverse-dns', $metadata['verify'] ?? null );
		$this->assertSame( array(), $metadata['verify_suffixes'] ?? null );
	}

	/**
	 * The rule screen offers verification, and says why it matters.
	 */
	public function test_the_rule_screen_offers_verification(): void {
		$rendered = $this->render_user_agent_screen();

		$this->assertStringContainsString( 'name="settings[verify]"', $rendered );
		$this->assertStringContainsString( 'name="settings[verify_suffixes]"', $rendered );
		$this->assertStringContainsString( 'skeleton key', $rendered );
	}

	/**
	 * The cost, and the resolver it needs, are stated where it is switched on.
	 */
	public function test_the_rule_screen_states_the_cost(): void {
		$rendered = $this->render_user_agent_screen();

		$this->assertStringContainsString( 'local caching resolver is a prerequisite', $rendered );
		$this->assertStringContainsString( '112 ms', $rendered );
	}

	/**
	 * A verifying rule with a domain saves.
	 */
	public function test_a_verifying_rule_saves(): void {
		$this->given_rules( array() );

		$this->assertTrue( $this->submit_rule( '1', "googlebot.com\n.Search.MSN.com" ), 'The rule was not saved.' );

		$stored = $this->stored_rules()[0]['settings'];

		$this->assertTrue( $stored['verify'] );
		$this->assertSame( array( 'googlebot.com', 'search.msn.com' ), $stored['verify_suffixes'] );
	}

	/**
	 * Verification with no domain is refused.
	 */
	public function test_verification_without_a_domain_is_refused(): void {
		$this->given_rules( array() );

		$this->assertFalse( $this->submit_rule( '1', '' ), 'A verifying rule with no domain was saved.' );
		$this->assertSame( array(), $this->stored_rules() );
	}

	/**
	 * Something that is not a domain is refused rather than stored.
	 */
	public function test_a_value_that_is_not_a_domain_is_refused(): void {
		$this->given_rules( array() );

		$this->assertFalse( $this->submit_rule( '1', 'https://googlebot.com/' ), 'A URL was saved as a crawler domain.' );
		$this->assertSame( array(), $this->stored_rules() );
	}

	/**
	 * A rule that does not verify saves as usual.
	 *
	 * The control: without it, a screen that refused every user agent rule
	 * would satisfy the refusals above.
	 */
	public function test_a_rule_without_verification_saves(): void {
		$this->given_rules( array() );

		$this->assertTrue( $this->submit_rule( '', '' ) );
		$this->assertFalse( $this->stored_rules()[0]['settings']['verify'] );
	}

	/**
	 * Saving a user agent rule no longer turns its detection cache off.
	 *
	 * The condition editor rendered conditions and nothing else, so every save
	 * posted no `cache_detection` -- which the validator read as unticked,
	 * compiling `cache: false` and costing every worker the 618 ms pattern
	 * compile on its first request.
	 */
	public function test_saving_keeps_the_detection_cache(): void {
		$this->given_rules( array() );

		$this->assertTrue( $this->submit_rule( '', '', array( 'cache_detection' => '1' ) ) );
		$this->assertTrue( $this->stored_rules()[0]['settings']['cache_detection'] );

		$this->assertStringContainsString( 'name="settings[cache_detection]"', $this->render_user_agent_screen() );
	}

	/**
	 * Site Health names a verifying rule, and says whether it can verify.
	 */
	public function test_site_health_names_a_verifying_rule(): void {
		$this->given_rules( array( $this->rule( true, array( 'googlebot.com' ) ) ) );

		$result = Site_Health::check( 'verification' );

		$this->assertStringContainsString( 'Known crawlers', $result['description'] );
		$this->assertSame(
			( new Library_Capabilities() )->identity_verification_runs() ? 'good' : 'critical',
			$result['status']
		);
	}

	/**
	 * A site with no verifying rule is told what verification is for.
	 */
	public function test_site_health_is_quiet_without_a_verifying_rule(): void {
		$this->given_rules( array( $this->rule( false, array() ) ) );

		$result = Site_Health::check( 'verification' );

		$this->assertSame( 'good', $result['status'] );
		$this->assertSame( 'No rule verifies crawlers', $result['label'] );
	}

	/**
	 * Render the rule screen for a new user agent rule.
	 */
	private function render_user_agent_screen(): string {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		$_GET = array( 'type' => 'user_agent' );

		ob_start();
		( new Rule_Edit_Screen() )->render();

		return (string) ob_get_clean();
	}

	/**
	 * Post the rule form for an allow rule on `bot equals true`.
	 *
	 * @param string                $verify   The verify box, '1' or ''.
	 * @param string                $suffixes The accepted domains, as typed.
	 * @param array<string, string> $extra    Further settings fields.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	private function submit_rule( string $verify, string $suffixes, array $extra = array() ): bool {
		$this->as_administrator();

		$settings = $extra + array(
			'match_type'      => 'any',
			'verify_suffixes' => $suffixes,
			'conditions'      => array(
				array(
					'variable' => 'bot',
					'operator' => 'equals',
					'value'    => 'true',
				),
			),
		);

		if ( '' !== $verify ) {
			$settings['verify'] = $verify;
		}

		$_GET  = array( 'type' => 'user_agent' );
		$_POST = array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-rule' ),
			'label'                => 'Known crawlers',
			'rule_id'              => 'crawlers',
			'enabled'              => '1',
			'response'             => 'allow',
			'weight'               => '0',
			'expiration'           => '0',
			'settings'             => $settings,
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
	 * The metadata one rule compiles to.
	 *
	 * @param array<string, mixed> $rule The rule.
	 *
	 * @return array<string, mixed>
	 */
	private function metadata_for( array $rule ): array {
		$type = Plugin::instance()->rule_types()->get( 'user_agent' );

		$this->assertNotNull( $type );

		return (array) ( $type->compile( $rule )['metadata'] ?? array() );
	}

	/**
	 * An allow rule for known crawlers.
	 *
	 * @param bool         $verify   Whether it verifies.
	 * @param list<string> $suffixes Accepted domains.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( bool $verify, array $suffixes ): array {
		return array(
			'id'              => 'crawlers',
			'type'            => 'user_agent',
			'label'           => 'Known crawlers',
			'enabled'         => true,
			'observe'         => false,
			'response'        => 'allow',
			'weight'          => 0,
			'status_code'     => 0,
			'record'          => 'default',
			'redirect_to'     => '',
			'redirect_status' => 302,
			'mark_as'         => '',
			'mark_header'     => '',
			'expiration'      => 0,
			'settings'        => array(
				'match_type'      => 'any',
				'sources'         => array(),
				'cache_detection' => true,
				'bot_source'      => 'curated',
				'verify'          => $verify,
				'verify_suffixes' => $suffixes,
				'conditions'      => array(
					array(
						'variable' => 'bot',
						'operator' => 'equals',
						'value'    => 'true',
					),
				),
			),
		);
	}
}
