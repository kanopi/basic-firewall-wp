<?php
/**
 * The edge signal rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Plugins\EdgeSignal;
use Symfony\Component\HttpFoundation\Request;

/**
 * Matching on what the CDN worked out that this site cannot.
 *
 * What this rule reads is a header a CDN set, which makes two things worth
 * stating on the screen rather than leaving to production: the headers are
 * believed only behind a trusted proxy, and Cloudflare's bot score runs the
 * opposite way to every other score in the firewall.
 *
 * The library evaluation at the end is the part that proves the type works at
 * all. The obvious rule -- `bot_score` at most 5 -- is a numeric comparison,
 * and until this type arrived the plugin handed the library its own short
 * operator names, which the library does not know. Every such comparison
 * matched nothing.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Edge_Signal
 * @covers \Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 */
final class EdgeSignalTest extends Settings_Snapshot {

	/**
	 * Request globals, put back after each test.
	 *
	 * @var array{get: array<mixed>, post: array<mixed>, user: int}
	 */
	private array $globals;

	/**
	 * Skip where the library has no edge signals, and remember the globals.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! class_exists( EdgeSignal::class ) ) {
			$this->markTestSkipped( 'The installed library has no edge signal plugin.' );
		}

		$this->globals = array(
			'get'  => $_GET, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'post' => $_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'user' => get_current_user_id(),
		);
	}

	/**
	 * Put everything back.
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
	 * The type is registered and offered.
	 */
	public function test_the_type_is_offered(): void {
		$this->assertArrayHasKey( 'edge_signal', Plugin::instance()->rule_types()->available() );
	}

	/**
	 * A named CDN compiles its name and no header map.
	 *
	 * The named providers keep their header map in the library. Writing a copy
	 * beside it would be a second source of truth that goes stale the next time
	 * a CDN renames a header.
	 */
	public function test_a_named_cdn_compiles_without_headers(): void {
		$entry = $this->compile( $this->rule( 'cloudflare', array( 'bot_score: X-Ignored' ) ) );

		$this->assertSame( 'cloudflare', $entry['metadata']['provider'] );
		$this->assertArrayNotHasKey( 'headers', $entry['metadata'] );
		$this->assertSame( 'bot_score', $entry['config'][0]['variable'] );
		$this->assertSame( 'less_than_or_equal', $entry['config'][0]['operator'], 'The library\'s own operator name.' );
		$this->assertSame( '5', $entry['config'][0]['value'] );
	}

	/**
	 * A custom CDN carries the header names, because nothing else knows them.
	 */
	public function test_a_custom_cdn_compiles_its_headers(): void {
		$entry = $this->compile( $this->rule( 'custom', array( 'ja3: X-Fingerprint', 'bot_score: X-Score' ) ) );

		$this->assertSame( 'custom', $entry['metadata']['provider'] );
		$this->assertSame(
			array(
				'ja3'       => 'X-Fingerprint',
				'bot_score' => 'X-Score',
			),
			$entry['metadata']['headers']
		);
	}

	/**
	 * An unknown CDN falls back rather than reaching the library.
	 *
	 * The library refuses to start on a provider it does not know, and a
	 * firewall that cannot start fails open on every rule.
	 */
	public function test_an_unknown_cdn_falls_back(): void {
		$this->assertSame( 'cloudflare', $this->compile( $this->rule( 'akamai', array() ) )['metadata']['provider'] );
	}

	/**
	 * A custom CDN naming no header is skipped, and the Status screen is told.
	 */
	public function test_a_custom_cdn_with_no_headers_is_skipped(): void {
		$this->given_settings( array( 'enabled' => true ) );
		Plugin::instance()->settings()->set( 'rules', array( $this->rule( 'custom', array() ) ) );
		Plugin::instance()->compiled()->rebuild();

		$problems = implode( "\n", (array) ( Plugin::instance()->compiled()->meta()['problems'] ?? array() ) );

		$this->assertStringContainsString( '"edge"', $problems );
		$this->assertStringContainsString( 'skipped', $problems );
	}

	/**
	 * The screen offers the CDNs the library knows, and no others.
	 *
	 * Akamai and CloudFront are absent on purpose: a named profile for either
	 * would be invented header names that look authoritative and match nothing.
	 */
	public function test_the_cdn_choices_match_the_library(): void {
		$rendered = $this->render_screen();

		foreach ( array( 'cloudflare', 'fastly', 'custom' ) as $provider ) {
			$this->assertStringContainsString( sprintf( 'value="%s"', $provider ), $rendered );
		}

		$this->assertStringNotContainsString( 'value="akamai"', $rendered );
		$this->assertStringNotContainsString( 'value="cloudfront"', $rendered );
	}

	/**
	 * The screen says the headers are worthless without a trusted proxy.
	 */
	public function test_the_trust_requirement_is_stated(): void {
		$rendered = $this->render_screen();

		$this->assertStringContainsString( 'claim, not a fact', $rendered );
		$this->assertStringContainsString( 'trusted proxy', $rendered );
	}

	/**
	 * The screen says Cloudflare's score runs backwards.
	 *
	 * Somebody carrying "higher is worse" across writes `bot_score > 30` on a
	 * blocking rule, which blocks the humans and lets the bots through -- and
	 * looks like it is working.
	 */
	public function test_the_inverted_score_is_called_out(): void {
		$this->assertStringContainsString( '1 means certainly a bot and 99 means certainly a human', $this->render_screen() );
	}

	/**
	 * A custom CDN naming no headers is refused, with the reason.
	 */
	public function test_a_custom_cdn_must_name_headers(): void {
		$this->assertFalse( $this->submit( 'custom', '' ) );
		$this->assertStringContainsString( 'Name at least one header', $this->notices() );
	}

	/**
	 * A header naming a signal the library cannot read is refused.
	 */
	public function test_an_unknown_signal_is_refused(): void {
		$this->assertFalse( $this->submit( 'custom', 'threat_level: X-Threat' ) );

		$notices = $this->notices();

		$this->assertStringContainsString( 'threat_level', $notices );
		$this->assertStringContainsString( 'bot_score', $notices );
	}

	/**
	 * A rule for a named CDN saves.
	 *
	 * The control for the two refusals above.
	 */
	public function test_a_named_cdn_rule_saves(): void {
		$this->assertTrue( $this->submit( 'cloudflare', '' ) );
	}

	/**
	 * What compiles is what the library acts on.
	 *
	 * Built from the compiled entry and evaluated, behind a trusted proxy and
	 * not. The untrusted case is the one to keep: a header any client can send
	 * must not be believed from a client that sent it directly.
	 */
	public function test_the_library_acts_on_the_compiled_rule(): void {
		$entry  = $this->compile( $this->rule( 'cloudflare', array() ) );
		$plugin = new EdgeSignal( $entry['metadata'], $entry['config'] );

		$proxies = Request::getTrustedProxies();
		$headers = Request::getTrustedHeaderSet();

		try {
			Request::setTrustedProxies( array( '10.0.0.1' ), Request::HEADER_X_FORWARDED_FOR );

			$this->assertTrue( $plugin->evaluate( $this->edge_request( '10.0.0.1', '2' ) ), 'A score of 2 through the CDN was not matched.' );
			$this->assertFalse( $plugin->evaluate( $this->edge_request( '10.0.0.1', '90' ) ), 'A human score was matched.' );
			$this->assertFalse( $plugin->evaluate( $this->edge_request( '198.51.100.7', '2' ) ), 'A header sent directly to the site was believed.' );
		} finally {
			Request::setTrustedProxies( $proxies, $headers );
		}
	}

	/**
	 * A request carrying a Cloudflare bot score.
	 *
	 * @param string $remote Address the request arrived from.
	 * @param string $score  The score.
	 */
	private function edge_request( string $remote, string $score ): Request {
		return Request::create(
			'/',
			'GET',
			array(),
			array(),
			array(),
			array(
				'REMOTE_ADDR'          => $remote,
				'HTTP_X_FORWARDED_FOR' => '203.0.113.10',
				'HTTP_CF_BOT_SCORE'    => $score,
			)
		);
	}

	/**
	 * The queued notices, as one string.
	 */
	private function notices(): string {
		$queue = get_transient( 'basic_firewall_notices_' . get_current_user_id() );

		return is_array( $queue ) ? implode( "\n", array_column( $queue, 'message' ) ) : '';
	}

	/**
	 * Render the screen for a new edge signal rule.
	 */
	private function render_screen(): string {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		$_GET = array( 'type' => 'edge_signal' );

		ob_start();
		( new Rule_Edit_Screen() )->render();

		return (string) ob_get_clean();
	}

	/**
	 * Post the rule form for a new edge signal rule.
	 *
	 * @param string $provider The CDN.
	 * @param string $headers  The custom header lines, as typed.
	 *
	 * @return bool Whether the screen saved it and redirected.
	 */
	private function submit( string $provider, string $headers ): bool {
		$this->given_settings( array( 'enabled' => true ) );
		$this->as_administrator();

		delete_transient( 'basic_firewall_notices_' . get_current_user_id() );

		$_GET  = array( 'type' => 'edge_signal' );
		$_POST = array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-rule' ),
			'label'                => 'Edge',
			'rule_id'              => 'edge',
			'enabled'              => '1',
			'response'             => 'block',
			'weight'               => '0',
			'expiration'           => '600',
			'settings'             => array(
				'match_type'     => 'any',
				'provider'       => $provider,
				'custom_headers' => $headers,
				'conditions'     => array(
					array(
						'variable' => 'bot_score',
						'operator' => 'lte',
						'value'    => '5',
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
	 * Compile one rule.
	 *
	 * @param array<string, mixed> $rule The rule.
	 *
	 * @return array<string, mixed>
	 */
	private function compile( array $rule ): array {
		$type = Plugin::instance()->rule_types()->get( 'edge_signal' );

		$this->assertNotNull( $type );

		return $type->compile( $rule );
	}

	/**
	 * A rule blocking what the edge scored as certainly a bot.
	 *
	 * @param string       $provider The CDN.
	 * @param list<string> $headers  Custom header lines.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $provider, array $headers ): array {
		return array(
			'id'              => 'edge',
			'type'            => 'edge_signal',
			'label'           => 'Edge',
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
				'match_type'     => 'any',
				'sources'        => array(),
				'provider'       => $provider,
				'custom_headers' => $headers,
				'conditions'     => array(
					array(
						'variable'       => 'bot_score',
						'operator'       => 'lte',
						'value'          => '5',
						'negate'         => false,
						'case_sensitive' => false,
					),
				),
			),
		);
	}
}
