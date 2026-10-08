<?php
/**
 * Who makes the DNS lookups behind crawler verification.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\General_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Firewall;
use Symfony\Component\Yaml\Yaml;

/**
 * DNS-over-HTTPS providers for crawler verification (kanopi/firewall 2.38.0, #473).
 *
 * Two things are pinned. Nothing is sent to a provider unless somebody chose
 * one: an untouched site compiles no `reverse_dns` at all. And nothing chosen
 * here, on any screen or in the advanced YAML, can stop the library starting
 * -- it refuses on a provider it cannot use, and this plugin fails open when it
 * refuses, which would switch every rule off to fix a slow lookup.
 *
 * @covers \Kanopi\BasicFirewall\Support\Reverse_Dns
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\RuleType\Types\User_Agent
 * @covers \Kanopi\BasicFirewall\Admin\Screen\General_Screen
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class ReverseDnsLookupsTest extends Settings_Snapshot {

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
	 * An untouched site sends nothing anywhere: no `reverse_dns`, and no rule choosing one.
	 */
	public function test_nothing_chosen_compiles_nothing(): void {
		$this->given( array(), array( $this->rule() ) );

		$compiled = $this->compiled();

		$this->assertArrayNotHasKey( 'reverse_dns', $compiled['global'] );
		$this->assertArrayNotHasKey( 'verify_provider', $this->verifying( $compiled ) );
		$this->assertArrayNotHasKey( 'verify_timeout_ms', $this->verifying( $compiled ) );
	}

	/**
	 * The site's provider and limit reach `global.reverse_dns`, and the library starts with them.
	 */
	public function test_the_site_provider_compiles_and_starts(): void {
		$this->needs_curl();

		$this->given(
			array(
				'provider'   => 'cloudflare',
				'timeout_ms' => 450,
			),
			array( $this->rule() )
		);

		$compiled = $this->compiled();

		$this->assertSame(
			array(
				'provider'   => 'cloudflare',
				'timeout_ms' => 450,
			),
			$compiled['global']['reverse_dns'] ?? null
		);
		$this->assertInstanceOf( Firewall::class, Firewall::create( array( self::without_storage( $compiled ) ) ) );
	}

	/**
	 * A rule's own provider and limit reach its metadata.
	 */
	public function test_a_rule_choice_compiles_into_its_metadata(): void {
		$this->needs_curl();

		$this->given(
			array(),
			array(
				$this->rule(
					array(
						'verify_provider'   => 'google',
						'verify_timeout_ms' => 600,
					)
				),
			)
		);

		$metadata = $this->verifying( $this->compiled() );

		$this->assertSame( 'google', $metadata['verify_provider'] ?? null );
		$this->assertSame( 600, $metadata['verify_timeout_ms'] ?? null );
	}

	/**
	 * A provider the library would refuse, typed into the advanced YAML, is left out rather than stopping the firewall.
	 */
	public function test_an_unusable_choice_is_left_out_and_reported(): void {
		$this->given_settings(
			array(
				'enabled'       => true,
				'advanced_yaml' => "global:\n  reverse_dns:\n    provider: cloudfare\n",
			)
		);
		Plugin::instance()->settings()->set( 'rules', array( $this->rule() ) );

		$result   = Plugin::instance()->compiled()->rebuild();
		$compiled = $this->compiled();

		$this->assertArrayNotHasKey( 'reverse_dns', $compiled['global'] );
		$this->assertNotEmpty( preg_grep( '/cloudfare/', $result['problems'] ) );
		$this->assertInstanceOf( Firewall::class, Firewall::create( array( self::without_storage( $compiled ) ) ) );
	}

	/**
	 * The General screen saves the choice, and refuses a provider that does not exist.
	 */
	public function test_the_general_screen_saves_the_choice(): void {
		$this->needs_curl();
		$this->given( array(), array() );

		$this->submit_general(
			array(
				'reverse_dns_provider'   => 'google',
				'reverse_dns_timeout_ms' => '700',
			)
		);

		Plugin::instance()->settings()->flush();

		$this->assertSame( 'google', Plugin::instance()->settings()->get( 'global.reverse_dns.provider' ) );
		$this->assertSame( 700, Plugin::instance()->settings()->get( 'global.reverse_dns.timeout_ms' ) );

		$this->submit_general( array( 'reverse_dns_provider' => 'nobody' ) );

		Plugin::instance()->settings()->flush();

		$this->assertNotSame( 'nobody', Plugin::instance()->settings()->get( 'global.reverse_dns.provider' ) );
	}

	/**
	 * The General screen offers the choice, and says what a provider receives.
	 */
	public function test_the_general_screen_states_what_is_sent(): void {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		ob_start();
		( new General_Screen() )->render();
		$rendered = (string) ob_get_clean();

		$this->assertStringContainsString( 'name="reverse_dns_provider"', $rendered );
		$this->assertStringContainsString( 'value="cloudflare"', $rendered );
		$this->assertStringContainsString( 'name="reverse_dns_timeout_ms"', $rendered );
		$this->assertStringContainsString( 'GDPR', $rendered );
	}

	/**
	 * The rule screen offers a rule its own choice.
	 */
	public function test_the_rule_screen_offers_a_rule_its_own_choice(): void {
		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->as_administrator();

		$_GET = array( 'type' => 'user_agent' );

		ob_start();
		( new Rule_Edit_Screen() )->render();
		$rendered = (string) ob_get_clean();

		$this->assertStringContainsString( 'name="settings[verify_provider]"', $rendered );
		$this->assertStringContainsString( 'name="settings[verify_timeout_ms]"', $rendered );
	}

	/**
	 * A rule's provider the library would refuse is not stored.
	 */
	public function test_a_rule_provider_that_does_not_exist_is_refused(): void {
		$type = Plugin::instance()->rule_types()->get( 'user_agent' );

		$this->assertNotNull( $type );

		$errors = array();
		$clean  = $type->validate_settings(
			$this->rule(
				array(
					'verify_provider'   => 'cloudfare',
					'verify_timeout_ms' => '20000',
				)
			)['settings'],
			$errors
		);

		$this->assertSame( '', $clean['verify_provider'] );
		$this->assertSame( 0, $clean['verify_timeout_ms'] );
		$this->assertArrayHasKey( 'verify_provider', $errors );
		$this->assertArrayHasKey( 'verify_timeout_ms', $errors );
	}

	/**
	 * Site Health says where each verifying rule's lookups go.
	 */
	public function test_site_health_names_where_lookups_go(): void {
		$this->given( array(), array( $this->rule() ) );

		$result = Site_Health::check( 'verification' );

		$this->assertSame( 'good', $result['status'] );
		$this->assertStringContainsString( 'PHP&#039;s own lookups', $result['description'] );

		if ( ! function_exists( 'curl_init' ) ) {
			return;
		}

		$this->given( array( 'provider' => 'cloudflare' ), array( $this->rule() ) );

		$result = Site_Health::check( 'verification' );

		$this->assertSame( 'good', $result['status'] );
		$this->assertStringContainsString( 'cloudflare (cloudflare-dns.com, 1.1.1.1)', $result['description'] );
	}

	/**
	 * Site Health raises a compiled file the library would refuse as critical.
	 *
	 * The compiler drops such a value, but in the PHP that compiled; curl can
	 * be missing from the web server's. Simulated by writing the file directly.
	 */
	public function test_site_health_raises_a_file_the_library_would_refuse(): void {
		$this->given( array(), array( $this->rule() ) );

		$path     = Plugin::instance()->paths()->compiled_file();
		$compiled = $this->compiled();

		$compiled['global']['reverse_dns'] = array( 'provider' => 'cloudfare' );

		file_put_contents( $path, Yaml::dump( $compiled, 10, 2 ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$result = Site_Health::check( 'verification' );

		Plugin::instance()->compiled()->rebuild();

		$this->assertSame( 'critical', $result['status'] );
		$this->assertStringContainsString( 'cloudfare', $result['description'] );
	}

	/**
	 * Install lookup settings and rules, and compile them.
	 *
	 * @param array<string, mixed>       $reverse_dns Stored `global.reverse_dns`.
	 * @param list<array<string, mixed>> $rules       Rules.
	 */
	private function given( array $reverse_dns, array $rules ): void {
		$this->given_settings(
			array(
				'enabled' => true,
				'global'  => array( 'reverse_dns' => $reverse_dns ),
			)
		);
		Plugin::instance()->settings()->set( 'rules', $rules );
		Plugin::instance()->compiled()->rebuild();
	}

	/**
	 * The compiled file, parsed.
	 *
	 * @return array<string, mixed>
	 */
	private function compiled(): array {
		$parsed = Yaml::parse( (string) Plugin::instance()->compiled()->contents() );

		$this->assertIsArray( $parsed );

		return $parsed;
	}

	/**
	 * The metadata of the first verifying rule in a compiled file.
	 *
	 * @param array<string, mixed> $compiled The compiled file.
	 *
	 * @return array<string, mixed>
	 */
	private function verifying( array $compiled ): array {
		foreach ( (array) ( $compiled['plugins'] ?? array() ) as $plugin ) {
			if ( isset( $plugin['metadata']['verify'] ) ) {
				return (array) $plugin['metadata'];
			}
		}

		$this->fail( 'No verifying rule was compiled.' );
	}

	/**
	 * A compiled file that can be started from an array, writing nothing.
	 *
	 * The library resolves storage and log paths against the directory of the
	 * file it loads; an array has none, so they would land in the working
	 * directory.
	 *
	 * @param array<string, mixed> $compiled The compiled file.
	 *
	 * @return array<string, mixed>
	 */
	private static function without_storage( array $compiled ): array {
		unset( $compiled['storage'], $compiled['logger'] );

		return $compiled;
	}

	/**
	 * Skip where DNS over HTTPS cannot run.
	 */
	private function needs_curl(): void {
		if ( ! function_exists( 'curl_init' ) ) {
			$this->markTestSkipped( 'DNS over HTTPS needs the curl extension.' );
		}
	}

	/**
	 * Post the General screen with its current values and some changes.
	 *
	 * @param array<string, string> $fields Fields to change.
	 */
	private function submit_general( array $fields ): void {
		$this->as_administrator();

		$_POST = $fields + array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-general' ),
			'enabled'              => '1',
			'mode'                 => 'log',
			'banning_status_code'  => '403',
			'require_config'       => '1',
		);

		add_filter(
			'wp_redirect',
			static function (): void {
				throw new \RuntimeException( 'redirected' );
			}
		);

		try {
			( new General_Screen() )->handle();
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'redirected', $e->getMessage() );
		}
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
	 * An allow rule for known crawlers that verifies them.
	 *
	 * @param array<string, mixed> $settings Settings to add.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( array $settings = array() ): array {
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
			'settings'        => $settings + array(
				'match_type'      => 'any',
				'sources'         => array(),
				'cache_detection' => true,
				'bot_source'      => 'curated',
				'verify'          => true,
				'verify_suffixes' => array( 'googlebot.com' ),
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
