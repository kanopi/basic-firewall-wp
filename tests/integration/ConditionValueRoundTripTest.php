<?php
/**
 * Condition values, list fields and pasted documents are stored as typed.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Advanced_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Import_Screen;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Request_Tester;

/**
 * Render the rule screen, post exactly what it rendered, compare what is stored.
 *
 * The rule screen read every setting through the textarea sanitiser, which
 * turns `<` into `&lt;` (or strips it with whatever follows) and deletes every
 * `%xx` sequence. A URL rule on `header.x-probe contains %3Cscript` came back
 * from an untouched save as a rule on `script`, and blocked far more than it
 * was written for (#60). These tests post what a browser would post -- the
 * rendered form, parsed as HTML, so an entity is decoded the way a browser
 * decodes it -- and require the stored value to be the one that was there.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen
 * @covers \Kanopi\BasicFirewall\Admin\Screen
 * @covers \Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base
 */
final class ConditionValueRoundTripTest extends Settings_Snapshot {

	use Rendered_Rule_Form;

	/**
	 * Values the sanitiser changed, and the ones it would have changed next.
	 */
	private const VALUES = array(
		'<script>alert(1)</script>',
		'a > b',
		'%2e%2e/',
		'%3Cscript',
		'q=1&x=2',
		'&lt;already-an-entity&gt;',
		'"double" and \'single\'',
		'back\\slash \\\\ two',
		'café 日本 🚀',
		"tab\tinside",
	);

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

		require_once ABSPATH . 'wp-admin/includes/template.php';

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
		delete_transient( 'basic_firewall_pending_import_' . get_current_user_id() );
		remove_all_filters( 'wp_redirect' );

		$_GET  = $this->globals['get'];
		$_POST = $this->globals['post'];
		wp_set_current_user( $this->globals['user'] );

		parent::tearDown();
	}

	/**
	 * Every condition rule type, with a variable it can read and what else it needs to save.
	 *
	 * @return array<string, array{0: string, 1: string, 2: array<string, mixed>}>
	 */
	public static function condition_types(): array {
		$reader = array(
			'reader' => array(
				'source'   => 'database',
				'database' => 'geoip/not-downloaded-yet.mmdb',
				'edge'     => 'cloudflare',
				'headers'  => array(),
			),
		);

		return array(
			'URL / request' => array( 'url', 'header.x-probe', array() ),
			'URL query'     => array( 'url', 'query.q', array() ),
			'user agent'    => array( 'user_agent', 'bot.name', array() ),
			'geolocation'   => array( 'geolocation', 'city', $reader ),
			'ASN'           => array( 'asn', 'asn_org', $reader ),
			'edge signal'   => array( 'edge_signal', 'ja4', array() ),
		);
	}

	/**
	 * Each value survives two untouched saves exactly, on every condition rule type.
	 *
	 * @dataProvider condition_types
	 *
	 * @param string               $type     Rule type.
	 * @param string               $variable A variable it reads.
	 * @param array<string, mixed> $extra    Other settings it needs.
	 */
	public function test_condition_values_survive_saving_unchanged( string $type, string $variable, array $extra ): void {
		$conditions = array();

		foreach ( self::VALUES as $value ) {
			$conditions[] = self::condition( $variable, 'contains', $value );
		}

		// A pattern with both, compiled by the validator as the library will run it.
		$conditions[] = self::condition( $variable, 'regex', '(<|%3c)script\\s*>' );

		$this->given_rule( 'typed', $type, $conditions, $extra );
		$this->assertSame( $conditions, $this->stored_rule( 'typed' )['settings']['conditions'], 'The fixture did not store the values as given.' );

		for ( $save = 0; $save < 2; $save++ ) {
			$this->assertTrue( $this->save_as_rendered( 'typed' ), 'The screen refused its own rendering of the rule.' );
			$this->assertSame( $conditions, $this->stored_rule( 'typed' )['settings']['conditions'] );
		}
	}

	/**
	 * What is stored as typed is printed escaped, so it cannot become markup on the screen.
	 */
	public function test_a_stored_value_is_escaped_on_the_screen(): void {
		$payload = '"><script>alert(document.cookie)</script><input value="';

		$this->given_rule( 'xss', 'url', array( self::condition( 'header.x-probe', 'contains', $payload ) ) );

		$fields = $this->rendered_fields( 'xss' );

		$this->assertStringNotContainsString( '<script>alert', $this->rendered_html, 'A stored value reached the page as markup.' );
		$this->assertStringContainsString( '&quot;&gt;&lt;script&gt;alert(document.cookie)&lt;/script&gt;', $this->rendered_html );
		$this->assertSame( $payload, $fields['settings[conditions][0][value]'] ?? null, 'The browser would read back a different value.' );

		// The rule list summarises it too.
		$_GET = array();
		ob_start();
		( new \Kanopi\BasicFirewall\Admin\Screen\Rules_Screen() )->render();
		$list = (string) ob_get_clean();

		$this->assertStringNotContainsString( '<script>alert', $list, 'The rule list printed the value as markup.' );
	}

	/**
	 * A value typed into the form is stored exactly; control characters are not.
	 */
	public function test_a_typed_value_is_stored_as_typed_less_control_characters(): void {
		$this->given_rule( 'typing', 'url', array( self::condition( 'header.x-probe', 'contains', 'placeholder' ) ) );

		$this->assertTrue(
			$this->save_as_rendered(
				'typing',
				array(
					'settings[conditions][0][value]'    => "%2e<b>\x00\x1b[31m\tend\r\n",
					'settings[conditions][1][variable]' => 'query',
					'settings[conditions][1][variable_name]' => 'q',
					'settings[conditions][1][operator]' => 'regex',
					'settings[conditions][1][value]'    => '(<|%3c)script',
				)
			)
		);

		$stored = $this->stored_rule( 'typing' )['settings']['conditions'];

		$this->assertSame( "%2e<b>[31m\tend", $stored[0]['value'], 'Only the control characters, other than a tab, should go.' );
		$this->assertSame( 'query.q', $stored[1]['variable'] );
		$this->assertSame( '(<|%3c)script', $stored[1]['value'] );
	}

	/**
	 * Whitespace at either end of a value is trimmed; whitespace inside is kept.
	 *
	 * Through the screen and straight through the validator, which is the
	 * path an import and WP-CLI take, so neither can store a value whose
	 * trailing space makes a block rule match nothing.
	 */
	public function test_whitespace_at_either_end_is_trimmed(): void {
		$this->given_rule( 'spaced', 'url', array( self::condition( 'path', 'starts_with', 'placeholder' ) ) );

		$this->assertTrue(
			$this->save_as_rendered(
				'spaced',
				array( 'settings[conditions][0][value]' => "  /wp-admin \t " )
			)
		);

		$this->assertSame( '/wp-admin', $this->stored_rule( 'spaced' )['settings']['conditions'][0]['value'] );

		$errors = array();
		$clean  = ( new \Kanopi\BasicFirewall\RuleType\Types\Url() )->validate_settings(
			array(
				'conditions' => array(
					self::condition( 'path', 'starts_with', ' /wp-login.php ' ),
					self::condition( 'header.x-probe', 'contains', ' a  b ' ),
				),
			),
			$errors
		);

		$this->assertSame( array(), $errors );
		$this->assertSame( '/wp-login.php', $clean['conditions'][0]['value'] );
		$this->assertSame( 'a  b', $clean['conditions'][1]['value'], 'Whitespace inside a value is part of it.' );
	}

	/**
	 * The validator still decides: an invalid pattern and an overlong value are refused.
	 */
	public function test_the_validator_still_refuses_what_it_should(): void {
		$this->given_rule( 'checked', 'url', array( self::condition( 'header.x-probe', 'contains', 'kept' ) ) );

		$this->assertFalse(
			$this->save_as_rendered(
				'checked',
				array(
					'settings[conditions][0][operator]' => 'regex',
					'settings[conditions][0][value]'    => '(<unclosed',
				)
			),
			'A pattern that does not compile was saved.'
		);

		$this->assertFalse(
			$this->save_as_rendered( 'checked', array( 'settings[conditions][0][value]' => str_repeat( '<', 4097 ) ) ),
			'A value over the length limit was saved.'
		);

		$this->assertSame( 'kept', $this->stored_rule( 'checked' )['settings']['conditions'][0]['value'] );
	}

	/**
	 * A referenced list's fields survive the screen with their percent-encodings and angle brackets.
	 */
	public function test_list_fields_survive_saving_unchanged(): void {
		$this->given_rule(
			'listed',
			'url',
			array(),
			array(
				'sources' => array(
					array(
						'url'      => 'https://lists.example.test/ua%20list.txt?sig=a%2Fb%3D&v=1',
						'name'     => 'Crawlers <weekly> & "friends"',
						'select'   => 'agents.*',
						'template' => '{value[name]}',
						'variable' => 'header.user-agent',
						'operator' => 'contains',
						'advanced' => array( 'where' => array( 'name@contains:%3C' ) ),
					),
				),
			)
		);

		$before = $this->stored_rule( 'listed' )['settings']['sources'][0];

		$this->assertSame( 'https://lists.example.test/ua%20list.txt?sig=a%2Fb%3D&v=1', $before['url'], 'The fixture did not store the URL as given.' );

		for ( $save = 0; $save < 2; $save++ ) {
			$this->assertTrue( $this->save_as_rendered( 'listed' ), 'The screen refused its own rendering of the rule.' );
			$this->assertSame( $before, $this->stored_rule( 'listed' )['settings']['sources'][0] );
		}
	}

	/**
	 * A rate limit line keeps its percent-encoded pattern.
	 */
	public function test_a_rate_limit_pattern_survives_saving_unchanged(): void {
		$this->given_rule(
			'limited',
			'rate_limit',
			array(),
			array( 'paths' => array( '/caf%C3%A9/* 5 60' ) ),
			false
		);

		$before = $this->stored_rule( 'limited' )['settings']['paths'];

		$this->assertSame( '/caf%C3%A9/*', $before[0]['pattern'] ?? null, 'The fixture did not store the pattern as given.' );

		$this->assertTrue( $this->save_as_rendered( 'limited' ), 'The screen refused its own rendering of the rule.' );
		$this->assertSame( $before, $this->stored_rule( 'limited' )['settings']['paths'] );
	}

	/**
	 * The stored value is what the library matches, so it matters that it is the one typed.
	 *
	 * On a request header, because a header value reaches the library as
	 * sent. The path would not show it: kanopi/firewall 2.35 normalises the
	 * path, decoding unreserved percent-encodings, so `%2e` in a path is `.`
	 * by the time a condition sees it, and a query parameter arrives decoded
	 * by Symfony. Through the sanitiser this rule was stored as `contains
	 * script` -- which matches the second request as well as the first.
	 */
	public function test_the_saved_value_is_the_one_the_library_matches(): void {
		$this->given_rule(
			'probe',
			'url',
			array(
				self::condition( 'header.x-probe', 'contains', '%3Cscript' ),
				self::condition( 'header.x-pattern', 'regex', '(<|%3c)script' ),
			)
		);

		$this->assertNotSame( '%3Cscript', sanitize_textarea_field( '%3Cscript' ), 'The premise: the sanitiser changes this value.' );
		$this->assertTrue( $this->save_as_rendered( 'probe' ) );
		$this->assertSame( '%3Cscript', $this->stored_rule( 'probe' )['settings']['conditions'][0]['value'] );

		Plugin::instance()->compiled()->rebuild();

		$this->assertSame( 'block', $this->test_request( 'X-Probe: q=%3Cscript%3E' )['verdict'], 'The rule did not match the value it was written for.' );
		$this->assertSame( 'allow', $this->test_request( 'X-Probe: a script tag' )['verdict'], 'The rule matched a request only the mangled value matches.' );
		$this->assertSame( 'block', $this->test_request( 'X-Pattern: <script>' )['verdict'], 'The pattern lost its angle bracket.' );
		$this->assertSame( 'block', $this->test_request( 'X-Pattern: %3cscript' )['verdict'], 'The pattern lost its percent-encoding.' );
	}

	/**
	 * A document pasted on the Import screen is held exactly as pasted.
	 */
	public function test_an_import_is_previewed_as_pasted(): void {
		$this->given_settings( array( 'enabled' => true ) );

		$document = "rules:\n  - id: pasted\n    type: url\n    response: block\n    settings:\n      conditions:\n        - variable: header.x-probe\n          operator: contains\n          value: '%3Cscript>'\n";

		$this->assertTrue( $this->handle_screen( new Import_Screen(), array( 'document' => $document ) ) );
		$this->assertSame( $document, get_transient( 'basic_firewall_pending_import_' . get_current_user_id() ) );
	}

	/**
	 * The Advanced YAML box keeps `<` and percent-encodings.
	 */
	public function test_the_advanced_yaml_is_stored_as_typed(): void {
		$this->given_settings( array( 'enabled' => true ) );

		$yaml = "# Typed <exactly> with %2e and %3C kept\nglobal:\n  banning_message: 'Blocked <b>%2e</b>'";

		$this->assertTrue( $this->handle_screen( new Advanced_Screen(), array( 'advanced_yaml' => $yaml ) ) );

		Plugin::instance()->settings()->flush();

		$this->assertSame( $yaml, Plugin::instance()->settings()->get( 'advanced_yaml' ) );
	}

	/**
	 * A condition, in the shape the validator stores.
	 *
	 * @param string $variable Variable.
	 * @param string $operator Operator.
	 * @param string $value    Value.
	 *
	 * @return array<string, mixed>
	 */
	private static function condition( string $variable, string $operator, string $value ): array {
		return array(
			'variable'       => $variable,
			'operator'       => $operator,
			'value'          => $value,
			'negate'         => false,
			'case_sensitive' => false,
		);
	}

	/**
	 * Store one rule, through the settings' own validation.
	 *
	 * @param string                     $id         Identifier.
	 * @param string                     $type       Rule type.
	 * @param list<array<string, mixed>> $conditions Conditions.
	 * @param array<string, mixed>       $extra      Other settings.
	 * @param bool                       $conditional Whether the type has conditions.
	 */
	private function given_rule( string $id, string $type, array $conditions, array $extra = array(), bool $conditional = true ): void {
		$settings = array_merge( Plugin::instance()->rule_types()->get( $type )->default_settings(), $extra );

		if ( $conditional ) {
			$settings['conditions'] = $conditions;
		}

		$this->given_settings( array( 'enabled' => true ) );
		Plugin::instance()->settings()->set(
			'rules',
			array(
				array(
					'id'          => $id,
					'type'        => $type,
					'label'       => ucfirst( $id ),
					'enabled'     => true,
					'response'    => 'block',
					'status_code' => 403,
					'expiration'  => 60,
					'settings'    => $settings,
				),
			)
		);
	}

	/**
	 * The stored rule, read fresh.
	 *
	 * @param string $id Identifier.
	 *
	 * @return array<string, mixed>
	 */
	private function stored_rule( string $id ): array {
		Plugin::instance()->settings()->flush();

		foreach ( (array) Plugin::instance()->settings()->get( 'rules', array() ) as $rule ) {
			if ( is_array( $rule ) && ( $rule['id'] ?? null ) === $id ) {
				return $rule;
			}
		}

		$this->fail( sprintf( 'Rule %s is not stored.', $id ) );
	}

	/**
	 * Ask the tester about a request carrying one header.
	 *
	 * @param string $header One `Name: value` line.
	 *
	 * @return array<string, mixed>
	 */
	private function test_request( string $header ): array {
		return ( new Request_Tester() )->test(
			array(
				'path'    => '/',
				'ip'      => '203.0.113.10',
				'headers' => $header,
			)
		);
	}

	/**
	 * Post fields to a screen, as a browser does, and report whether it finished with a redirect.
	 *
	 * @param \Kanopi\BasicFirewall\Admin\Screen $screen The screen.
	 * @param array<string, string>              $fields Its fields, unslashed.
	 */
	private function handle_screen( \Kanopi\BasicFirewall\Admin\Screen $screen, array $fields ): bool {
		$this->as_administrator();

		$fields['basic_firewall_nonce'] = $this->nonce_for( $screen );

		$_GET  = array();
		$_POST = wp_slash( $fields );

		add_filter(
			'wp_redirect',
			static function (): void {
				throw new \RuntimeException( 'redirected' );
			}
		);

		try {
			$screen->handle();
		} catch ( \RuntimeException $e ) {
			return 'redirected' === $e->getMessage();
		}

		return false;
	}

	/**
	 * The nonce a screen's own form carries.
	 *
	 * @param \Kanopi\BasicFirewall\Admin\Screen $screen The screen.
	 */
	private function nonce_for( \Kanopi\BasicFirewall\Admin\Screen $screen ): string {
		$method = new \ReflectionMethod( $screen, 'nonce_action' );
		$method->setAccessible( true );

		return wp_create_nonce( (string) $method->invoke( $screen ) );
	}
}
