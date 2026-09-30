<?php
/**
 * Spellings of /wp-login.php that the web server runs as wp-login.php.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Runtime\Request_Factory;
use Symfony\Component\HttpFoundation\Request;

/**
 * A `/wp-login.php` rule and rate limit catch every spelling of it.
 *
 * Both nginx and Apache decode and normalise the URL before choosing a file, so
 * `/./wp-login.php`, `/%77p-login.php`, `//wp-login.php` and
 * `/x/../wp-login.php` all run wp-login.php, and a server that drops path
 * parameters runs it for `/wp-login.php;x` too. `SCRIPT_NAME` is
 * `/wp-login.php` for every one of them; `REQUEST_URI` is whatever the client
 * sent.
 *
 * The request rewrite this plugin used before (#31) pointed `SCRIPT_NAME` at
 * index.php and let Symfony read the path out of `REQUEST_URI`, so each
 * spelling reached the rules as itself: a block on `/wp-login.php` let all
 * five through, and a rate limit on it counted none of them. Run against that
 * code, both tests below fail. The compiled `path_source: script_name` reads
 * the file the server ran, and they pass.
 *
 * These build the server values a web server sends and go through
 * Request_Factory, the way the early path does, rather than over HTTP: PHP's
 * built-in server normalises the first four itself but routes
 * `/wp-login.php;x` to index.php. DirectFileRequestTest covers the four over
 * real HTTP.
 *
 * Requests routed through index.php are the other half (#51). For those the
 * library reads the path from the request URI, as the client spelled it, while
 * the server has already normalised the URL and WordPress trims every leading
 * slash, so `//wp-json/…`, `/./wp-json/…`, `/%77p-json/…` and `/wp-json;x/…`
 * were the REST API to WordPress and missed a rule on `/wp-json/`. Since
 * kanopi/firewall 2.35.0 both path sources normalise: repeated slashes
 * collapse, `.` segments go, unreserved characters are decoded and `;params`
 * are dropped. `..` is kept as written, on purpose, so it is not among them.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Runtime\Request_Factory
 */
final class PathSpellingTest extends Honoured_Settings {

	/**
	 * Every spelling, the plain one first.
	 */
	private const SPELLINGS = array( '/wp-login.php', '/./wp-login.php', '/%77p-login.php', '//wp-login.php', '/x/../wp-login.php', '/wp-login.php;x' );

	/**
	 * Spellings of a REST API route that the server routes to index.php, the plain one first.
	 */
	private const ROUTED_SPELLINGS = array( '/wp-json/wp/v2/users', '//wp-json/wp/v2/users', '/./wp-json/wp/v2/users', '/%77p-json/wp/v2/users', '/wp-json;x/wp/v2/users', '/%2e/wp-json/wp/v2/users' );

	/**
	 * The real `$_SERVER`, put back after each test.
	 *
	 * @var array<string, mixed>
	 */
	private array $server = array();

	/**
	 * Remember the real server values.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->server = $_SERVER;
	}

	/**
	 * Put them back.
	 */
	protected function tearDown(): void {
		$_SERVER = $this->server;

		parent::tearDown();
	}

	/**
	 * A block on `path equals /wp-login.php` refuses every spelling.
	 */
	public function test_a_login_block_refuses_every_spelling(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'login-block', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/wp-login.php' ) ) ), array( 'expiration' => 1 ) ),
				),
			)
		);

		foreach ( self::SPELLINGS as $index => $spelling ) {
			$outcome = $this->outcome( $firewall, $this->direct( $spelling, '203.0.113.' . ( 60 + $index ) ) );

			$this->assertSame( 'block', $outcome['verdict'], $spelling . ' ran wp-login.php and was let past a block on /wp-login.php.' );
		}

		$this->assertSame( 'allow', $this->outcome( $firewall, $this->direct( '/sample-page/', '203.0.113.70', '/index.php' ) )['verdict'], 'The rule refuses everything, so this test proves nothing.' );
	}

	/**
	 * A `/wp-login.php 5 60` rate limit counts every spelling against one budget.
	 */
	public function test_a_login_rate_limit_counts_every_spelling(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'login-limit',
						'rate_limit',
						array(
							'paths'                => array( '/wp-login.php 5 60' ),
							'default_limit'        => 60,
							'default_window'       => 60,
							'limit_unlisted_paths' => false,
							'storage'              => array(
								'backend' => 'file',
								'file'    => $this->scratch . '/ratelimit.data',
							),
						),
						array( 'record' => 'no' )
					),
				),
			)
		);

		$verdicts = array();

		foreach ( self::SPELLINGS as $spelling ) {
			$verdicts[ $spelling ] = $this->outcome( $firewall, $this->direct( $spelling, '203.0.113.80' ) )['verdict'];
		}

		$this->assertSame( array( 'allow', 'allow', 'allow', 'allow', 'allow' ), array_slice( array_values( $verdicts ), 0, 5 ), 'A request within the allowance was refused: ' . wp_json_encode( $verdicts ) );
		$this->assertSame( 'block', $verdicts['/wp-login.php;x'], 'The sixth request for wp-login.php, in six spellings, was not refused, so some spellings are not counted: ' . wp_json_encode( $verdicts ) );
	}

	/**
	 * A block on `path starts with /wp-json/` refuses every routed spelling (#51).
	 */
	public function test_a_routed_block_refuses_every_spelling(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'rest-block', 'url', array( 'conditions' => array( self::condition( 'path', 'starts_with', '/wp-json/' ) ) ), array( 'expiration' => 1 ) ),
				),
			)
		);

		foreach ( self::ROUTED_SPELLINGS as $index => $spelling ) {
			$outcome = $this->outcome( $firewall, $this->direct( $spelling, '203.0.113.' . ( 90 + $index ), '/index.php' ) );

			$this->assertSame( 'block', $outcome['verdict'], $spelling . ' reached the REST API and was let past a block on /wp-json/.' );
		}

		$this->assertSame( 'allow', $this->outcome( $firewall, $this->direct( '/sample-page/', '203.0.113.99', '/index.php' ) )['verdict'], 'The rule refuses everything, so this test proves nothing.' );
	}

	/**
	 * A rate limit on a REST route counts every routed spelling against one budget (#51).
	 */
	public function test_a_routed_rate_limit_counts_every_spelling(): void {
		$budget   = count( self::ROUTED_SPELLINGS ) - 1;
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'rest-limit',
						'rate_limit',
						array(
							'paths'                => array( '/wp-json/wp/v2/users ' . $budget . ' 60' ),
							'default_limit'        => 60,
							'default_window'       => 60,
							'limit_unlisted_paths' => false,
							'storage'              => array(
								'backend' => 'file',
								'file'    => $this->scratch . '/ratelimit.data',
							),
						),
						array( 'record' => 'no' )
					),
				),
			)
		);

		$verdicts = array();

		foreach ( self::ROUTED_SPELLINGS as $spelling ) {
			$verdicts[ $spelling ] = $this->outcome( $firewall, $this->direct( $spelling, '203.0.113.100', '/index.php' ) )['verdict'];
		}

		$last = (string) array_key_last( $verdicts );

		$this->assertSame( array_fill( 0, $budget, 'allow' ), array_slice( array_values( $verdicts ), 0, $budget ), 'A request within the allowance was refused: ' . wp_json_encode( $verdicts ) );
		$this->assertSame( 'block', $verdicts[ $last ], 'The last request for the route, after the budget was spent across its spellings, was not refused, so some spellings are not counted: ' . wp_json_encode( $verdicts ) );
	}

	/**
	 * `..` is kept as written, so it cannot turn a REST API request into something else (#51).
	 *
	 * Resolving it would remove the segment before it: `/wp-json/wp/v2/x/../../../y`
	 * would be `/y` to the rules and still the REST API to WordPress, which is
	 * exactly the bypass this closes.
	 */
	public function test_a_dot_dot_segment_is_not_resolved_away_from_a_routed_rule(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'rest-block', 'url', array( 'conditions' => array( self::condition( 'path', 'starts_with', '/wp-json/' ) ) ), array( 'expiration' => 1 ) ),
				),
			)
		);

		$this->assertSame( 'block', $this->outcome( $firewall, $this->direct( '/wp-json/wp/v2/x/../../../sample-page', '203.0.113.110', '/index.php' ) )['verdict'] );
	}

	/**
	 * A `/wp-login.php` rate limit counts `/WP-LOGIN.PHP` against the same budget (#50).
	 *
	 * On a case-insensitive filesystem (macOS, Windows, some mounted volumes)
	 * the server runs wp-login.php for `/WP-LOGIN.PHP` and `SCRIPT_NAME` keeps
	 * the client's case. Rate-limit patterns were case-sensitive until
	 * kanopi/firewall 2.35.0, so each casing had a budget of its own.
	 */
	public function test_a_login_rate_limit_ignores_case(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'login-limit',
						'rate_limit',
						array(
							'paths'                => array( '/wp-login.php 3 60' ),
							'default_limit'        => 60,
							'default_window'       => 60,
							'limit_unlisted_paths' => false,
							'storage'              => array(
								'backend' => 'file',
								'file'    => $this->scratch . '/ratelimit.data',
							),
						),
						array( 'record' => 'no' )
					),
				),
			)
		);

		$verdicts = array();

		foreach ( array( '/wp-login.php', '/WP-LOGIN.PHP', '/Wp-Login.php', '/WP-LOGIN.PHP' ) as $index => $casing ) {
			$verdicts[ $index . ' ' . $casing ] = $this->outcome( $firewall, $this->direct( $casing, '203.0.113.120', $casing ) )['verdict'];
		}

		$this->assertSame( array( 'allow', 'allow', 'allow', 'block' ), array_values( $verdicts ), 'Some casings of wp-login.php were not counted against its limit: ' . wp_json_encode( $verdicts ) );
	}

	/**
	 * A URL rule on `/wp-login.php` already ignored case, and still does (#50).
	 */
	public function test_a_login_block_ignores_case(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'login-block', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/wp-login.php' ) ) ), array( 'expiration' => 1 ) ),
				),
			)
		);

		foreach ( array( '/WP-LOGIN.PHP', '/Wp-Login.Php' ) as $index => $casing ) {
			$this->assertSame( 'block', $this->outcome( $firewall, $this->direct( $casing, '203.0.113.' . ( 130 + $index ), $casing ) )['verdict'], $casing . ' ran wp-login.php and was let past a block on /wp-login.php.' );
		}
	}

	/**
	 * The request a web server hands PHP for a spelling of a file, built as the early path builds it.
	 *
	 * @param string $uri    REQUEST_URI, as the client sent it.
	 * @param string $ip     Client address.
	 * @param string $script The file the server ran, as a URL path.
	 */
	private function direct( string $uri, string $ip, string $script = '/wp-login.php' ): Request {
		$_SERVER = array(
			'REQUEST_METHOD'  => 'GET',
			'REQUEST_URI'     => $uri,
			'SCRIPT_NAME'     => $script,
			'PHP_SELF'        => $script,
			'SCRIPT_FILENAME' => ABSPATH . ltrim( $script, '/' ),
			'HTTP_HOST'       => 'example.org',
			'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
			'REMOTE_ADDR'     => $ip,
		);

		$request = Request_Factory::from_globals();

		$_SERVER = $this->server;

		return $request;
	}
}
