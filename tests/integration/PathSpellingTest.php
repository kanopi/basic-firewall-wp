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
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Runtime\Request_Factory
 */
final class PathSpellingTest extends Honoured_Settings {

	/**
	 * Every spelling, the plain one first.
	 */
	private const SPELLINGS = array( '/wp-login.php', '/./wp-login.php', '/%77p-login.php', '//wp-login.php', '/x/../wp-login.php', '/wp-login.php;x' );

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
