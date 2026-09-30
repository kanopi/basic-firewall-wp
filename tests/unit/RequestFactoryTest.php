<?php
/**
 * How the request the firewall evaluates is built, and what path it resolves to.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Runtime\Request_Factory;
use Kanopi\Firewall\Utility\RequestPath;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The factory builds Symfony's own request, and the library resolves its path.
 *
 * Each case is the server values a web server really sends for that request,
 * so the path asserted is the one a rule sees in production under the compiled
 * `path_source: script_name`. Under the library's default every direct-file
 * case here resolves to `/` (#30).
 *
 * The factory used to rewrite the request's `SCRIPT_NAME` to index.php so that
 * `getPathInfo()` returned the path from the raw URL. The alternate spellings
 * below are why it no longer does: each runs wp-login.php, and each came out of
 * that rewrite as the spelling rather than `/wp-login.php`.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Request_Factory
 */
final class RequestFactoryTest extends TestCase {

	/**
	 * The WordPress root the cases are laid out under.
	 */
	private const ROOT = '/srv/www/wordpress/';

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
	 * The request carries the server values as the server sent them.
	 *
	 * Nothing in its server bag is rewritten any more, and the real `$_SERVER`
	 * -- which WordPress derives `$pagenow` from -- is untouched.
	 */
	public function test_the_request_is_built_as_symfony_builds_it(): void {
		$_SERVER = array(
			'REQUEST_URI'     => '/wp-admin/edit.php',
			'SCRIPT_NAME'     => '/wp-admin/edit.php',
			'PHP_SELF'        => '/wp-admin/edit.php',
			'SCRIPT_FILENAME' => self::ROOT . 'wp-admin/edit.php',
			'HTTP_HOST'       => 'example.com',
		);

		$before  = $_SERVER;
		$request = Request_Factory::from_globals();

		$this->assertSame( '/wp-admin/edit.php', $request->server->get( 'SCRIPT_NAME' ) );
		$this->assertSame( '/wp-admin/edit.php', $request->server->get( 'PHP_SELF' ) );
		$this->assertSame( self::ROOT . 'wp-admin/edit.php', $request->server->get( 'SCRIPT_FILENAME' ) );
		$this->assertSame( $before, $_SERVER, 'The factory changed the real $_SERVER.' );

		$this->assertSame( '/wp-admin/edit.php', RequestPath::resolve( $request, RequestPath::SCRIPT_NAME ) );
	}

	/**
	 * The wp-config.php path builds from a named class and gets the same request.
	 */
	public function test_building_from_a_named_class_gives_the_same_request(): void {
		$_SERVER = array(
			'REQUEST_URI'     => '/wp-login.php',
			'SCRIPT_NAME'     => '/wp-login.php',
			'PHP_SELF'        => '/wp-login.php',
			'SCRIPT_FILENAME' => self::ROOT . 'wp-login.php',
			'HTTP_HOST'       => 'example.com',
		);

		$request = Request_Factory::from_globals_of( Request::class );

		$this->assertInstanceOf( Request::class, $request );
		$this->assertSame( '/wp-login.php', $request->server->get( 'SCRIPT_NAME' ) );
		$this->assertSame( '/wp-login.php', RequestPath::resolve( $request, RequestPath::SCRIPT_NAME ) );
	}

	/**
	 * Every direct request resolves to the file the server ran, in each layout.
	 *
	 * @dataProvider direct_requests
	 *
	 * @param string $uri         REQUEST_URI.
	 * @param string $script_name SCRIPT_NAME.
	 * @param string $path_info   PATH_INFO.
	 * @param string $base_path   The compiled base_path.
	 * @param string $path        The path the rules should see.
	 */
	public function test_a_direct_request_resolves_to_the_file_that_ran( string $uri, string $script_name, string $path_info, string $base_path, string $path ): void {
		$request = self::live( $uri, $script_name, $path_info );

		$this->assertSame( $path, RequestPath::resolve( $request, RequestPath::SCRIPT_NAME, $base_path ), 'The rules would not see the requested file.' );
		$this->assertSame( $uri, $request->getRequestUri(), 'The request URI -- the challenge\'s return address -- changed.' );
	}

	/**
	 * Direct and routed requests at the root, in a subdirectory, and with
	 * WordPress in its own directory.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3: string, 4: string}>
	 */
	public static function direct_requests(): array {
		return array(
			'wp-login.php'                 => array( '/wp-login.php', '/wp-login.php', '', '', '/wp-login.php' ),
			'wp-login.php with a query'    => array( '/wp-login.php?action=lostpassword', '/wp-login.php', '', '', '/wp-login.php' ),
			'xmlrpc.php'                   => array( '/xmlrpc.php', '/xmlrpc.php', '', '', '/xmlrpc.php' ),
			'wp-cron.php'                  => array( '/wp-cron.php?doing_wp_cron=1', '/wp-cron.php', '', '', '/wp-cron.php' ),
			'an admin screen'              => array( '/wp-admin/edit.php?post_type=page', '/wp-admin/edit.php', '', '', '/wp-admin/edit.php' ),
			'the dashboard'                => array( '/wp-admin/', '/wp-admin/index.php', '', '', '/wp-admin/index.php' ),
			'a custom endpoint'            => array( '/sso/oauth.php', '/sso/oauth.php', '', '', '/sso/oauth.php' ),
			'a direct file with path info' => array( '/xmlrpc.php/extra', '/xmlrpc.php', '/extra', '', '/xmlrpc.php/extra' ),
			'a page'                       => array( '/sample-page/', '/index.php', '', '', '/sample-page/' ),
			'subdirectory wp-login.php'    => array( '/blog/wp-login.php', '/blog/wp-login.php', '', '/blog', '/wp-login.php' ),
			'subdirectory admin screen'    => array( '/blog/wp-admin/edit.php', '/blog/wp-admin/edit.php', '', '/blog', '/wp-admin/edit.php' ),
			'subdirectory page'            => array( '/blog/sample-page/', '/blog/index.php', '', '/blog', '/sample-page/' ),
			'own directory wp-login.php'   => array( '/wp/wp-login.php', '/wp/wp-login.php', '', '', '/wp/wp-login.php' ),
			'own directory admin screen'   => array( '/wp/wp-admin/edit.php', '/wp/wp-admin/edit.php', '', '', '/wp/wp-admin/edit.php' ),
			'own directory page'           => array( '/sample-page/', '/index.php', '', '', '/sample-page/' ),
			'network site wp-login.php'    => array( '/site2/wp-login.php', '/wp-login.php', '', '', '/wp-login.php' ),
			'network site page'            => array( '/site2/sample-page/', '/index.php', '', '', '/site2/sample-page/' ),
		);
	}

	/**
	 * Every spelling of wp-login.php resolves to `/wp-login.php`.
	 *
	 * The web server decodes and normalises the URL before it chooses a file,
	 * so each of these runs wp-login.php and the server says so in
	 * `SCRIPT_NAME`. The second assertion is what the old rewrite produced --
	 * `SCRIPT_NAME` pointed at index.php, and the path read out of the raw URL
	 * -- and is here to show the bypass it had, not to keep it.
	 *
	 * @dataProvider spellings
	 *
	 * @param string $uri REQUEST_URI, as the client sent it.
	 */
	public function test_every_spelling_of_the_login_page_resolves_to_it( string $uri ): void {
		$this->assertSame( '/wp-login.php', RequestPath::resolve( self::live( $uri, '/wp-login.php' ), RequestPath::SCRIPT_NAME ) );

		if ( '/wp-login.php' === $uri ) {
			return;
		}

		$rewritten = self::live( $uri, '/index.php' );

		$this->assertNotSame( '/wp-login.php', $rewritten->getPathInfo(), 'The raw URL would have matched after all, so this spelling proves nothing.' );
	}

	/**
	 * Spellings of `/wp-login.php` that nginx and Apache run as wp-login.php.
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function spellings(): array {
		return array(
			'plain'             => array( '/wp-login.php' ),
			'a dot segment'     => array( '/./wp-login.php' ),
			'an encoded letter' => array( '/%77p-login.php' ),
			'a doubled slash'   => array( '//wp-login.php' ),
			'a parent segment'  => array( '/x/../wp-login.php' ),
			'a path parameter'  => array( '/wp-login.php;x' ),
		);
	}

	/**
	 * Made-up requests are built the way a web server would describe them.
	 *
	 * The files are this plugin's own, under a stand-in ABSPATH, because the
	 * decision -- a direct request or a routed one -- turns on whether the
	 * named file exists.
	 *
	 * @dataProvider made_up_requests
	 *
	 * @param string $path      Path relative to the base path.
	 * @param string $base_path Where the front controller's directory is served.
	 * @param string $core_path Where ABSPATH is served.
	 * @param string $script    Expected SCRIPT_NAME.
	 * @param string $seen      The path the rules should see.
	 */
	public function test_made_up_requests_match_real_ones( string $path, string $base_path, string $core_path, string $script, string $seen ): void {
		$root   = dirname( __DIR__, 2 ) . '/';
		$server = Request_Factory::server_for( $path, $base_path, $core_path, $root );

		$this->assertSame( $script, $server['SCRIPT_NAME'] );
		$this->assertSame( $server['SCRIPT_NAME'] . $server['PATH_INFO'], $server['PHP_SELF'] );

		$request = Request::create( $server['REQUEST_URI'], 'GET', array(), array(), array(), $server );

		$request->server->set( 'PATH_INFO', $server['PATH_INFO'] );

		$this->assertSame( $seen, RequestPath::resolve( $request, RequestPath::SCRIPT_NAME, rtrim( $base_path, '/' ) ) );
	}

	/**
	 * Paths the request tester and Site Health make requests for.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3: string, 4: string}>
	 */
	public static function made_up_requests(): array {
		return array(
			'an existing file'              => array( '/bootstrap.php', '', '', '/bootstrap.php', '/bootstrap.php' ),
			'an existing file, a query'     => array( '/bootstrap.php?x=1', '', '', '/bootstrap.php', '/bootstrap.php' ),
			'a nested existing file'        => array( '/src/Plugin.php', '', '', '/src/Plugin.php', '/src/Plugin.php' ),
			'an existing file, path info'   => array( '/bootstrap.php/extra', '', '', '/bootstrap.php', '/bootstrap.php/extra' ),
			'a missing file'                => array( '/missing.php', '', '', '/index.php', '/missing.php' ),
			'a page'                        => array( '/sample-page/', '', '', '/index.php', '/sample-page/' ),
			'subdirectory existing file'    => array( '/bootstrap.php', '/blog', '/blog', '/blog/bootstrap.php', '/bootstrap.php' ),
			'subdirectory page'             => array( '/sample-page/', '/blog/', '/blog', '/blog/index.php', '/sample-page/' ),
			'own directory, prefixed file'  => array( '/wp/bootstrap.php', '', '/wp', '/wp/bootstrap.php', '/wp/bootstrap.php' ),
			'own directory, bare file name' => array( '/bootstrap.php', '', '/wp', '/index.php', '/bootstrap.php' ),
			'own directory, a page'         => array( '/sample-page/', '', '/wp', '/index.php', '/sample-page/' ),
		);
	}

	/**
	 * The front controller's file, for each layout.
	 */
	public function test_the_front_controller_file_follows_the_layout(): void {
		$this->assertSame( '/srv/www/wordpress/index.php', Request_Factory::server_for( '/', '', '', self::ROOT )['SCRIPT_FILENAME'] );
		$this->assertSame( '/srv/www/wordpress/index.php', Request_Factory::server_for( '/', '/blog', '/blog', self::ROOT )['SCRIPT_FILENAME'] );
		$this->assertSame( '/srv/www/index.php', Request_Factory::server_for( '/', '', '/wordpress', self::ROOT )['SCRIPT_FILENAME'] );
		$this->assertSame( '/srv/www/index.php', Request_Factory::server_for( '/', '/blog', '/blog/wordpress', self::ROOT )['SCRIPT_FILENAME'] );
	}

	/**
	 * A request as a web server describes it.
	 *
	 * @param string $uri         REQUEST_URI.
	 * @param string $script_name SCRIPT_NAME, and PHP_SELF with any path info.
	 * @param string $path_info   PATH_INFO.
	 */
	private static function live( string $uri, string $script_name, string $path_info = '' ): Request {
		$query  = (string) parse_url( $uri, PHP_URL_QUERY ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- no WordPress in a unit test.
		$server = array(
			'REQUEST_URI'     => $uri,
			'QUERY_STRING'    => $query,
			'SCRIPT_NAME'     => $script_name,
			'PHP_SELF'        => $script_name . $path_info,
			'SCRIPT_FILENAME' => self::ROOT . ltrim( $script_name, '/' ),
			'HTTP_HOST'       => 'example.com',
		);

		if ( '' !== $path_info ) {
			$server['PATH_INFO'] = $path_info;
		}

		return new Request( array(), array(), array(), array(), array(), $server );
	}
}
