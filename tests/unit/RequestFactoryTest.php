<?php
/**
 * How the request the firewall evaluates is built.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Runtime\Request_Factory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * A directly requested file is matched on its own path, not on `/`.
 *
 * Each case is the server values a web server really sends for that request,
 * so the path asserted is the one a rule would have seen in production. Before
 * the factory existed, every direct-file case here resolved to `/` (#30).
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
	 * Every direct request resolves to the requested path, in either layout.
	 *
	 * @dataProvider direct_requests
	 *
	 * @param string $uri         REQUEST_URI.
	 * @param string $script_name SCRIPT_NAME.
	 * @param string $file        SCRIPT_FILENAME, under ROOT.
	 * @param string $path        The path the rules should see.
	 * @param string $base        The base URL left over.
	 */
	public function test_a_direct_request_is_matched_on_its_own_path( string $uri, string $script_name, string $file, string $path, string $base ): void {
		$request = $this->normalised( $uri, $script_name, self::ROOT . $file );

		$this->assertSame( $path, $request->getPathInfo(), 'The rules would not see the requested path.' );
		$this->assertSame( $base, $request->getBaseUrl() );

		// The URL is the one requested: the logged `url` and a block record's
		// URL used to carry a trailing `/` after the file name.
		$this->assertSame( 'http://example.com' . strtok( $uri, '?' ), strtok( $request->getUri(), '?' ) );
		$this->assertSame( $uri, $request->getRequestUri(), 'The request URI -- the challenge\'s return address -- changed.' );
	}

	/**
	 * Direct requests, at the root and under a subdirectory.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3: string, 4: string}>
	 */
	public static function direct_requests(): array {
		return array(
			'wp-login.php'                 => array( '/wp-login.php', '/wp-login.php', 'wp-login.php', '/wp-login.php', '' ),
			'wp-login.php with a query'    => array( '/wp-login.php?action=lostpassword', '/wp-login.php', 'wp-login.php', '/wp-login.php', '' ),
			'xmlrpc.php'                   => array( '/xmlrpc.php', '/xmlrpc.php', 'xmlrpc.php', '/xmlrpc.php', '' ),
			'wp-cron.php'                  => array( '/wp-cron.php?doing_wp_cron=1', '/wp-cron.php', 'wp-cron.php', '/wp-cron.php', '' ),
			'an admin screen'              => array( '/wp-admin/edit.php?post_type=page', '/wp-admin/edit.php', 'wp-admin/edit.php', '/wp-admin/edit.php', '' ),
			'the dashboard'                => array( '/wp-admin/', '/wp-admin/index.php', 'wp-admin/index.php', '/wp-admin/', '' ),
			'a custom endpoint'            => array( '/sso/oauth.php', '/sso/oauth.php', 'sso/oauth.php', '/sso/oauth.php', '' ),
			'a direct file with path info' => array( '/xmlrpc.php/extra', '/xmlrpc.php', 'xmlrpc.php', '/xmlrpc.php/extra', '' ),
			'subdirectory wp-login.php'    => array( '/blog/wp-login.php', '/blog/wp-login.php', 'wp-login.php', '/wp-login.php', '/blog' ),
			'subdirectory admin screen'    => array( '/blog/wp-admin/edit.php', '/blog/wp-admin/edit.php', 'wp-admin/edit.php', '/wp-admin/edit.php', '/blog' ),
			'nested subdirectory'          => array( '/a/b/xmlrpc.php', '/a/b/xmlrpc.php', 'xmlrpc.php', '/xmlrpc.php', '/a/b' ),
		);
	}

	/**
	 * The subdirectory's front controller is derived, not assumed.
	 */
	public function test_the_front_controller_is_derived_for_a_subdirectory(): void {
		$this->assertSame(
			array(
				'SCRIPT_NAME'     => '/blog/index.php',
				'PHP_SELF'        => '/blog/index.php',
				'SCRIPT_FILENAME' => self::ROOT . 'index.php',
			),
			Request_Factory::front_controller(
				array(
					'SCRIPT_NAME'     => '/blog/wp-admin/edit.php',
					'SCRIPT_FILENAME' => self::ROOT . 'wp-admin/edit.php',
				),
				self::ROOT
			)
		);
	}

	/**
	 * A direct request resolves the way an `index.php`-routed one already does.
	 *
	 * The point of the change: one rule, one path, whichever file served it.
	 */
	public function test_a_direct_request_looks_like_a_routed_one(): void {
		$routed = $this->normalised( '/blog/wp-login.php', '/blog/index.php', self::ROOT . 'index.php' );
		$direct = $this->normalised( '/blog/wp-login.php', '/blog/wp-login.php', self::ROOT . 'wp-login.php' );

		$this->assertSame( $routed->getPathInfo(), $direct->getPathInfo() );
		$this->assertSame( $routed->getBaseUrl(), $direct->getBaseUrl() );
		$this->assertSame( $routed->getBasePath(), $direct->getBasePath(), 'The challenge form would post somewhere else.' );
	}

	/**
	 * A request already routed through index.php is left exactly as it was.
	 *
	 * @dataProvider routed_requests
	 *
	 * @param string $uri         REQUEST_URI.
	 * @param string $script_name SCRIPT_NAME.
	 * @param string $path        The path the rules should see.
	 */
	public function test_a_routed_request_is_unchanged( string $uri, string $script_name, string $path ): void {
		$server = array(
			'SCRIPT_NAME'     => $script_name,
			'SCRIPT_FILENAME' => self::ROOT . 'index.php',
		);

		$this->assertNull( Request_Factory::front_controller( $server, self::ROOT ) );
		$this->assertSame( $path, $this->normalised( $uri, $script_name, self::ROOT . 'index.php' )->getPathInfo() );
	}

	/**
	 * Routed requests, including PATH_INFO-style URLs.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public static function routed_requests(): array {
		return array(
			'a page'                 => array( '/sample-page/', '/index.php', '/sample-page/' ),
			'the home page'          => array( '/', '/index.php', '/' ),
			'path info'              => array( '/index.php/sample-page/', '/index.php', '/sample-page/' ),
			'subdirectory page'      => array( '/blog/sample-page/', '/blog/index.php', '/sample-page/' ),
			'subdirectory path info' => array( '/blog/index.php/feed/', '/blog/index.php', '/feed/' ),
		);
	}

	/**
	 * Values that cannot be reconciled are not guessed at.
	 *
	 * @dataProvider unreconcilable
	 *
	 * @param array<string, mixed> $server  Server values.
	 * @param string               $abspath ABSPATH.
	 */
	public function test_unreconcilable_values_leave_the_request_alone( array $server, string $abspath ): void {
		$this->assertNull( Request_Factory::front_controller( $server, $abspath ) );
	}

	/**
	 * Server values that do not describe a file under ABSPATH in a usable way.
	 *
	 * @return array<string, array{0: array<string, mixed>, 1: string}>
	 */
	public static function unreconcilable(): array {
		return array(
			'script outside ABSPATH'                      => array(
				array(
					'SCRIPT_NAME'     => '/tools/status.php',
					'SCRIPT_FILENAME' => '/srv/www/tools/status.php',
				),
				self::ROOT,
			),
			'script name folds in path info'              => array(
				array(
					'SCRIPT_NAME'     => '/wp-login.php/extra',
					'SCRIPT_FILENAME' => self::ROOT . 'wp-login.php',
				),
				self::ROOT,
			),
			'script name for another file'                => array(
				array(
					'SCRIPT_NAME'     => '/login',
					'SCRIPT_FILENAME' => self::ROOT . 'wp-login.php',
				),
				self::ROOT,
			),
			'a relative script name'                      => array(
				array(
					'SCRIPT_NAME'     => 'blog/wp-login.php',
					'SCRIPT_FILENAME' => self::ROOT . 'wp-login.php',
				),
				self::ROOT,
			),
			'the CLI'                                     => array(
				array(
					'SCRIPT_NAME'     => '/usr/local/bin/wp',
					'SCRIPT_FILENAME' => '/usr/local/bin/wp',
				),
				self::ROOT,
			),
			'no script name'                              => array(
				array( 'SCRIPT_FILENAME' => self::ROOT . 'wp-login.php' ),
				self::ROOT,
			),
			'no script filename'                          => array(
				array( 'SCRIPT_NAME' => '/wp-login.php' ),
				self::ROOT,
			),
			'no ABSPATH'                                  => array(
				array(
					'SCRIPT_NAME'     => '/wp-login.php',
					'SCRIPT_FILENAME' => self::ROOT . 'wp-login.php',
				),
				'',
			),
			'a sibling directory with a prefix in common' => array(
				array(
					'SCRIPT_NAME'     => '/wp-login.php',
					'SCRIPT_FILENAME' => '/srv/www/wordpress-old/wp-login.php',
				),
				self::ROOT,
			),
		);
	}

	/**
	 * Windows paths are compared with either slash.
	 */
	public function test_windows_paths_are_reconciled(): void {
		$result = Request_Factory::front_controller(
			array(
				'SCRIPT_NAME'     => '/wp-admin/edit.php',
				'SCRIPT_FILENAME' => 'C:\\inetpub\\wordpress\\wp-admin\\edit.php',
			),
			'C:\\inetpub\\wordpress\\'
		);

		$this->assertNotNull( $result );
		$this->assertSame( '/index.php', $result['SCRIPT_NAME'] );
	}

	/**
	 * The real `$_SERVER` is never modified.
	 *
	 * WordPress sets `$pagenow` from PHP_SELF, and the login form's action and
	 * the admin's redirects follow from that. Only the request's copy changes.
	 */
	public function test_the_real_server_values_are_untouched(): void {
		$_SERVER = array(
			'REQUEST_URI'     => '/wp-admin/edit.php',
			'SCRIPT_NAME'     => '/wp-admin/edit.php',
			'PHP_SELF'        => '/wp-admin/edit.php',
			'SCRIPT_FILENAME' => ABSPATH . 'wp-admin/edit.php',
			'HTTP_HOST'       => 'example.com',
		);

		$before  = $_SERVER;
		$request = Request_Factory::from_globals();

		$this->assertSame( '/wp-admin/edit.php', $request->getPathInfo() );
		$this->assertSame( '/index.php', $request->server->get( 'SCRIPT_NAME' ) );
		$this->assertSame( $before, $_SERVER, 'The factory changed the real $_SERVER.' );
	}

	/**
	 * The wp-config.php path builds from a named class and gets the same answer.
	 */
	public function test_building_from_a_named_class_normalises_too(): void {
		$_SERVER = array(
			'REQUEST_URI'     => '/wp-login.php',
			'SCRIPT_NAME'     => '/wp-login.php',
			'PHP_SELF'        => '/wp-login.php',
			'SCRIPT_FILENAME' => ABSPATH . 'wp-login.php',
			'HTTP_HOST'       => 'example.com',
		);

		$request = Request_Factory::from_globals_of( Request::class );

		$this->assertInstanceOf( Request::class, $request );
		$this->assertSame( '/wp-login.php', $request->getPathInfo() );
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
	 * @param string $path      Path relative to the site.
	 * @param string $site_path The site's path on its host.
	 * @param string $script    Expected SCRIPT_NAME.
	 * @param string $seen      The path the rules should see.
	 */
	public function test_made_up_requests_match_real_ones( string $path, string $site_path, string $script, string $seen ): void {
		$root   = dirname( __DIR__, 2 ) . '/';
		$server = Request_Factory::server_for( $path, $site_path, $root );

		$this->assertSame( $script, $server['SCRIPT_NAME'] );

		$request = Request::create( $server['REQUEST_URI'], 'GET', array(), array(), array(), $server );

		Request_Factory::normalise( $request );

		$this->assertSame( $seen, $request->getPathInfo() );
	}

	/**
	 * Paths the request tester and Site Health make requests for.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3: string}>
	 */
	public static function made_up_requests(): array {
		return array(
			'an existing file'            => array( '/bootstrap.php', '', '/bootstrap.php', '/bootstrap.php' ),
			'an existing file, a query'   => array( '/bootstrap.php?x=1', '', '/bootstrap.php', '/bootstrap.php' ),
			'a nested existing file'      => array( '/src/Plugin.php', '', '/src/Plugin.php', '/src/Plugin.php' ),
			'an existing file, path info' => array( '/bootstrap.php/extra', '', '/bootstrap.php', '/bootstrap.php/extra' ),
			'a missing file'              => array( '/missing.php', '', '/index.php', '/missing.php' ),
			'a page'                      => array( '/sample-page/', '', '/index.php', '/sample-page/' ),
			'subdirectory existing file'  => array( '/bootstrap.php', '/blog', '/blog/bootstrap.php', '/bootstrap.php' ),
			'subdirectory page'           => array( '/sample-page/', '/blog/', '/blog/index.php', '/sample-page/' ),
		);
	}

	/**
	 * Build a request from server values and put it through the factory.
	 *
	 * @param string $uri         REQUEST_URI.
	 * @param string $script_name SCRIPT_NAME, and PHP_SELF.
	 * @param string $file        SCRIPT_FILENAME.
	 */
	private function normalised( string $uri, string $script_name, string $file ): Request {
		$query = (string) parse_url( $uri, PHP_URL_QUERY ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- no WordPress in a unit test.

		$request = new Request(
			array(),
			array(),
			array(),
			array(),
			array(),
			array(
				'REQUEST_URI'     => $uri,
				'QUERY_STRING'    => $query,
				'SCRIPT_NAME'     => $script_name,
				'PHP_SELF'        => $script_name,
				'SCRIPT_FILENAME' => $file,
				'HTTP_HOST'       => 'example.com',
			)
		);

		$replacement = Request_Factory::front_controller( $request->server->all(), self::ROOT );

		foreach ( null === $replacement ? array() : $replacement as $key => $value ) {
			$request->server->set( $key, $value );
		}

		return $request;
	}
}
