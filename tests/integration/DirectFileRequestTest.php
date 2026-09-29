<?php
/**
 * Directly requested PHP files, over HTTP, through the wp-config.php path.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Request_Tester;

/**
 * Rules see the path of a file requested directly, not `/`.
 *
 * WordPress serves real pages from files other than index.php: wp-login.php,
 * xmlrpc.php, every wp-admin screen. For those the web server sets
 * SCRIPT_NAME to the requested file, Symfony takes it as the base URL, and the
 * path the library matched was `/` (#30). Every earlier HTTP test requested a
 * URL routed through index.php, which is why nothing caught it.
 *
 * So these request real files. PHP's built-in server runs a requested `.php`
 * file directly with SCRIPT_NAME set to it -- exactly what nginx and Apache do
 * -- and falls back to index.php for anything else, which is WordPress's
 * rewrite. The docroot is a stand-in WordPress: each stub defines ABSPATH the
 * way WordPress does and requires the wp-config.php fixture, which runs the
 * real bootstrap. A second copy under `/blog/` is a site installed in a
 * subdirectory.
 *
 * Run against `main` before the fix, every test here but the Site Health one
 * fails: the rate limit never counts, the admin rule never matches, the
 * negated rule matches the admin screen, and the log says `/`.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Request_Factory
 * @covers \Kanopi\BasicFirewall\Request_Tester
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class DirectFileRequestTest extends Settings_Snapshot {

	/**
	 * What the fixture prints once the firewall has let a request through.
	 */
	private const SERVED = 'SERVED BY WORDPRESS';

	/**
	 * The files each stand-in site has, relative to its ABSPATH.
	 */
	private const FILES = array( 'index.php', 'wp-login.php', 'xmlrpc.php', 'wp-cron.php', 'wp-admin/index.php', 'wp-admin/edit.php' );

	/**
	 * Prefix of every file these tests write to the private directory.
	 */
	private const STORE = 'direct-file-test-';

	/**
	 * The built-in server's process.
	 *
	 * @var resource|null
	 */
	private static $server = null;

	/**
	 * The built-in server's base URL.
	 *
	 * @var string
	 */
	private static string $base = '';

	/**
	 * The stand-in docroot.
	 *
	 * @var string
	 */
	private static string $docroot = '';

	/**
	 * Lay out the docroot and start a server on it.
	 */
	public static function setUpBeforeClass(): void {
		parent::setUpBeforeClass();

		$probe = stream_socket_server( 'tcp://127.0.0.1:0' );

		if ( false === $probe ) {
			return;
		}

		$name = (string) stream_socket_get_name( $probe, false );
		fclose( $probe ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- a socket, not a file.

		$port = (int) substr( $name, (int) strrpos( $name, ':' ) + 1 );

		self::make_docroot();

		$env = getenv();
		$env = array_merge(
			is_array( $env ) ? $env : array(),
			array(
				'BFW_EARLY_PLUGIN_PATH'  => dirname( __DIR__, 2 ),
				'BFW_EARLY_PRIVATE_PATH' => Plugin::instance()->paths()->base(),
			)
		);

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open -- a test starting a web server, never loaded by a site.
		$process = proc_open(
			// No router script: the server runs the requested file itself.
			array( PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', self::$docroot ),
			array(
				0 => array( 'file', '/dev/null', 'r' ),
				1 => array( 'file', '/dev/null', 'w' ),
				2 => array( 'file', '/dev/null', 'w' ),
			),
			$pipes,
			self::$docroot,
			$env
		);

		if ( ! is_resource( $process ) ) {
			return;
		}

		self::$server = $process;
		self::$base   = 'http://127.0.0.1:' . $port;

		for ( $i = 0; $i < 50; $i++ ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fsockopen -- a socket, refused until the server is up.
			$socket = @fsockopen( '127.0.0.1', $port, $errno, $errstr, 0.1 );

			if ( false !== $socket ) {
				fclose( $socket ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- a socket, not a file.

				return;
			}

			usleep( 100000 );
		}
	}

	/**
	 * Stop the server and remove the docroot.
	 */
	public static function tearDownAfterClass(): void {
		if ( is_resource( self::$server ) ) {
			proc_terminate( self::$server );
			proc_close( self::$server );
		}

		self::$server = null;

		if ( '' !== self::$docroot ) {
			$files = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( self::$docroot, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::CHILD_FIRST
			);

			// phpcs:disable WordPress.WP.AlternativeFunctions -- a test's own scratch files.
			foreach ( $files as $file ) {
				$file->isDir() ? rmdir( $file->getPathname() ) : unlink( $file->getPathname() );
			}

			rmdir( self::$docroot );
			// phpcs:enable WordPress.WP.AlternativeFunctions

			self::$docroot = '';
		}

		parent::tearDownAfterClass();
	}

	/**
	 * Two stand-in WordPress installs: one at the root, one under `/blog/`.
	 *
	 * Each stub defines ABSPATH from its own location, as wp-config.php does
	 * from `__DIR__`, so the path is the one the server resolves the file to.
	 */
	private static function make_docroot(): void {
		$docroot = sys_get_temp_dir() . '/bfw-direct-file-' . bin2hex( random_bytes( 4 ) );
		$fixture = __DIR__ . '/fixtures/wp-config-early-path.php';

		// phpcs:disable WordPress.WP.AlternativeFunctions -- a test's own scratch files, outside WordPress.
		foreach ( array( '', 'blog/' ) as $site ) {
			foreach ( self::FILES as $file ) {
				$target = $docroot . '/' . $site . $file;
				$depth  = substr_count( $file, '/' );

				if ( ! is_dir( dirname( $target ) ) ) {
					mkdir( dirname( $target ), 0700, true );
				}

				file_put_contents(
					$target,
					sprintf(
						"<?php\ndefine( 'ABSPATH', %s . '/' );\nrequire %s;\n",
						0 === $depth ? '__DIR__' : 'dirname( __DIR__, ' . $depth . ' )',
						var_export( $fixture, true ) // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- writing a PHP literal, not debugging.
					)
				);
			}
		}
		// phpcs:enable WordPress.WP.AlternativeFunctions

		self::$docroot = $docroot;
	}

	/**
	 * Release anything the rules recorded.
	 */
	protected function tearDown(): void {
		$this->forget_stores();

		parent::tearDown();
	}

	/**
	 * A `/wp-login.php 5 60` rate limit counts direct requests for wp-login.php.
	 *
	 * The case the issue was opened for: the limit never counted a single
	 * login attempt, because every one of them was a request for `/`.
	 */
	public function test_a_login_rate_limit_counts_direct_requests(): void {
		$this->given_rules(
			array(
				array(
					'id'       => 'direct_rate',
					'type'     => 'rate_limit',
					'label'    => 'Direct login rate limit',
					'response' => 'block',
					'record'   => 'no',
					'settings' => array(
						'paths'                => array(
							array(
								'pattern' => '/wp-login.php',
								'limit'   => 5,
								'window'  => 60,
							),
						),
						'default_limit'        => 60,
						'default_window'       => 60,
						'limit_unlisted_paths' => false,
						'status_code'          => 429,
						'storage'              => array(
							'backend' => 'file',
							'file'    => 'private://' . self::STORE . 'ratelimit.data',
						),
					),
				),
			)
		);

		$statuses = array();

		for ( $i = 0; $i < 6; $i++ ) {
			$statuses[] = $this->request( '/wp-login.php' )['status'];
		}

		$this->assertSame( array( 200, 200, 200, 200, 200 ), array_slice( $statuses, 0, 5 ), 'A request within the allowance was refused: ' . implode( ', ', $statuses ) );
		$this->assertSame( 429, $statuses[5], 'The sixth direct request for wp-login.php was not refused, so the limit is not counting it: ' . implode( ', ', $statuses ) );

		// A different page is not in the limit's count.
		$this->assertSame( 200, $this->request( '/bfw-direct-page' )['status'] );
	}

	/**
	 * `path starts_with /wp-admin` matches an admin screen, and the tester agrees.
	 */
	public function test_an_admin_path_rule_matches_admin_screens(): void {
		$this->given_rules( array( self::url_rule( 'direct_admin', array( self::condition( 'path', 'starts_with', '/wp-admin' ) ) ) ) );

		$this->assertSame( 403, $this->request( '/wp-admin/edit.php' )['status'], 'The rule did not match an admin screen.' );
		$this->assertSame( 403, $this->request( '/wp-admin/edit.php?post_type=page' )['status'] );
		$this->assertSame( 403, $this->request( '/wp-admin/' )['status'], 'The rule did not match the dashboard.' );

		$login = $this->request( '/wp-login.php' );

		$this->assertSame( 200, $login['status'], 'The rule matched a page outside /wp-admin.' );
		$this->assertStringContainsString( self::SERVED, $login['body'] );

		// WordPress reads $pagenow from PHP_SELF: the real one is untouched.
		$this->assertSame( '/wp-login.php', $login['php_self'], 'The firewall changed the PHP_SELF WordPress reads.' );

		// The test screen answers what production just did.
		$tester = new Request_Tester();

		$this->assertSame( 'block', $tester->test( array( 'path' => '/wp-admin/edit.php' ) )['verdict'], 'The request tester disagrees with production about an admin screen.' );
		$this->assertSame( 'allow', $tester->test( array( 'path' => '/wp-login.php' ) )['verdict'], 'The request tester disagrees with production about wp-login.php.' );
	}

	/**
	 * A negated path condition does not match every admin screen.
	 *
	 * With every direct request read as `/`, "path does not start with
	 * /wp-admin" was true on every admin screen, and an all-conditions rule
	 * built on it refused the very pages it was written to leave alone.
	 */
	public function test_a_negated_path_condition_does_not_match_an_admin_screen(): void {
		$outside = self::condition( 'path', 'starts_with', '/wp-admin' );

		$outside['negate'] = true;

		$this->given_rules(
			array(
				self::url_rule(
					'direct_negated',
					array(
						$outside,
						// Only the test's own requests, marked by a query value.
						self::condition( 'query.bfw', 'equals', 'negated' ),
					),
					'all'
				),
			)
		);

		$this->assertSame( 200, $this->request( '/wp-admin/edit.php?bfw=negated' )['status'], 'A rule for paths outside /wp-admin refused an admin screen.' );
		$this->assertSame( 403, $this->request( '/wp-login.php?bfw=negated' )['status'], 'The rule does not refuse anything, so this test proves nothing.' );
		$this->assertSame( 403, $this->request( '/bfw-direct-page?bfw=negated' )['status'] );
	}

	/**
	 * A rule on xmlrpc.php refuses requests for it.
	 */
	public function test_xmlrpc_can_be_blocked(): void {
		$this->given_rules( array( self::url_rule( 'direct_xmlrpc', array( self::condition( 'path', 'equals', '/xmlrpc.php' ) ) ) ) );

		$this->assertSame( 403, $this->request( '/xmlrpc.php' )['status'], 'A GET for xmlrpc.php was not refused.' );
		$this->assertSame( 403, $this->request( '/xmlrpc.php', array(), 'POST' )['status'], 'A POST to xmlrpc.php was not refused.' );
		$this->assertSame( 200, $this->request( '/wp-cron.php' )['status'], 'The rule refused another direct file.' );
	}

	/**
	 * The log and the block record carry the requested path and URL.
	 *
	 * They used to say `path: /` beside `url: .../edit.php/?...` -- so the one
	 * place somebody investigating a block would look also said `/`.
	 */
	public function test_the_log_and_block_record_carry_the_requested_path(): void {
		$log = Plugin::instance()->paths()->base() . '/' . self::STORE . 'firewall.log';

		$rule = self::url_rule( 'direct_recorded', array( self::condition( 'path', 'equals', '/wp-admin/edit.php' ) ) );

		$rule['record'] = 'yes';

		$this->given_rules(
			array( $rule ),
			'block',
			array(
				'logger' => array(
					array(
						'type'    => 'stream',
						'enabled' => true,
						'level'   => 'info',
						'path'    => $log,
					),
				),
			)
		);

		$this->assertSame( 403, $this->request( '/wp-admin/edit.php?post_type=page' )['status'] );

		$logged = file_exists( $log ) ? (string) file_get_contents( $log ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a local log file.

		$this->assertStringContainsString( '"path":"/wp-admin/edit.php"', str_replace( '\\/', '/', $logged ), 'The log does not record the requested path.' );
		$this->assertStringNotContainsString( '"path":"/"', str_replace( '\\/', '/', $logged ), 'The log still records a direct request as `/`.' );
		$this->assertStringNotContainsString( 'edit.php/', str_replace( '\\/', '/', $logged ), 'The logged URL has a `/` after the file name.' );

		$store = Plugin::instance()->paths()->base() . '/' . self::STORE . 'blocked.data';
		$data  = file_exists( $store ) ? json_decode( (string) file_get_contents( $store ), true ) : null; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the test's own block store.

		$this->assertIsArray( $data, 'Nothing was recorded, so the record cannot be checked.' );
		$this->assertContains( '/wp-admin/edit.php', self::values_of( $data, 'path' ), 'The block record does not carry the requested path.' );
		$this->assertNotContains( '/', self::values_of( $data, 'path' ), 'The block record still says `/`.' );
	}

	/**
	 * A challenge on a direct file posts to the challenge path and returns to the file.
	 *
	 * The form's action is built from the request's base path, and the return
	 * address from its request URI. For an admin screen the base path used to
	 * be `/wp-admin`, so a challenge there posted somewhere the firewall never
	 * looked for an answer.
	 */
	public function test_a_challenge_on_a_direct_file_returns_to_it(): void {
		$this->given_rules(
			array(
				self::url_rule(
					'direct_challenge',
					array(
						self::condition( 'path', 'equals', '/wp-login.php' ),
						self::condition( 'path', 'starts_with', '/wp-admin' ),
					),
					'any',
					'challenge'
				),
			)
		);

		$path = (string) Plugin::instance()->settings()->get( 'challenge.path', '/basic-firewall/challenge' );

		foreach (
			array(
				'/wp-login.php?redirect_to=%2Fwp-admin%2F' => '',
				'/wp-admin/edit.php'                       => '',
				'/blog/wp-login.php'                       => '/blog',
			) as $requested => $prefix
		) {
			$body = $this->request( $requested )['body'];

			$this->assertStringContainsString( 'Verification required', $body, $requested . ' was not challenged.' );
			$this->assertStringContainsString( 'action="' . $prefix . $path . '"', $body, $requested . ' posts its answer somewhere the firewall does not look.' );
			$this->assertStringContainsString( 'value="' . $requested . '"', $body, $requested . ' does not return the visitor to the page they asked for.' );
		}
	}

	/**
	 * A site in a subdirectory matches the same rules on its own files.
	 */
	public function test_a_subdirectory_install_sees_the_path_under_it(): void {
		$this->given_rules(
			array(
				self::url_rule(
					'direct_subdirectory',
					array(
						self::condition( 'path', 'equals', '/wp-login.php' ),
						self::condition( 'path', 'starts_with', '/wp-admin' ),
					)
				),
			)
		);

		$this->assertSame( 403, $this->request( '/blog/wp-login.php' )['status'], 'wp-login.php under /blog/ was not matched as /wp-login.php.' );
		$this->assertSame( 403, $this->request( '/blog/wp-admin/edit.php' )['status'], 'An admin screen under /blog/ was not matched.' );
		$this->assertSame( 200, $this->request( '/blog/xmlrpc.php' )['status'], 'The rule refused a file it does not name.' );

		$page = $this->request( '/blog/bfw-direct-page' );

		$this->assertSame( 200, $page['status'] );
		$this->assertStringContainsString( self::SERVED, $page['body'] );
	}

	/**
	 * Site Health's regression check passes on a working build.
	 */
	public function test_site_health_confirms_the_path_of_a_direct_request(): void {
		$result = Site_Health::check( 'request_path' );

		$this->assertSame( 'good', $result['status'], wp_strip_all_tags( $result['description'] ) );
	}

	/**
	 * Install a rule set and compile it.
	 *
	 * @param array<int, array<string, mixed>> $rules    Rules.
	 * @param string                           $mode     Operating mode.
	 * @param array<string, mixed>             $document Further top-level settings.
	 */
	private function given_rules( array $rules, string $mode = 'block', array $document = array() ): void {
		if ( null === self::$server ) {
			$this->markTestSkipped( 'PHP\'s built-in web server could not be started.' );
		}

		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$this->markTestSkipped( 'BASIC_FIREWALL_MODE pins this site\'s mode, so a fixture cannot choose one.' );
		}

		$this->forget_stores();

		foreach ( $rules as $index => $rule ) {
			$rules[ $index ] = $rule + array(
				'enabled'         => true,
				'weight'          => 0,
				'status_code'     => 403,
				'expiration'      => 600,
				'record'          => 'no',
				'redirect_to'     => '',
				'redirect_status' => 302,
				'mark_as'         => '',
				'mark_header'     => '',
			);
		}

		$this->given_settings(
			$document + array(
				'global'    => array(
					'mode'            => $mode,
					'banning_message' => 'Refused by the direct file test.',
				),
				'challenge' => array(
					'provider' => 'math',
					'secret'   => str_repeat( 'direct-file-secret-', 3 ),
				),

				// File storage, which needs no connection: the fixture
				// defines no DB_ constants.
				'storage'   => array(
					'backend' => 'file',
					'file'    => array(
						'storage_file' => self::STORE . 'blocked.data',
						'offense_file' => self::STORE . 'offenses.data',
					),
				),
				'rules'     => $rules,
			)
		);

		$result = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $result['written'], 'The fixture did not compile.' );
		$this->assertSame( array(), $result['problems'], 'The fixture compiled with problems.' );
	}

	/**
	 * A URL rule.
	 *
	 * @param string                           $id         Rule ID.
	 * @param array<int, array<string, mixed>> $conditions Conditions.
	 * @param string                           $match_type `any` or `all`.
	 * @param string                           $response   Response.
	 *
	 * @return array<string, mixed>
	 */
	private static function url_rule( string $id, array $conditions, string $match_type = 'any', string $response = 'block' ): array {
		return array(
			'id'                 => $id,
			'type'               => 'url',
			'label'              => $id,
			'response'           => $response,
			'challenge_provider' => 'math',
			'settings'           => array(
				'match_type' => $match_type,
				'conditions' => $conditions,
			),
		);
	}

	/**
	 * A condition.
	 *
	 * @param string $variable Variable.
	 * @param string $operator Operator.
	 * @param string $value    Value.
	 *
	 * @return array<string, mixed>
	 */
	private static function condition( string $variable, string $operator, string $value ): array {
		return array(
			'variable' => $variable,
			'operator' => $operator,
			'value'    => $value,
		);
	}

	/**
	 * Every value stored under a key, at any depth.
	 *
	 * @param array<mixed> $data Decoded data.
	 * @param string       $key  Key.
	 *
	 * @return list<mixed>
	 */
	private static function values_of( array $data, string $key ): array {
		$found = array();

		array_walk_recursive(
			$data,
			static function ( $value, $name ) use ( $key, &$found ): void {
				if ( $name === $key ) {
					$found[] = $value;
				}
			}
		);

		return $found;
	}

	/**
	 * Delete everything these tests wrote to the private directory.
	 */
	private function forget_stores(): void {
		foreach ( (array) glob( Plugin::instance()->paths()->base() . '/' . self::STORE . '*' ) as $file ) {
			if ( is_string( $file ) && is_file( $file ) ) {
				wp_delete_file( $file );
			}
		}
	}

	/**
	 * Make a request of the stand-in docroot.
	 *
	 * @param string                $path    Path to request.
	 * @param array<string, string> $headers Request headers.
	 * @param string                $method  HTTP method.
	 *
	 * @return array{status: int, body: string, php_self: string}
	 */
	private function request( string $path, array $headers = array(), string $method = 'GET' ): array {
		$response = wp_remote_request(
			self::$base . $path,
			array(
				'method'      => $method,
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => $headers,
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->fail( 'The request failed: ' . $response->get_error_message() );
		}

		return array(
			'status'   => (int) wp_remote_retrieve_response_code( $response ),
			'body'     => (string) wp_remote_retrieve_body( $response ),
			'php_self' => (string) wp_remote_retrieve_header( $response, 'x-early-php-self' ),
		);
	}
}
