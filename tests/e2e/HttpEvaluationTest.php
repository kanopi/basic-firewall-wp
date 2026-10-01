<?php
/**
 * End-to-end coverage over real HTTP.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\e2e;

use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;
use PHPUnit\Framework\TestCase;

/**
 * Drives the firewall through the web server, not through the evaluator.
 *
 * Everything else in this suite calls `Firewall::evaluate()` directly, which
 * proves the rules are right and proves nothing about whether they run. Between
 * a correct rule set and a blocked request sit the mu-plugin, the wp-config.php
 * bootstrap, the compiled file on disk, the library's parse cache, the outcome
 * responder and the web server -- and every defect this plugin has shipped so
 * far lived in that gap rather than in the rules.
 *
 * So these tests make real requests. They are slower, they need a running site,
 * and they are the only tests here that would have caught a scoped build whose
 * plugin classes silently failed to load.
 *
 * Set BFW_E2E_URL to the site's base URL to run them.
 */
final class HttpEvaluationTest extends TestCase {

	/**
	 * The settings as they were before the test.
	 *
	 * @var mixed
	 */
	private $snapshot;

	/**
	 * The site being driven.
	 *
	 * @var string
	 */
	private string $base = '';

	/**
	 * Skip unless a site is available, and snapshot what we are about to change.
	 */
	protected function setUp(): void {
		parent::setUp();

		$base = getenv( 'BFW_E2E_URL' );

		if ( ! is_string( $base ) || '' === $base ) {
			$this->markTestSkipped( 'Set BFW_E2E_URL to the site base URL to run the end-to-end suite.' );
		}

		$this->base     = rtrim( $base, '/' );
		$this->snapshot = get_option( Schema::OPTION, null );

		Plugin::instance()->settings()->flush();
	}

	/**
	 * Put the site back exactly as it was, compiled file included.
	 */
	protected function tearDown(): void {
		if ( null === $this->snapshot ) {
			delete_option( Schema::OPTION );
		} else {
			update_option( Schema::OPTION, $this->snapshot, false );
		}

		Plugin::instance()->settings()->flush();

		// The compiled file is what the runtime reads, so restoring the option
		// alone would leave the site enforcing this test's fixture.
		Plugin::instance()->compiled()->rebuild();

		// And release anything these tests blocked, including ourselves.
		Plugin::instance()->blocked()->clear();

		$this->reset_rate_limit_counters();

		parent::tearDown();
	}

	/**
	 * Install a rule set and compile it.
	 *
	 * @param array<int, array<string, mixed>> $rules Rules to enforce.
	 * @param string                           $mode  Operating mode.
	 */
	private function given_rules( array $rules, string $mode = 'block' ): void {
		// Fill in the keys the schema expects, so a fixture naming only what it
		// cares about does not have the rest coerced to defaults mid-test.
		foreach ( $rules as $index => $rule ) {
			$rules[ $index ] = $rule + array(
				'record'          => 'default',
				'redirect_to'     => '',
				'redirect_status' => 302,
				'mark_as'         => '',
				'mark_header'     => '',
			);
		}

		$settings = array_replace_recursive(
			Schema::defaults(),
			array(
				'global'    => array(
					'mode'            => $mode,
					'banning_message' => 'Blocked by the end-to-end test.',
				),

				/*
				 * A signing secret, because Schema::defaults() has none.
				 *
				 * On a real site Challenge_Secret::ensure() generates one at
				 * activation; a fixture that replaces the whole document wipes
				 * it, and the compiler then -- correctly -- refuses to emit a
				 * challenge section and warns that every rule would stop being
				 * enforced. That warning is the plugin working. The fixture has
				 * to supply what activation would have.
				 */
				'challenge' => array(
					'provider' => 'math',
					'secret'   => str_repeat( 'e2e-secret-', 4 ),
				),
				'rules'     => $rules,
			)
		);

		Plugin::instance()->settings()->replace( $settings );
		Plugin::instance()->settings()->flush();

		$result = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $result['written'], 'The fixture did not compile.' );
		$this->assertSame( array(), $result['problems'], 'The fixture compiled with problems.' );

		// A block recorded by a previous request would answer before the rules do.
		Plugin::instance()->blocked()->clear();

		$this->reset_rate_limit_counters();
	}

	/**
	 * Delete any persisted rate limit counters.
	 *
	 * Counters survive between runs, which is correct behaviour and ruins a
	 * repeated test: the second run of the rate limit case started with the
	 * allowance already spent and was rejected on its first request. That is the
	 * same durability an operator relies on -- the window is real time, not
	 * request count -- so the fixture clears it rather than the plugin
	 * forgetting it.
	 */
	private function reset_rate_limit_counters(): void {
		$base = Plugin::instance()->paths()->base();

		foreach ( (array) glob( $base . '/e2e-ratelimit.data*' ) as $file ) {
			if ( is_string( $file ) && is_file( $file ) ) {
				wp_delete_file( $file );
			}
		}
	}

	/**
	 * Make a request and return the status code.
	 *
	 * @param string                $path    Path to request.
	 * @param array<string, string> $headers Extra headers.
	 *
	 * @return array{status: int, body: string, location: string, cache: array<string, string>}
	 */
	private function request( string $path, array $headers = array() ): array {
		$response = wp_remote_get(
			$this->base . $path,
			array(
				'timeout'     => 15,
				'redirection' => 0,
				// A development certificate is not what is under test.
				'sslverify'   => false,
				'headers'     => array_merge(
					array( 'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15' ),
					$headers
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->fail( 'The request failed: ' . $response->get_error_message() );
		}

		return array(
			'status'   => (int) wp_remote_retrieve_response_code( $response ),
			'body'     => (string) wp_remote_retrieve_body( $response ),
			'location' => (string) wp_remote_retrieve_header( $response, 'location' ),
			'cache'    => array(
				'Cache-Control'     => (string) wp_remote_retrieve_header( $response, 'cache-control' ),
				'Pragma'            => (string) wp_remote_retrieve_header( $response, 'pragma' ),
				'Expires'           => (string) wp_remote_retrieve_header( $response, 'expires' ),
				'Surrogate-Control' => (string) wp_remote_retrieve_header( $response, 'surrogate-control' ),
				'CDN-Cache-Control' => (string) wp_remote_retrieve_header( $response, 'cdn-cache-control' ),
			),
		);
	}

	/**
	 * A blocking rule rejects a real request, and only the matching one.
	 */
	public function test_a_block_rule_rejects_a_real_request(): void {
		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_block_path',
					'type'     => 'url',
					'label'    => 'End-to-end blocked path',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/bfw-e2e-blocked',
							),
						),
					),
				),
			)
		);

		/*
		 * The control request comes FIRST, and that ordering is the test.
		 *
		 * Blocking a request records the client in the durable block list, so
		 * every later request from the same address is refused by the block list
		 * rather than by the rules. Asserting "an ordinary request still works"
		 * after triggering a block therefore fails on a perfectly healthy
		 * firewall -- which is what happened, and is the same behaviour the
		 * readme warns about under "load-testing your own site will block you".
		 *
		 * A firewall that rejects everything would pass the block assertion on
		 * its own, so the control is worth keeping; it just has to run before
		 * the address is in the block list.
		 */
		$allowed = $this->request( '/' );

		$this->assertSame( 200, $allowed['status'], 'An ordinary request was rejected.' );

		$blocked = $this->request( '/bfw-e2e-blocked' );

		$this->assertSame( 403, $blocked['status'], 'A matching request was not rejected over HTTP.' );
		$this->assertStringContainsString(
			'Blocked by the end-to-end test.',
			$blocked['body'],
			'The configured block message did not reach the client.'
		);
	}

	/**
	 * Log-only mode evaluates and records, and blocks nothing.
	 *
	 * The shipped default, and the one somebody relies on while watching the log
	 * for a few days before switching to Block.
	 */
	public function test_log_only_mode_does_not_block(): void {
		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_log_only',
					'type'     => 'url',
					'label'    => 'End-to-end log only',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/bfw-e2e-logged',
							),
						),
					),
				),
			),
			'log'
		);

		$this->assertNotSame(
			403,
			$this->request( '/bfw-e2e-logged' )['status'],
			'Log-only mode rejected a request. Nothing is supposed to be blocked in this mode.'
		);
	}

	/**
	 * A challenge rule serves an interstitial rather than the page.
	 *
	 * Asserted on the BODY, not the status, and that is the finding rather than
	 * a workaround. In blocking mode the library composes and sends the
	 * interstitial itself and then exits, so this plugin's outcome responder --
	 * which answers 503 with a Retry-After -- never runs. That responder is only
	 * reached on the exception path, which is what the request tester uses.
	 *
	 * The library answers 200, and 200 is right: the visitor is not being
	 * refused, they are being handed a puzzle. What identifies it is the page
	 * itself, which carries `noindex, nofollow` and `Cache-Control: no-store` so
	 * that neither a crawler nor a CDN keeps it.
	 */
	public function test_a_challenge_rule_serves_an_interstitial(): void {
		$this->given_rules(
			array(
				array(
					'id'                 => 'e2e_challenge',
					'type'               => 'url',
					'label'              => 'End-to-end challenge',
					'enabled'            => true,
					'response'           => 'challenge',
					'weight'             => 0,
					'expiration'         => 600,
					'challenge_provider' => 'math',
					'settings'           => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/bfw-e2e-challenge',
							),
						),
					),
				),
			)
		);

		$challenged = $this->request( '/bfw-e2e-challenge' );

		$this->assertStringContainsString(
			'Verification required',
			$challenged['body'],
			'A challenged request was served the ordinary page instead of the interstitial.'
		);

		$this->assertStringContainsString(
			'noindex',
			$challenged['body'],
			'The interstitial does not tell crawlers to ignore it.'
		);

		// And an unmatched path is untouched.
		$this->assertStringNotContainsString(
			'Verification required',
			$this->request( '/' )['body'],
			'An unmatched request was challenged.'
		);
	}

	/**
	 * #34: a per-rule ALTCHA challenge on a routed page, in both modes.
	 *
	 * The reported setup: a `url` rule on a path prefix, `response:
	 * challenge`, the rule naming `altcha` while the default is `math`, on a
	 * path WordPress routes through index.php. A path of its own rather than
	 * a real page's, so it is the same under plain permalinks, where a page's
	 * permalink is `/?page_id=2` and has no path to match. In `exception`
	 * mode the report was the page itself, with WordPress's cache headers,
	 * then cached at the edge. Whichever path answers -- the library in
	 * `block` mode, the plugin's responder in `exception` mode -- the visitor
	 * gets the ALTCHA interstitial, never the page, and every no-store header
	 * a cache in front of the site might read.
	 */
	public function test_a_per_rule_altcha_challenge_guards_a_routed_page_in_both_modes(): void {
		$path = '/bfw-e2e-learning-resources/some-page/';

		$rule = array(
			'id'                 => 'e2e_issue_34',
			'type'               => 'url',
			'label'              => 'Issue 34',
			'enabled'            => true,
			'response'           => 'challenge',
			'weight'             => 0,
			'expiration'         => 600,
			'challenge_provider' => 'altcha',
			'settings'           => array(
				'match_type' => 'any',
				'conditions' => array(
					array(
						'variable' => 'path',
						'operator' => 'starts_with',
						'value'    => '/bfw-e2e-learning-resources',
					),
				),
			),
		);

		foreach ( array(
			'exception' => 503,
			'block'     => 200,
		) as $mode => $status ) {
			$this->given_rules( array( $rule ), $mode );

			$response = $this->request( $path . '?fresh=' . wp_rand() );

			$this->assertSame( $status, $response['status'], $mode . ': not challenged.' );
			$this->assertStringContainsString( 'altcha-widget', $response['body'], $mode . ': the rule\'s own provider did not render the page.' );
			$this->assertStringNotContainsString( 'wp-content/themes', $response['body'], $mode . ': WordPress served the page.' );
			$this->assertSame(
				array(
					'Cache-Control'     => 'private, no-store, no-cache, must-revalidate, max-age=0',
					'Pragma'            => 'no-cache',
					'Expires'           => '0',
					'Surrogate-Control' => 'no-store',
					'CDN-Cache-Control' => 'no-store',
				),
				$response['cache'],
				$mode . ': the interstitial can be cached.'
			);
		}
	}

	/**
	 * A redirect sends the visitor somewhere instead of refusing them.
	 *
	 * Needs library 2.26.0. Temporary by default, deliberately: a rule's verdict
	 * changes with the next edit, and a 301 is cached by browsers and
	 * intermediaries more or less forever.
	 */
	public function test_a_redirect_rule_sends_the_visitor_elsewhere(): void {
		if ( ! ( new Library_Capabilities() )->has_soft_responses() ) {
			$this->markTestSkipped( 'The installed library predates redirect and mark responses.' );
		}

		$this->given_rules(
			array(
				array(
					'id'              => 'e2e_redirect',
					'type'            => 'url',
					'label'           => 'End-to-end redirect',
					'enabled'         => true,
					'response'        => 'redirect',
					'weight'          => 0,
					'redirect_to'     => '/why-was-i-redirected',
					'redirect_status' => 302,
					'settings'        => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/bfw-e2e-redirect',
							),
						),
					),
				),
			)
		);

		$response = $this->request( '/bfw-e2e-redirect' );

		$this->assertSame( 302, $response['status'], 'The visitor was not redirected.' );
		$this->assertSame(
			'/why-was-i-redirected',
			$response['location'],
			'The visitor was redirected somewhere other than the configured location.'
		);

		/*
		 * And nothing was recorded. A redirect is not a ban: a client sent to a
		 * notice page who came back to find themselves blocked instead would
		 * have no way to understand why.
		 */
		$this->assertSame(
			0,
			count( Plugin::instance()->blocked()->all()['clients'] ),
			'A redirect recorded the client. It must not, unless the rule opts in.'
		);
	}

	/**
	 * A block can refuse without recording.
	 *
	 * The lockdown case, and the reason `record` exists: a rule that refuses
	 * everybody and records them leaves a block list full of customers once it
	 * is lifted, each on an escalating ban nobody asked for.
	 */
	public function test_a_block_can_refuse_without_recording(): void {
		if ( ! ( new Library_Capabilities() )->has_record_control() ) {
			$this->markTestSkipped( 'The installed library always records a block.' );
		}

		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_lockdown',
					'type'     => 'url',
					'label'    => 'End-to-end lockdown',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'record'   => 'no',
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/bfw-e2e-lockdown',
							),
						),
					),
				),
			)
		);

		$this->assertSame(
			403,
			$this->request( '/bfw-e2e-lockdown' )['status'],
			'The lockdown rule did not refuse the request.'
		);

		$this->assertSame(
			0,
			count( Plugin::instance()->blocked()->all()['clients'] ),
			'A block with record disabled still wrote the client to the block list. Lifting this lockdown would leave every visitor banned.'
		);
	}

	/**
	 * A facet count is read off the query string the web server actually passed.
	 *
	 * The integration tests set QUERY_STRING by hand; this is the check that a
	 * real server hands PHP the raw string the library counts, so a repeated
	 * `f=` and encoded brackets count over HTTP as they do there. Record is
	 * off, so a refused request does not ban the address the later requests
	 * come from.
	 */
	public function test_a_facet_count_is_honoured_over_http(): void {
		if ( ! ( new Library_Capabilities() )->has_record_control() ) {
			$this->markTestSkipped( 'The installed library always records a block.' );
		}

		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_facets',
					'type'     => 'url',
					'label'    => 'End-to-end facet crawling',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'record'   => 'no',
					'settings' => array(
						'match_type' => 'all',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'starts_with',
								'value'    => '/bfw-e2e-search',
							),
							array(
								'variable' => 'query_count.f',
								'operator' => 'gt',
								'value'    => '3',
							),
						),
					),
				),
			)
		);

		$this->assertNotSame( 403, $this->request( '/bfw-e2e-search?f[0]=a&f[1]=b&f[2]=c' )['status'], 'Three facets were refused under a cap of three.' );

		foreach ( array(
			'f[0]=a&f[1]=b&f[2]=c&f[3]=d',
			'f=a&f=b&f=c&f=d',
			'f%5B0%5D=a&f%5B1%5D=b&f%5B2%5D=c&f%5B3%5D=d',
			'f[]=a&q=x&f[7]=b&f=c&f[x]=d',
		) as $query ) {
			$this->assertSame( 403, $this->request( '/bfw-e2e-search?' . $query )['status'], "Four facets sent as ?$query were not refused." );
		}

		$this->assertSame( 0, count( Plugin::instance()->blocked()->all()['clients'] ), 'A rule with record off wrote the client to the block list.' );
	}

	/**
	 * A member of an exempt role is let through, and nobody else is.
	 *
	 * Over HTTP because the whole point is where each request is decided: a
	 * login cookie is left unevaluated by the wp-config.php path (when the
	 * site has the snippet) and by the mu-plugin at muplugins_loaded, and the
	 * runner validates it at plugins_loaded. A forged cookie must come out of
	 * that the same as no cookie at all.
	 */
	public function test_an_exempt_role_is_not_evaluated_and_a_forged_cookie_is(): void {
		require_once ABSPATH . 'wp-admin/includes/user.php';

		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_bypass',
					'type'     => 'url',
					'label'    => 'End-to-end role bypass',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					// Nobody is written to the block list, so one request's
					// refusal is not the next request's answer.
					'record'   => 'no',
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/bfw-e2e-bypass',
							),
						),
					),
				),
			)
		);

		Plugin::instance()->settings()->set( 'global.bypass_roles', array( 'editor' ) );

		$editor     = wp_insert_user(
			array(
				'user_login' => 'bfw-e2e-editor-' . wp_generate_password( 6, false ),
				'user_pass'  => wp_generate_password(),
				'role'       => 'editor',
			)
		);
		$subscriber = wp_insert_user(
			array(
				'user_login' => 'bfw-e2e-subscriber-' . wp_generate_password( 6, false ),
				'user_pass'  => wp_generate_password(),
				'role'       => 'subscriber',
			)
		);

		$this->assertIsInt( $editor );
		$this->assertIsInt( $subscriber );

		$as = static fn ( string $value ): array => array( 'Cookie' => LOGGED_IN_COOKIE . '=' . rawurlencode( $value ) );

		try {
			$this->assertSame( 403, $this->request( '/bfw-e2e-bypass' )['status'], 'The rule does not refuse anybody, so this test proves nothing.' );
			$this->assertNotSame( 403, $this->request( '/bfw-e2e-bypass', $as( wp_generate_auth_cookie( $editor, time() + 600, 'logged_in' ) ) )['status'], 'A member of an exempt role was refused.' );
			$this->assertSame( 403, $this->request( '/bfw-e2e-bypass', $as( wp_generate_auth_cookie( $subscriber, time() + 600, 'logged_in' ) ) )['status'], 'A member of a role that is not exempt went unevaluated.' );
			$this->assertSame( 403, $this->request( '/bfw-e2e-bypass', $as( 'admin|' . ( time() + 600 ) . '|forged|forged' ) )['status'], 'A forged login cookie went unevaluated.' );
		} finally {
			wp_delete_user( $editor );
			wp_delete_user( $subscriber );
		}
	}

	/**
	 * A rate limit rejects once the allowance is spent, and not before.
	 *
	 * Worth doing over HTTP specifically: the request tester cannot exercise a
	 * rate limit at all, because counters start empty for a run and one request
	 * cannot exceed a limit.
	 */
	public function test_a_rate_limit_rejects_once_the_allowance_is_spent(): void {
		$limit = 3;

		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_rate_limit',
					'type'     => 'rate_limit',
					'label'    => 'End-to-end rate limit',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'settings' => array(
						'paths'                => array(
							array(
								'pattern' => '/bfw-e2e-rate',
								'limit'   => $limit,
								'window'  => 60,
							),
						),
						'default_limit'        => 60,
						'default_window'       => 60,
						// Only the listed path, or this caps the whole site and
						// the control request below would be rejected too.
						'limit_unlisted_paths' => false,
						'status_code'          => 429,
						'storage'              => array(
							'backend' => 'file',
							'file'    => 'private://e2e-ratelimit.data',
						),
					),
				),
			)
		);

		$statuses = array();

		// One more request than the allowance permits.
		for ( $i = 0; $i <= $limit; $i++ ) {
			$statuses[] = $this->request( '/bfw-e2e-rate' )['status'];
		}

		$this->assertNotContains(
			429,
			array_slice( $statuses, 0, $limit ),
			sprintf( 'A request within the allowance of %d was rejected: %s', $limit, implode( ', ', $statuses ) )
		);

		$this->assertContains(
			429,
			$statuses,
			sprintf( 'The allowance of %d was never enforced: %s', $limit, implode( ', ', $statuses ) )
		);
	}

	/**
	 * A directly requested file is matched on its own path, on both paths.
	 *
	 * WordPress serves wp-login.php, xmlrpc.php and every admin screen from
	 * the file requested rather than through index.php, and the library used
	 * to see each of them as `/` (#30). Every other test here requests a URL
	 * routed through index.php, which is why none of them noticed.
	 *
	 * An anonymous request is decided by the wp-config.php path where the
	 * site has the snippet, and by the mu-plugin where it does not. A request
	 * carrying a login cookie, with a role exempt, is deferred to the runner
	 * at `plugins_loaded` -- so the subscriber's request below is decided
	 * there, and has to see the real path too.
	 */
	public function test_direct_files_are_matched_on_their_own_path(): void {
		require_once ABSPATH . 'wp-admin/includes/user.php';

		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_direct_admin',
					'type'     => 'url',
					'label'    => 'End-to-end admin screens',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'record'   => 'no',
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'starts_with',
								'value'    => '/wp-admin/edit.php',
							),
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/xmlrpc.php',
							),
						),
					),
				),
			)
		);

		$this->assertSame( 403, $this->request( '/wp-admin/edit.php' )['status'], 'A rule on an admin screen did not match a direct request for it.' );
		$this->assertSame( 403, $this->request( '/xmlrpc.php' )['status'], 'A rule on xmlrpc.php did not match a direct request for it.' );
		$this->assertNotSame( 403, $this->request( '/wp-login.php' )['status'], 'The rule matched a file it does not name.' );

		Plugin::instance()->settings()->set( 'global.bypass_roles', array( 'editor' ) );

		$subscriber = wp_insert_user(
			array(
				'user_login' => 'bfw-e2e-direct-' . wp_generate_password( 6, false ),
				'user_pass'  => wp_generate_password(),
				'role'       => 'subscriber',
			)
		);

		$this->assertIsInt( $subscriber );

		try {
			$cookie = array( 'Cookie' => LOGGED_IN_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( $subscriber, time() + 600, 'logged_in' ) ) );

			$this->assertSame( 403, $this->request( '/wp-admin/edit.php', $cookie )['status'], 'A logged-in request deferred to the runner did not see the admin screen\'s path.' );
		} finally {
			wp_delete_user( $subscriber );
		}
	}

	/**
	 * A rate limit on `/wp-login.php` counts direct requests for it.
	 */
	public function test_a_login_rate_limit_counts_direct_requests(): void {
		$limit = 3;

		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_login_rate',
					'type'     => 'rate_limit',
					'label'    => 'End-to-end login rate limit',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'record'   => 'no',
					'settings' => array(
						'paths'                => array(
							array(
								'pattern' => '/wp-login.php',
								'limit'   => $limit,
								'window'  => 60,
							),
						),
						'default_limit'        => 60,
						'default_window'       => 60,
						'limit_unlisted_paths' => false,
						'status_code'          => 429,
						'storage'              => array(
							'backend' => 'file',
							'file'    => 'private://e2e-ratelimit.data',
						),
					),
				),
			)
		);

		$statuses = array();

		for ( $i = 0; $i <= $limit; $i++ ) {
			$statuses[] = $this->request( '/wp-login.php' )['status'];
		}

		$this->assertNotContains( 429, array_slice( $statuses, 0, $limit ), 'A login within the allowance was refused: ' . implode( ', ', $statuses ) );
		$this->assertSame( 429, $statuses[ $limit ], 'Direct requests for wp-login.php were never counted: ' . implode( ', ', $statuses ) );
	}

	/**
	 * Every spelling of wp-login.php the web server runs it for is counted and refused.
	 *
	 * The web server decodes and normalises the URL before it chooses a file,
	 * so `/./wp-login.php`, `/%77p-login.php`, `//wp-login.php` and
	 * `/x/../wp-login.php` all run wp-login.php. The request rewrite this
	 * plugin used before read the path out of the raw URL, so each reached the
	 * rules as itself, uncounted and unrefused. The compiled
	 * `path_source: script_name` reads the file that ran. Sent over a raw
	 * socket, because an HTTP client may tidy the path first.
	 */
	public function test_alternate_spellings_of_the_login_page_are_caught(): void {
		$spellings = array( '/wp-login.php', '/./wp-login.php', '/%77p-login.php', '//wp-login.php', '/x/../wp-login.php', '/wp-login.php' );

		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_spelling_rate',
					'type'     => 'rate_limit',
					'label'    => 'End-to-end spelling rate limit',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
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
							'file'    => 'private://e2e-ratelimit.data',
						),
					),
				),
			)
		);

		$statuses = array();

		foreach ( $spellings as $index => $spelling ) {
			$statuses[ $index . ' ' . $spelling ] = $this->raw_request( $spelling );
		}

		$this->assertNotContains( 429, array_slice( array_values( $statuses ), 0, 5 ), 'A login within the allowance was refused: ' . wp_json_encode( $statuses ) );
		$this->assertSame( 429, array_values( $statuses )[5], 'The spellings were not counted against the /wp-login.php limit: ' . wp_json_encode( $statuses ) );

		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_spelling_block',
					'type'     => 'url',
					'label'    => 'End-to-end spelling block',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'record'   => 'no',
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/wp-login.php',
							),
						),
					),
				),
			)
		);

		foreach ( array_unique( $spellings ) as $spelling ) {
			$this->assertSame( 403, $this->raw_request( $spelling ), $spelling . ' ran wp-login.php and got past a block on /wp-login.php.' );
		}
	}

	/**
	 * Every spelling of a REST API route the web server routes to index.php is refused (#51).
	 *
	 * The server normalises the URL before routing it, and WordPress trims
	 * every leading slash, so each of these is the REST API to WordPress. The
	 * library read a routed request's path from the raw request URI until
	 * kanopi/firewall 2.35.0, which normalises it: each spelling reached the
	 * rules as itself and got past `path starts with /wp-json/`. Sent over a
	 * raw socket, because an HTTP client may tidy the path first.
	 */
	public function test_routed_spellings_of_a_rest_route_are_caught(): void {
		$this->given_rules(
			array(
				array(
					'id'       => 'e2e_routed_spelling_block',
					'type'     => 'url',
					'label'    => 'End-to-end routed spelling block',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'record'   => 'no',
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'starts_with',
								'value'    => '/wp-json/',
							),
						),
					),
				),
			)
		);

		foreach ( array( '/wp-json/wp/v2/users', '//wp-json/wp/v2/users', '/./wp-json/wp/v2/users', '/%77p-json/wp/v2/users', '/wp-json;x/wp/v2/users' ) as $spelling ) {
			$this->assertSame( 403, $this->raw_request( $spelling ), $spelling . ' reached the REST API and got past a block on /wp-json/.' );
		}

		$this->assertNotSame( 403, $this->raw_request( '/' ), 'The rule refuses everything, so this test proves nothing.' );
	}

	/**
	 * Decisions are announced as `basic_firewall_decision`, over real HTTP (#3).
	 *
	 * DecisionEventsTest drives the dispatcher in-process; this is the path a
	 * site's own listener is on. A test mu-plugin records each announcement
	 * (fixtures/decision-recorder.php), and what is expected follows the
	 * README's "When they arrive": a request let through is announced at
	 * `plugins_loaded` on either path; a refusal on the mu-plugin path is
	 * announced at shutdown; a refusal on the wp-config.php path exits before
	 * WordPress loads and is never announced. Log mode lets the request
	 * through, so its `blocked` is announced on either path, not enforced.
	 */
	public function test_decisions_are_announced_to_an_mu_plugin_listener(): void {
		$recorder = WPMU_PLUGIN_DIR . '/0-bfw-e2e-decision-recorder.php';

		if ( ! wp_mkdir_p( WPMU_PLUGIN_DIR ) || ! copy( __DIR__ . '/fixtures/decision-recorder.php', $recorder ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions -- installing a test fixture.
			$this->fail( 'Could not install the decision recorder in ' . WPMU_PLUGIN_DIR . '.' );
		}

		try {
			$rules = array(
				array(
					'id'       => 'e2e_decision_block',
					'type'     => 'url',
					'label'    => 'End-to-end decision block',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 0,
					'record'   => 'no',
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/bfw-e2e-decision-blocked',
							),
						),
					),
				),
				array(
					'id'                 => 'e2e_decision_challenge',
					'type'               => 'url',
					'label'              => 'End-to-end decision challenge',
					'enabled'            => true,
					'response'           => 'challenge',
					'weight'             => 1,
					'expiration'         => 600,
					'challenge_provider' => 'math',
					'settings'           => array(
						'match_type' => 'any',
						'conditions' => array(
							array(
								'variable' => 'path',
								'operator' => 'equals',
								'value'    => '/bfw-e2e-decision-challenge',
							),
						),
					),
				),
			);

			$this->given_rules( $rules );

			// Allowed first, before anything could have put this client on a list.
			$allowed = $this->recorded_request( '/' );

			$this->assertSame( 200, $allowed['status'] );
			$this->assertTrue( $allowed['seen'], 'The request never reached WordPress, so the recorder heard nothing.' );
			$this->assertContains( 'allowed', $allowed['types'], 'An allowed request was not announced: ' . wp_json_encode( $allowed['events'] ) );
			$this->assertSame( array( 'plugins_loaded' ), array_values( array_unique( array_column( $allowed['events'], 'when' ) ) ), 'A request let through was not announced at plugins_loaded.' );

			$early = $allowed['early'];

			$blocked    = $this->recorded_request( '/bfw-e2e-decision-blocked' );
			$challenged = $this->recorded_request( '/bfw-e2e-decision-challenge' );

			$this->assertSame( 403, $blocked['status'], 'The block rule did not refuse the request, so there is no refusal to announce.' );
			$this->assertStringContainsString( 'Verification required', $challenged['body'], 'The challenge rule did not challenge the request.' );

			if ( $early ) {
				// The wp-config.php path: refusals end the request before WordPress.
				$this->assertFalse( $blocked['seen'], 'A refusal on the wp-config.php path reached WordPress.' );
				$this->assertSame( array(), $blocked['types'], 'A refusal on the wp-config.php path was announced, which the README says cannot happen.' );
				$this->assertSame( array(), $challenged['types'] );
			} else {
				$this->assertSame( array( 'blocked' ), $blocked['types'], 'A refusal was not announced as `blocked`: ' . wp_json_encode( $blocked['events'] ) );
				$this->assertTrue( $blocked['events'][0]['enforced'], 'A refusal in Block mode was announced as not enforced.' );
				$this->assertSame( '/bfw-e2e-decision-blocked', $blocked['events'][0]['path'] );
				$this->assertSame( 'shutdown', $blocked['events'][0]['when'], 'A refusal ends the request before plugins_loaded, so it can only be announced at shutdown.' );

				$this->assertSame( array( 'challenged' ), $challenged['types'], 'A challenge was not announced as `challenged`: ' . wp_json_encode( $challenged['events'] ) );
				$this->assertSame( 'shutdown', $challenged['events'][0]['when'] );
			}

			// Log mode: the rule matches, nothing is refused, and it is said so.
			$this->given_rules( $rules, 'log' );

			$logged = $this->recorded_request( '/bfw-e2e-decision-blocked' );

			$this->assertNotSame( 403, $logged['status'], 'Log mode refused the request.' );
			$this->assertContains( 'blocked', $logged['types'], 'A match in log mode was not announced: ' . wp_json_encode( $logged['events'] ) );

			foreach ( $logged['events'] as $event ) {
				if ( 'blocked' === $event['type'] ) {
					$this->assertFalse( $event['enforced'], 'A match in log mode was announced as enforced.' );
				}
			}
		} finally {
			wp_delete_file( $recorder );
		}
	}

	/**
	 * Make a request the decision recorder writes down, and read what it wrote.
	 *
	 * @param string $path Path to request.
	 *
	 * @return array{status: int, body: string, seen: bool, early: bool, events: list<array<string, mixed>>, types: list<string>}
	 */
	private function recorded_request( string $path ): array {
		$token = bin2hex( random_bytes( 8 ) );
		$log   = WP_CONTENT_DIR . '/bfw-e2e-decisions-' . $token . '.jsonl';

		$response = $this->request( $path, array( 'X-Bfw-E2E-Decisions' => $token ) );

		$lines = is_readable( $log ) ? (array) file( $log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) : array();

		wp_delete_file( $log );

		$seen   = false;
		$early  = false;
		$events = array();

		foreach ( $lines as $line ) {
			$entry = json_decode( (string) $line, true );

			if ( ! is_array( $entry ) ) {
				continue;
			}

			if ( ! empty( $entry['seen'] ) ) {
				$seen  = true;
				$early = ! empty( $entry['early'] );
				continue;
			}

			$events[] = $entry;
		}

		return array(
			'status' => $response['status'],
			'body'   => $response['body'],
			'seen'   => $seen,
			'early'  => $early,
			'events' => $events,
			'types'  => array_values( array_map( 'strval', array_column( $events, 'type' ) ) ),
		);
	}

	/**
	 * Make a request with the path sent exactly as given, and return the status.
	 *
	 * @param string $path Request target, sent verbatim.
	 */
	private function raw_request( string $path ): int {
		$parts  = wp_parse_url( $this->base );
		$secure = 'https' === ( $parts['scheme'] ?? 'http' );
		$host   = (string) ( $parts['host'] ?? '127.0.0.1' );
		$port   = (int) ( $parts['port'] ?? ( $secure ? 443 : 80 ) );

		// The port too, when the URL names one: a multisite network answers
		// only the domain it was installed on, `127.0.0.1:8080` in CI, and
		// redirects anything else before the firewall has loaded.
		$authority = isset( $parts['port'] ) ? $host . ':' . $port : $host;

		$context = stream_context_create(
			array(
				'ssl' => array(
					'verify_peer'      => false,
					'verify_peer_name' => false,
				),
			)
		);

		// phpcs:disable WordPress.WP.AlternativeFunctions -- a raw socket, so no client normalises the path.
		$socket = stream_socket_client( ( $secure ? 'ssl://' : 'tcp://' ) . $host . ':' . $port, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context );

		if ( false === $socket ) {
			$this->fail( 'Could not connect to the site: ' . $errstr );
		}

		stream_set_timeout( $socket, 15 );
		fwrite( $socket, 'GET ' . $path . " HTTP/1.0\r\nHost: " . $authority . "\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15\r\nConnection: close\r\n\r\n" );

		$status = (string) fgets( $socket );
		fclose( $socket );
		// phpcs:enable WordPress.WP.AlternativeFunctions

		return 1 === preg_match( '#^HTTP/\S+ (\d{3})#', $status, $match ) ? (int) $match[1] : 0;
	}
}
