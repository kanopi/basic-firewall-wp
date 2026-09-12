<?php
/**
 * End-to-end coverage over real HTTP.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\e2e;

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
	 * @return array{status: int, body: string}
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
			'status' => (int) wp_remote_retrieve_response_code( $response ),
			'body'   => (string) wp_remote_retrieve_body( $response ),
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
}
