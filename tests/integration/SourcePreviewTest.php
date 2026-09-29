<?php
/**
 * What `wp basic-firewall refresh-sources --dry-run` reports.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use Kanopi\BasicFirewall\Sources\Refresher;
use Kanopi\Firewall\Source\SourceCache;
use Kanopi\Firewall\Source\SourceDefinition;

/**
 * The preview reports each list as the library reads it, and the cache as the request path sees it.
 *
 * It used to read `onError` out of the stored declaration -- a key nothing
 * writes, the declaration being snake_case -- so every list reported
 * `last_known_good` whatever its policy was, and it showed nothing of the
 * cache its help text promised.
 *
 * @covers \Kanopi\BasicFirewall\Sources\Refresher
 */
final class SourcePreviewTest extends Settings_Snapshot {

	/**
	 * A credential typed into a list's URL, which must not reach a terminal.
	 */
	private const TOKEN = 'PREVIEW-TOKEN-4d1f';

	/**
	 * Definitions whose cache this test wrote, forgotten afterwards.
	 *
	 * @var list<SourceDefinition>
	 */
	private array $written = array();

	/**
	 * Forget anything this test cached.
	 */
	protected function tearDown(): void {
		foreach ( $this->written as $definition ) {
			( new SourceCache() )->forget( $definition );
		}

		parent::tearDown();
	}

	/**
	 * The error policy is the declared one, and the credential in the URL is masked.
	 */
	public function test_it_reports_the_declared_policy_and_masks_the_url(): void {
		$this->given_list( array( 'on_error' => 'fail_open' ) );

		$row = $this->only_row();

		$this->assertSame( 'fail_open', $row['on_error'], 'The declared error policy was not the one reported.' );
		$this->assertSame( '86400', $row['ttl'] );
		$this->assertStringNotContainsString( self::TOKEN, $row['upstream'], 'The credential in the URL was printed.' );
		$this->assertStringContainsString( 'feeds.example.test/preview.txt', $row['upstream'] );
	}

	/**
	 * A remote list nothing has fetched says so, and says what it costs.
	 */
	public function test_an_unfetched_list_reports_an_empty_cache(): void {
		$this->given_list();

		$row = $this->only_row();

		$this->assertSame( 'no', $row['cached'] );
		$this->assertSame( '', $row['entries'] );
		$this->assertStringStartsWith( 'not cached', $row['state'] );
		$this->assertStringContainsString( 'contributes nothing', $row['state'] );
	}

	/**
	 * A cached copy is reported with its size, age and freshness.
	 */
	public function test_a_cached_list_reports_what_the_cache_holds(): void {
		$this->given_list();

		// The preview defines the cache directory the request path uses, so
		// it is asked first and the copy is written where it will look.
		Refresher::preview();

		$declaration = Refresher::declarations()[0];
		$definition  = SourceDefinition::fromArray( $declaration );

		( new SourceCache() )->store( $definition, array( '192.0.2.1', '192.0.2.2', '192.0.2.3' ), array() );
		$this->written[] = $definition;

		$row = $this->only_row();

		$this->assertSame( 'yes', $row['cached'] );
		$this->assertSame( '3', $row['entries'] );
		$this->assertSame( 'fresh', $row['state'] );
		$this->assertStringEndsWith( 'UTC', $row['fetched'] );
	}

	/**
	 * The one row the fixture produces.
	 *
	 * @return array<string, string>
	 */
	private function only_row(): array {
		$rows = Refresher::preview();

		$this->assertCount( 1, $rows, 'Expected exactly the fixture\'s list.' );

		return $rows[0];
	}

	/**
	 * Store and compile a single IP address rule referencing one list.
	 *
	 * @param array<string, mixed> $source Overrides for the list.
	 */
	private function given_list( array $source = array() ): void {
		$type   = Plugin::instance()->rule_types()->get( 'ip_address' );
		$errors = array();

		$this->assertNotNull( $type );

		$settings = $type->validate_settings(
			array(
				'addresses' => array(),
				'sources'   => array(
					array_merge(
						Ip_Address::source_defaults(),
						array(
							'name'   => 'preview-list',
							'url'    => 'https://reader:' . self::TOKEN . '@feeds.example.test/preview.txt',
							'format' => 'txt',
							'ttl'    => 86400,
						),
						$source
					),
				),
			),
			$errors
		);

		$this->assertSame( array(), $errors );

		Plugin::instance()->settings()->set(
			'rules',
			array(
				array(
					'id'              => 'preview-rule',
					'type'            => 'ip_address',
					'label'           => 'Preview',
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
					'expiration'      => 3600,
					'description'     => '',
					'settings'        => $settings,
				),
			)
		);
		Plugin::instance()->settings()->set( 'presets', array() );

		$this->assertTrue( Plugin::instance()->compiled()->rebuild()['written'] );
	}
}
