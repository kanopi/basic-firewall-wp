<?php
/**
 * What Site Health says a clean compile holds.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;

/**
 * Disabled rules are not counted as compiled, and observing rules are named.
 *
 * Every stored rule was reported as "compiled and being enforced", disabled
 * ones included, though the compiler skips a disabled rule before anything
 * else.
 *
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class CompiledHealthCountTest extends Settings_Snapshot {

	/**
	 * One enforcing, one observing, two switched off.
	 */
	public function test_only_enabled_rules_are_counted_as_compiled(): void {
		Plugin::instance()->settings()->set(
			'rules',
			array(
				$this->rule( 'count-on', true, false ),
				$this->rule( 'count-watching', true, true ),
				$this->rule( 'count-off-1', false, false ),
				$this->rule( 'count-off-2', false, true ),
			)
		);
		Plugin::instance()->settings()->set( 'presets', array() );

		$this->assertTrue( Plugin::instance()->compiled()->rebuild()['written'] );

		$result = Site_Health::check( 'compiled' );

		$this->assertSame( 'good', $result['status'], (string) $result['description'] );
		$this->assertStringContainsString( '2 enabled rule(s) and 0 preset(s) are compiled and being evaluated.', $result['description'] );
		$this->assertStringContainsString( '1 of those rules observe only', $result['description'] );
		$this->assertStringContainsString( '2 disabled rule(s) are not compiled', $result['description'] );
		$this->assertStringNotContainsString( 'being enforced', $result['description'] );
	}

	/**
	 * With nothing disabled or observing, neither is mentioned.
	 */
	public function test_the_extra_sentences_appear_only_when_they_apply(): void {
		Plugin::instance()->settings()->set( 'rules', array( $this->rule( 'count-only', true, false ) ) );
		Plugin::instance()->settings()->set( 'presets', array() );

		$this->assertTrue( Plugin::instance()->compiled()->rebuild()['written'] );

		$description = (string) Site_Health::check( 'compiled' )['description'];

		$this->assertStringContainsString( '1 enabled rule(s)', $description );
		$this->assertStringNotContainsString( 'observe only', $description );
		$this->assertStringNotContainsString( 'disabled', $description );
	}

	/**
	 * A stored IP address rule.
	 *
	 * @param string $id      Identifier.
	 * @param bool   $enabled Whether it is enabled.
	 * @param bool   $observe Whether it only observes.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( string $id, bool $enabled, bool $observe ): array {
		return array(
			'id'              => $id,
			'type'            => 'ip_address',
			'label'           => $id,
			'enabled'         => $enabled,
			'observe'         => $observe,
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
			'settings'        => array( 'addresses' => array( '192.0.2.20' ) ),
		);
	}
}
