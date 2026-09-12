<?php
/**
 * Saves and restores a site's settings around a test.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;
use PHPUnit\Framework\TestCase;

/**
 * Base class that leaves the site exactly as it found it.
 *
 * These tests run against a real site, so a test that wrote a rule set and
 * forgot to put the old one back would silently reconfigure a live firewall.
 * The whole option is snapshotted and restored, including the case where the
 * option did not exist.
 */
abstract class Settings_Snapshot extends TestCase {

	/**
	 * The option as it was before the test.
	 *
	 * @var mixed
	 */
	private $snapshot;

	/**
	 * Take the snapshot.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->snapshot = get_option( Schema::OPTION, null );

		Plugin::instance()->settings()->flush();
	}

	/**
	 * Put everything back.
	 */
	protected function tearDown(): void {
		if ( null === $this->snapshot ) {
			delete_option( Schema::OPTION );
		} else {
			update_option( Schema::OPTION, $this->snapshot, false );
		}

		Plugin::instance()->settings()->flush();

		parent::tearDown();
	}

	/**
	 * Write a settings document for the test to work against.
	 *
	 * @param array<string, mixed> $overrides Values merged over the defaults.
	 *
	 * @return array<string, mixed> The document as stored.
	 */
	protected function given_settings( array $overrides ): array {
		$settings = array_replace_recursive( Schema::defaults(), $overrides );

		Plugin::instance()->settings()->replace( $settings );
		Plugin::instance()->settings()->flush();

		return Plugin::instance()->settings()->all();
	}
}
