<?php
/**
 * A private-path filter added too late is noticed, not silently ignored.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Paths;
use PHPUnit\Framework\TestCase;

/**
 * The directory is settled at muplugins_loaded, once, on purpose.
 *
 * So a filter added from an ordinary plugin or a theme never counts. That is
 * documented, and this is what makes it visible on the site that got it
 * wrong: Site Health names the directory the filter asked for and the one in
 * use.
 *
 * Under the test runner plugins have long since loaded, so "settled before
 * plugins loaded" is arranged on the object rather than by timing.
 *
 * @covers \Kanopi\BasicFirewall\Support\Paths
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class PrivatePathFilterTest extends TestCase {

	/**
	 * The paths service as the plugin had it.
	 *
	 * @var Paths
	 */
	private Paths $original;

	/**
	 * The late filter under test.
	 *
	 * @var callable
	 */
	private $filter;

	/**
	 * Keep the real service.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->original = Plugin::instance()->paths();
		$this->filter   = static fn (): string => '/var/private/bfw-too-late';
	}

	/**
	 * Put it back.
	 */
	protected function tearDown(): void {
		remove_filter( 'basic_firewall_private_path', $this->filter );
		Plugin::instance()->set_service( 'paths', $this->original );

		parent::tearDown();
	}

	/**
	 * A filter added after the directory settled is reported with both paths.
	 */
	public function test_a_late_filter_is_reported(): void {
		$paths = $this->settled_early();

		$this->assertNull( $paths->late_filter(), 'Nothing was added late, and something was reported.' );

		add_filter( 'basic_firewall_private_path', $this->filter );

		$this->assertSame( '/var/private/bfw-too-late', $paths->late_filter() );
		$this->assertNotSame( '/var/private/bfw-too-late', $paths->base(), 'The directory changed partway through the request, so the admin and the runner would disagree about it.' );

		Plugin::instance()->set_service( 'paths', $paths );

		$result = Site_Health::check( 'private_dir' );

		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( '/var/private/bfw-too-late', $result['description'] );
		$this->assertStringContainsString( 'mu-plugins', $result['description'], 'The result does not say where the filter has to go.' );
	}

	/**
	 * Settled after plugins loaded, a filter was consulted, so nothing is late.
	 */
	public function test_nothing_is_late_once_plugins_have_loaded(): void {
		$paths = new Paths();

		add_filter( 'basic_firewall_private_path', $this->filter );

		$this->assertSame( '/var/private/bfw-too-late', $paths->base() );
		$this->assertNull( $paths->late_filter() );
	}

	/**
	 * A paths service whose directory was settled before plugins loaded.
	 */
	private function settled_early(): Paths {
		$paths = new Paths();

		$paths->base();

		$flag = new \ReflectionProperty( Paths::class, 'settled_early' );
		$flag->setAccessible( true );
		$flag->setValue( $paths, true );

		return $paths;
	}
}
