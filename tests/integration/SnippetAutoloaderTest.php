<?php
/**
 * The autoloader line in the snippet the status screens print.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Plugin;

/**
 * The printed snippet names an autoloader only when the bootstrap needs telling.
 *
 * Which vendor-dir layouts need the line is pinned in AutoloaderLocatorTest.
 * This is the other half: that the snippet on the screens is built from the
 * library this site is actually running, and that a site the bootstrap can
 * already serve is not handed a line it does not need.
 *
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 * @covers \Kanopi\BasicFirewall\Support\Autoloader_Locator
 */
final class SnippetAutoloaderTest extends Settings_Snapshot {

	/**
	 * How Library_Loader resolved the library before a test changed it.
	 *
	 * @var string|null
	 */
	private ?string $mode;

	/**
	 * Remember the resolved mode.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->mode = Library_Loader::mode();
	}

	/**
	 * Put it back.
	 */
	protected function tearDown(): void {
		$this->set_mode( $this->mode );

		parent::tearDown();
	}

	/**
	 * The library from the plugin's own vendor/ is found first, with no line.
	 */
	public function test_a_bundled_library_gets_no_autoloader_line(): void {
		$snippet = Site_Health::bootstrap_snippet();

		$this->assertStringContainsString( "'private_path' => '" . Plugin::instance()->paths()->base() . "'", $snippet );
		$this->assertStringNotContainsString( "'autoloader'", $snippet );
	}

	/**
	 * A site-composer install is read off where the library really came from.
	 *
	 * This working copy runs the library from the plugin's own vendor/, so
	 * even reported as a site-level install, the tree the class was declared
	 * in is one the bootstrap tries first -- and the line stays out. The
	 * decision is made from the class file, not from the mode alone.
	 */
	public function test_a_site_install_is_judged_by_the_class_file(): void {
		$this->set_mode( 'site-composer' );

		$this->assertStringNotContainsString( "'autoloader'", Site_Health::bootstrap_snippet() );
	}

	/**
	 * Set Library_Loader's resolved mode.
	 *
	 * @param string|null $mode The mode.
	 */
	private function set_mode( ?string $mode ): void {
		$property = new \ReflectionProperty( Library_Loader::class, 'mode' );
		$property->setAccessible( true );
		$property->setValue( null, $mode );
	}
}
