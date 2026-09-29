<?php
/**
 * The autoloader line in the wp-config.php snippet.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Support\Autoloader_Locator;
use PHPUnit\Framework\TestCase;

/**
 * The snippet names a site's autoloader only when the bootstrap could not find it.
 *
 * The paths here do not exist, so nothing is resolved on disk and each case
 * is only the rule it states -- except the Composer 1 fallback, which reads
 * this plugin's own vendor tree, because walking a directory is the rule.
 *
 * @covers \Kanopi\BasicFirewall\Support\Autoloader_Locator
 */
final class AutoloaderLocatorTest extends TestCase {

	private const ABSPATH = '/srv/site/web/';

	private const PLUGIN = '/srv/site/web/wp-content/plugins/basic-firewall/';

	/**
	 * A vendor-dir under mu-plugins -- the case in the issue -- is named, relative to ABSPATH.
	 */
	public function test_a_custom_vendor_dir_under_abspath_is_named_relative_to_it(): void {
		$vendor = '/srv/site/web/wp-content/mu-plugins/vendor';

		$this->assertSame(
			"ABSPATH . 'wp-content/mu-plugins/vendor/autoload.php'",
			Autoloader_Locator::snippet_expression(
				'site-composer',
				$vendor . '/kanopi/firewall/src/Firewall.php',
				array( '/srv/site/web/wp-content/plugins/other/vendor', $vendor ),
				self::ABSPATH,
				self::PLUGIN
			)
		);
	}

	/**
	 * Outside ABSPATH there is nothing to be relative to, so the path is absolute.
	 */
	public function test_a_custom_vendor_dir_outside_abspath_is_named_absolutely(): void {
		$this->assertSame(
			"'/opt/composer/lib/autoload.php'",
			Autoloader_Locator::snippet_expression(
				'site-composer',
				'/opt/composer/lib/kanopi/firewall/src/Firewall.php',
				array( '/opt/composer/lib' ),
				self::ABSPATH,
				self::PLUGIN
			)
		);
	}

	/**
	 * A vendor directory beside the WordPress root is found without being named.
	 */
	public function test_the_guessed_site_location_needs_no_line(): void {
		$this->assertNull(
			Autoloader_Locator::snippet_expression(
				'site-composer',
				'/srv/site/vendor/kanopi/firewall/src/Firewall.php',
				array( '/srv/site/vendor' ),
				self::ABSPATH,
				self::PLUGIN
			)
		);
	}

	/**
	 * A release zip or a plugin-local install is the plugin's own vendor/, found first.
	 *
	 * @dataProvider bundled_modes
	 *
	 * @param string $mode How Library_Loader resolved the library.
	 */
	public function test_a_bundled_library_needs_no_line( string $mode ): void {
		$this->assertNull(
			Autoloader_Locator::snippet_expression(
				$mode,
				'/srv/elsewhere/vendor/kanopi/firewall/src/Firewall.php',
				array( '/srv/elsewhere/vendor' ),
				self::ABSPATH,
				self::PLUGIN
			)
		);
	}

	/**
	 * Every mode but `site-composer`.
	 *
	 * @return array<string, array{string}>
	 */
	public static function bundled_modes(): array {
		return array(
			'release zip'          => array( 'bundled-scoped' ),
			'plugin-local install' => array( 'bundled-unscoped' ),
			'library missing'      => array( 'missing' ),
			'unknown'              => array( 'unknown' ),
		);
	}

	/**
	 * Nothing to go on is no line, rather than a guess.
	 */
	public function test_an_unknown_class_file_needs_no_line(): void {
		$this->assertNull( Autoloader_Locator::snippet_expression( 'site-composer', null, array(), self::ABSPATH, self::PLUGIN ) );
		$this->assertNull( Autoloader_Locator::snippet_expression( 'site-composer', '/nowhere/Firewall.php', array( '/srv/site/vendor' ), self::ABSPATH, self::PLUGIN ) );
	}

	/**
	 * The deepest registered vendor directory holding the file wins.
	 *
	 * A package can carry a vendor tree of its own inside the site's; the
	 * library found there came from that tree's autoloader, not the site's.
	 */
	public function test_the_deepest_vendor_dir_wins(): void {
		$this->assertSame(
			'/srv/site/vendor/acme/tool/vendor/autoload.php',
			Autoloader_Locator::autoloader_for(
				'/srv/site/vendor/acme/tool/vendor/kanopi/firewall/src/Firewall.php',
				array( '/srv/site/vendor', '/srv/site/vendor/acme/tool/vendor' )
			)
		);

		// A sibling whose name merely starts the same is not a parent.
		$this->assertNull( Autoloader_Locator::autoloader_for( '/srv/site/vendor-old/x.php', array( '/srv/site/vendor' ) ) );
	}

	/**
	 * Without Composer 2's loader list, the vendor directory is found by its layout.
	 */
	public function test_without_registered_loaders_the_tree_is_walked(): void {
		$vendor = dirname( __DIR__, 2 ) . '/vendor';
		$class  = ( new \ReflectionClass( \PHPUnit\Framework\TestCase::class ) )->getFileName();

		$this->assertIsString( $class );
		$this->assertSame( realpath( $vendor ) . '/autoload.php', Autoloader_Locator::autoloader_for( $class, array() ) );
	}

	/**
	 * A path is quoted safely for wp-config.php.
	 */
	public function test_the_expression_is_a_safe_literal(): void {
		$this->assertSame( "'/opt/it\\'s/autoload.php'", Autoloader_Locator::expression( "/opt/it's/autoload.php", self::ABSPATH ) );
		$this->assertSame( "ABSPATH . 'lib/autoload.php'", Autoloader_Locator::expression( '/srv/site/web/lib/autoload.php', '/srv/site/web' ) );
	}
}
