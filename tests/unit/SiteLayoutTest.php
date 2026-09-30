<?php
/**
 * Where the front controller and WordPress's own files are served.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Support\Site_Layout;
use PHPUnit\Framework\TestCase;

/**
 * The compiled `base_path`, and the prefix WordPress's own files carry, per layout.
 *
 * @covers \Kanopi\BasicFirewall\Support\Site_Layout
 */
final class SiteLayoutTest extends TestCase {

	/**
	 * Each layout's base path and core path.
	 *
	 * @dataProvider layouts
	 *
	 * @param array{home: string, siteurl: string, network_path?: string|null, network_siteurl?: string|null} $addresses Stored addresses.
	 * @param string                                                                                          $base      Expected base path.
	 * @param string                                                                                          $core      Expected core path.
	 * @param string                                                                                          $prefix    Expected core prefix.
	 */
	public function test_each_layout( array $addresses, string $base, string $core, string $prefix ): void {
		$layout = Site_Layout::derive( $addresses );

		$this->assertSame( $base, $layout['base_path'], 'base_path' );
		$this->assertSame( $core, $layout['core_path'], 'core_path' );
		$this->assertSame( $prefix, Site_Layout::relative( $layout['core_path'], $layout['base_path'] ), 'core prefix' );
	}

	/**
	 * The layouts WordPress supports.
	 *
	 * @return array<string, array{0: array<string, string>, 1: string, 2: string, 3: string}>
	 */
	public static function layouts(): array {
		return array(
			'root'                               => array(
				array(
					'home'    => 'https://example.com',
					'siteurl' => 'https://example.com',
				),
				'',
				'',
				'',
			),
			'root, trailing slashes'             => array(
				array(
					'home'    => 'https://example.com/',
					'siteurl' => 'https://example.com/',
				),
				'',
				'',
				'',
			),
			'subdirectory'                       => array(
				array(
					'home'    => 'https://example.com/blog',
					'siteurl' => 'https://example.com/blog/',
				),
				'/blog',
				'/blog',
				'',
			),
			'own directory'                      => array(
				array(
					'home'    => 'https://example.com',
					'siteurl' => 'https://example.com/wp',
				),
				'',
				'/wp',
				'/wp',
			),
			'own directory in a subdirectory'    => array(
				array(
					'home'    => 'https://example.com/blog',
					'siteurl' => 'https://example.com/blog/wp',
				),
				'/blog',
				'/blog/wp',
				'/wp',
			),
			'network site in a subdirectory'     => array(
				array(
					'home'            => 'https://example.com/site2',
					'siteurl'         => 'https://example.com/site2',
					'network_path'    => '/',
					'network_siteurl' => 'https://example.com',
				),
				'',
				'',
				'',
			),
			'network under a path'               => array(
				array(
					'home'            => 'https://example.com/net/site2',
					'siteurl'         => 'https://example.com/net/site2',
					'network_path'    => '/net/',
					'network_siteurl' => 'https://example.com/net',
				),
				'/net',
				'/net',
				'',
			),
			'network, core in its own directory' => array(
				array(
					'home'            => 'https://example.com/site2',
					'siteurl'         => 'https://example.com/site2/wp',
					'network_path'    => '/',
					'network_siteurl' => 'https://example.com/wp',
				),
				'',
				'/wp',
				'/wp',
			),
		);
	}

	/**
	 * A path is relative to the base only at a segment boundary.
	 */
	public function test_relative_needs_a_segment_boundary(): void {
		$this->assertSame( '/blogroll', Site_Layout::relative( '/blogroll', '/blog' ) );
		$this->assertSame( '/wp', Site_Layout::relative( '/blog/wp', '/blog' ) );
		$this->assertSame( '', Site_Layout::relative( '/blog', '/blog' ) );
		$this->assertSame( '/wp', Site_Layout::relative( '/wp', '' ) );
	}
}
