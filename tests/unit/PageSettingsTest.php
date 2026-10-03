<?php
/**
 * The challenge, block and lockdown pages' settings.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Support\Page_Settings;
use Kanopi\BasicFirewall\Support\Validator;
use Kanopi\Firewall\Challenge\ChallengePage;
use Kanopi\Firewall\Page\BlockPage;
use PHPUnit\Framework\TestCase;

/**
 * Nothing compiled here can stop the library starting.
 *
 * The library refuses to start on a page value it cannot use, and this plugin
 * fails open when it refuses: a typo in a colour would switch every rule off.
 * So the validator refuses such a value on save, and the compiler leaves out
 * one that arrived some other way.
 *
 * @covers \Kanopi\BasicFirewall\Support\Page_Settings
 * @covers \Kanopi\BasicFirewall\Support\Validator
 */
final class PageSettingsTest extends TestCase {

	/**
	 * Values the library refuses to start on, by key.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public function unusable(): array {
		return array(
			'lang with a space'            => array( 'lang', 'not a language' ),
			'styles closing the block'     => array( 'styles', '.x{}</STYLE><script>alert(1)</script>' ),
			'protocol-relative stylesheet' => array( 'stylesheet', '//elsewhere.example/x.css' ),
			'http stylesheet'              => array( 'stylesheet', 'http://example.com/x.css' ),
			'javascript stylesheet'        => array( 'stylesheet', 'javascript:alert(1)' ),
		);
	}

	/**
	 * The validator refuses each one, in the library's own words, and stores nothing.
	 *
	 * @dataProvider unusable
	 *
	 * @param string $key   Key under global.pages.
	 * @param string $value Its value.
	 */
	public function test_the_validator_refuses_what_the_library_would( string $key, string $value ): void {
		$validator = new Validator();
		$result    = $validator->validate( array( 'global' => array( 'pages' => array( $key => $value ) ) ) );

		$this->assertSame( '', $result['global']['pages'][ $key ] );
		$this->assertSame( array( 'global.pages.' . $key ), array_column( $validator->errors(), 'path' ) );
		$this->assertSame( ChallengePage::problems( array( $key => $value ) ), array_column( $validator->errors(), 'message' ) );
	}

	/**
	 * And the compiler leaves each one out rather than writing it.
	 *
	 * @dataProvider unusable
	 *
	 * @param string $key   Key under global.pages.
	 * @param string $value Its value.
	 */
	public function test_the_compiler_leaves_out_what_the_library_would_refuse( string $key, string $value ): void {
		$pages = array( $key => $value );

		$this->assertSame( array(), Page_Settings::challenge( array(), $pages ) );
		$this->assertTrue( Page_Settings::refusal( array( 'enabled' => true ), $pages, array( 'title' ) ) );
	}

	/**
	 * Usable values reach every page, and the library accepts what is written.
	 */
	public function test_usable_values_reach_every_page(): void {
		$pages = array(
			'lang'       => ' fr-CA ',
			'styles'     => ':root { --fw-accent: #0b8f5a; }',
			'stylesheet' => 'https://cdn.example.com/firewall.css',
		);

		$challenge = Page_Settings::challenge(
			array(
				'heading' => 'Vérification',
				'button'  => '',
				'unknown' => 'ignored',
			),
			$pages
		);

		$this->assertSame(
			array(
				'heading'    => 'Vérification',
				'lang'       => 'fr-CA',
				'styles'     => ':root { --fw-accent: #0b8f5a; }',
				'stylesheet' => 'https://cdn.example.com/firewall.css',
			),
			$challenge
		);
		$this->assertSame( array(), ChallengePage::problems( $challenge ) );

		$lockdown = Page_Settings::refusal(
			array(
				'enabled' => true,
				'message' => "Back soon.\nReference {{request.id}}",
			),
			$pages,
			array( 'title', 'heading', 'message' )
		);

		$this->assertIsArray( $lockdown );
		$this->assertSame( "Back soon.\nReference {{request.id}}", $lockdown['message'] );
		$this->assertSame( array(), BlockPage::problems( $lockdown ) );
	}

	/**
	 * Off is no page at all; on with nothing set is the built-in page.
	 */
	public function test_a_refusal_page_is_off_unless_switched_on(): void {
		$this->assertNull( Page_Settings::refusal( array( 'title' => 'Set but off' ), array(), array( 'title' ) ) );
		$this->assertTrue( Page_Settings::refusal( array( 'enabled' => true ), array(), array( 'title' ) ) );
	}
}
