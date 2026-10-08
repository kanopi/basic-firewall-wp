<?php
/**
 * Who makes the DNS lookups behind crawler verification.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Support\Reverse_Dns;
use Kanopi\BasicFirewall\Support\Validator;
use Kanopi\Firewall\Utility\ReverseDns\ReverseDnsSettings;
use PHPUnit\Framework\TestCase;

/**
 * Nothing a site sets here can stop the library starting, and nothing is sent anywhere unless chosen.
 *
 * The library refuses to start on a `global.reverse_dns` it cannot use, and
 * this plugin fails open when it refuses. And naming a provider is the moment
 * a site starts sending visitors' addresses to it, so an unset setting has to
 * compile to nothing at all.
 *
 * @covers \Kanopi\BasicFirewall\Support\Reverse_Dns
 * @covers \Kanopi\BasicFirewall\Support\Validator
 */
final class ReverseDnsTest extends TestCase {

	/**
	 * Unset is PHP's own lookups, and compiles to nothing.
	 */
	public function test_nothing_set_compiles_nothing(): void {
		$this->assertSame( array(), Reverse_Dns::compile( array() ) );
		$this->assertSame(
			array(),
			Reverse_Dns::compile(
				array(
					'provider'   => '',
					'timeout_ms' => Reverse_Dns::DEFAULT_TIMEOUT_MS,
				)
			)
		);
	}

	/**
	 * A provider is written, and a time limit only when it is not the library's default.
	 */
	public function test_a_provider_and_a_limit_compile_as_the_library_reads_them(): void {
		$this->assertSame( array( 'provider' => 'cloudflare' ), Reverse_Dns::compile( array( 'provider' => ' cloudflare ' ) ) );

		$compiled = Reverse_Dns::compile(
			array(
				'provider'   => 'google',
				'timeout_ms' => 500,
			)
		);

		$this->assertSame(
			array(
				'provider'   => 'google',
				'timeout_ms' => 500,
			),
			$compiled
		);
		$this->assertSame( array(), ReverseDnsSettings::problems( array( 'reverse_dns' => $compiled ) ) );
	}

	/**
	 * Every built-in provider is offered, after the empty choice.
	 */
	public function test_every_built_in_provider_is_a_choice(): void {
		$this->assertContains( 'cloudflare', Reverse_Dns::providers() );
		$this->assertContains( 'google', Reverse_Dns::providers() );
	}

	/**
	 * The validator refuses a provider the library does not know, in its words, and stores nothing.
	 */
	public function test_the_validator_refuses_an_unknown_provider(): void {
		$validator = new Validator();
		$result    = $validator->validate( array( 'global' => array( 'reverse_dns' => array( 'provider' => 'cloudfare' ) ) ) );

		$this->assertSame( '', $result['global']['reverse_dns']['provider'] );
		$this->assertSame( array( 'global.reverse_dns.provider' ), array_column( $validator->errors(), 'path' ) );
		$this->assertStringContainsString( 'cloudflare', (string) Reverse_Dns::provider_problem( 'cloudfare' ) );
	}

	/**
	 * A built-in provider is accepted wherever curl is loaded.
	 */
	public function test_the_validator_accepts_a_built_in_provider(): void {
		if ( ! function_exists( 'curl_init' ) ) {
			$this->markTestSkipped( 'DNS over HTTPS needs the curl extension.' );
		}

		$validator = new Validator();
		$result    = $validator->validate(
			array(
				'global' => array(
					'reverse_dns' => array(
						'provider'   => 'cloudflare',
						'timeout_ms' => '450',
					),
				),
			)
		);

		$this->assertSame( array(), $validator->errors() );
		$this->assertSame( 'cloudflare', $result['global']['reverse_dns']['provider'] );
		$this->assertSame( 450, $result['global']['reverse_dns']['timeout_ms'] );
	}

	/**
	 * A time limit outside what the library accepts is refused, and the default kept.
	 */
	public function test_a_time_limit_out_of_range_is_refused(): void {
		foreach ( array( 0, Reverse_Dns::max_timeout_ms() + 1 ) as $timeout ) {
			$validator = new Validator();
			$result    = $validator->validate( array( 'global' => array( 'reverse_dns' => array( 'timeout_ms' => $timeout ) ) ) );

			$this->assertSame( Reverse_Dns::DEFAULT_TIMEOUT_MS, $result['global']['reverse_dns']['timeout_ms'] );
			$this->assertSame( array( 'global.reverse_dns.timeout_ms' ), array_column( $validator->errors(), 'path' ) );
		}
	}

	/**
	 * The schema's bound is the library's.
	 */
	public function test_the_schema_bound_is_the_library_bound(): void {
		$validator = new Validator();
		$result    = $validator->validate( array( 'global' => array( 'reverse_dns' => array( 'timeout_ms' => Reverse_Dns::max_timeout_ms() ) ) ) );

		$this->assertSame( array(), $validator->errors() );
		$this->assertSame( Reverse_Dns::max_timeout_ms(), $result['global']['reverse_dns']['timeout_ms'] );
	}
}
