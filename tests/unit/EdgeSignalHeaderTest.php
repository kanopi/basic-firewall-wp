<?php
/**
 * Tests for the header names a custom CDN is mapped with.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\RuleType\Types\Edge_Signal;
use PHPUnit\Framework\TestCase;

/**
 * What a "signal: Header-Name" line is read as.
 *
 * The library refuses to start on a mapping naming a signal it does not know,
 * and a firewall that cannot start fails open on every rule, not just this one.
 * So a line is either a signal the library reads and a plausible header, or it
 * is nothing.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Edge_Signal
 */
final class EdgeSignalHeaderTest extends TestCase {

	/**
	 * A signal and a header are read, the signal lower-cased.
	 */
	public function test_a_signal_and_header_are_read(): void {
		$this->assertSame( array( 'bot_score', 'X-Edge-Bot-Score' ), Edge_Signal::header_pair( 'bot_score: X-Edge-Bot-Score' ) );
		$this->assertSame( array( 'ja3', 'X-Fingerprint' ), Edge_Signal::header_pair( '  JA3 :X-Fingerprint  ' ) );
	}

	/**
	 * Lines that are not a mapping the library would accept.
	 *
	 * @return array<string, array{string}>
	 */
	public static function unusable(): array {
		return array(
			'an unknown signal'     => array( 'threat_level: X-Threat' ),
			'no header'             => array( 'bot_score:' ),
			'no colon'              => array( 'bot_score X-Score' ),
			'a header with a space' => array( 'ja4: X Ja4' ),
			'a header with a colon' => array( 'ja4: X-Ja4: extra' ),
			'nothing but a header'  => array( ': X-Score' ),
		);
	}

	/**
	 * Anything else is refused.
	 *
	 * @dataProvider unusable
	 *
	 * @param string $line The line.
	 */
	public function test_anything_else_is_refused( string $line ): void {
		$this->assertNull( Edge_Signal::header_pair( $line ) );
	}

	/**
	 * The compiled map keeps what is usable, keyed by signal.
	 */
	public function test_the_map_keeps_what_is_usable(): void {
		$this->assertSame(
			array(
				'ja3'       => 'X-Fingerprint',
				'bot_score' => 'X-Score',
			),
			Edge_Signal::header_map(
				array( 'custom_headers' => "ja3: X-Fingerprint\nthreat_level: X-Threat\nbot_score: X-Score" )
			)
		);
	}
}
