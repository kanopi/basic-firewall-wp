<?php
/**
 * Referencing a list rather than copying it.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use PHPUnit\Framework\TestCase;

/**
 * What a referenced list compiles to, and what is refused before it gets there.
 *
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Ip_Address
 */
final class SourceReferenceTest extends TestCase {

	/**
	 * A rule carrying a URL.
	 *
	 * @param array<string, mixed> $settings Settings overrides.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( array $settings = array() ): array {
		return array(
			'id'       => 'uptimerobot-allow',
			'type'     => 'ip_address',
			'response' => 'allow',
			'weight'   => -100,
			'settings' => array_merge(
				array(
					'addresses' => array(),
					'sources'   => array(
						array_merge(
							Ip_Address::source_defaults(),
							array( 'url' => 'https://cdn.uptimerobot.com/api/IPv4andIPv6.txt' )
						),
					),
				),
				$settings
			),
		);
	}

	/**
	 * The URL reaches the compiled file, and the addresses do not.
	 *
	 * The whole point: a published list changes without telling anyone, so a
	 * copy is correct on the day it is pasted and wrong from then on. On an
	 * allow rule, wrong means blocking the monitor that exists to tell you the
	 * site is up.
	 */
	public function test_a_referenced_list_compiles_to_a_source(): void {
		$entry = ( new Ip_Address() )->compile( $this->rule() );

		$this->assertSame( array(), $entry['config'], 'A referenced list must not be expanded into the rule.' );

		$sources = $entry['metadata']['sources'] ?? array();

		$this->assertCount( 1, $sources );
		$this->assertSame( 'https://cdn.uptimerobot.com/api/IPv4andIPv6.txt', $sources[0]['upstream'] );
		$this->assertSame( 86400, $sources[0]['ttl'] );

		/*
		 * `on_error`, not `onError`. The declaration is read with array keys,
		 * so the camelCase constructor name is not an error -- it is silently
		 * ignored and the default applies, turning a deliberate `abort` policy
		 * into `last_known_good` with nothing to show for it.
		 */
		$this->assertArrayHasKey( 'on_error', $sources[0], 'The library reads on_error; onError is ignored in silence.' );
		$this->assertSame( 'last_known_good', $sources[0]['on_error'] );

		$this->assertSame(
			'uptimerobot-allow',
			$sources[0]['name'],
			'A source is named for its rule so a refresh failure says which rule it belongs to.'
		);

		$this->assertSame(
			'cidr',
			$sources[0]['validate'],
			'The library validates cidr as address, block or range -- exactly what this plugin accepts -- so a feed that starts emitting hostnames is rejected at refresh rather than contributing entries that match nothing.'
		);
	}

	/**
	 * Typed-in addresses still work, and still work alongside a reference.
	 */
	public function test_inline_addresses_survive_alongside_a_reference(): void {
		$entry = ( new Ip_Address() )->compile(
			$this->rule( array( 'addresses' => array( '203.0.113.7' ) ) )
		);

		$this->assertSame( array( '203.0.113.7' ), $entry['config'] );
		$this->assertCount( 1, $entry['metadata']['sources'] ?? array() );
	}

	/**
	 * A rule with no reference emits no sources key at all.
	 *
	 * An empty `sources` list is not the same as none: it is a key the library
	 * then has to interpret, for no reason.
	 */
	public function test_no_reference_emits_no_sources_key(): void {
		$entry = ( new Ip_Address() )->compile(
			$this->rule( array( 'sources' => array() ) )
		);

		$this->assertArrayNotHasKey( 'sources', $entry['metadata'] ?? array() );
	}

	/**
	 * Several lists on one rule, each with its own shape.
	 *
	 * The case that made the first version of this inadequate. A rule allowing
	 * "our monitoring and our CDN" is two feeds in two formats, and offering
	 * one URL field meant the second had to go somewhere else or nowhere.
	 */
	public function test_several_lists_compile_independently(): void {
		$entry = ( new Ip_Address() )->compile(
			$this->rule(
				array(
					'sources' => array(
						array_merge(
							Ip_Address::source_defaults(),
							array(
								'name' => 'uptimerobot',
								'url'  => 'https://cdn.uptimerobot.com/api/IPv4andIPv6.txt',
							)
						),
						array_merge(
							Ip_Address::source_defaults(),
							array(
								'name'      => 'aws-cloudfront',
								'url'       => 'https://ip-ranges.amazonaws.com/ip-ranges.json',
								'format'    => 'json',
								'select'    => 'prefixes.*',
								'template'  => '{value[ip_prefix]}',
								'max_delta' => '0.25',
								'advanced'  => array( 'where' => array( 'service@equals:CLOUDFRONT' ) ),
							)
						),
					),
				)
			)
		);

		$sources = $entry['metadata']['sources'];

		$this->assertCount( 2, $sources );
		$this->assertSame( 'uptimerobot', $sources[0]['name'] );
		$this->assertArrayNotHasKey( 'select', $sources[0], 'A plain text list must not be given a select it does not need.' );

		$this->assertSame( 'json', $sources[1]['format'] );
		$this->assertSame( 'prefixes.*', $sources[1]['select'] );
		$this->assertSame( '{value[ip_prefix]}', $sources[1]['template'] );
		$this->assertSame( 0.25, $sources[1]['max_delta'] );
		$this->assertSame( array( 'service@equals:CLOUDFRONT' ), $sources[1]['where'] );
	}

	/**
	 * The advanced block reaches the declaration, and the URL still wins.
	 *
	 * `upstream` becomes a map the moment anything is added to it, and the URL
	 * typed into the visible field has to survive that -- a field somebody can
	 * see must not be silently overridden by a block they have to scroll to.
	 */
	public function test_the_advanced_block_extends_the_upstream(): void {
		$entry = ( new Ip_Address() )->compile(
			$this->rule(
				array(
					'sources' => array(
						array_merge(
							Ip_Address::source_defaults(),
							array(
								'url'      => 'https://feed.example/ips.json',
								'advanced' => array(
									'upstream' => array(
										'url'     => 'https://wrong.example/ignored',
										'auth'    => array(
											'type'  => 'bearer',
											'token' => '%env(FEED_TOKEN)%',
										),
										'timeout' => 10,
									),
								),
							)
						),
					),
				)
			)
		);

		$upstream = $entry['metadata']['sources'][0]['upstream'];

		$this->assertIsArray( $upstream );
		$this->assertSame( 'https://feed.example/ips.json', $upstream['url'] );
		$this->assertSame( 10, $upstream['timeout'] );
		$this->assertSame( 'bearer', $upstream['auth']['type'] );
	}

	/**
	 * A credential on a referenced list is named as a secret.
	 *
	 * A paid feed's token would otherwise travel in an exported configuration
	 * pasted into a ticket, which is the leak this plugin already refuses for
	 * every other credential it holds.
	 */
	public function test_a_list_credential_is_declared_secret(): void {
		$secrets = ( new Ip_Address() )->secret_settings();

		$this->assertContains( 'sources.*.advanced.upstream.auth.token', $secrets );
		$this->assertContains( 'sources.*.advanced.upstream.auth.password', $secrets );
	}

	/**
	 * What may be referenced.
	 *
	 * @dataProvider source_references
	 *
	 * @param string $entry    The reference.
	 * @param bool   $expected Whether it is accepted.
	 * @param string $because  Why.
	 */
	public function test_source_references_are_checked( string $entry, bool $expected, string $because ): void {
		$this->assertSame( $expected, Ip_Address::is_valid_source( $entry ), $because );
	}

	/**
	 * Every shape a reference arrives in.
	 *
	 * @return array<string, array{0: string, 1: bool, 2: string}>
	 */
	public static function source_references(): array {
		return array(
			'https URL'           => array( 'https://cdn.uptimerobot.com/api/IPv4andIPv6.txt', true, 'The ordinary case.' ),
			'http URL'            => array( 'http://example.test/ips.txt', true, 'Permitted; the transport is the administrator\'s choice.' ),
			'a relative filename' => array( 'lists/office.txt', true, 'Resolved inside the private directory, for a list deployed as a file.' ),
			'an absolute path'    => array( '/etc/passwd', false, 'metadata.sources is reachable from an imported document, and a source is read at the web server\'s privilege.' ),
			'a traversing path'   => array( '../../wp-config.php', false, 'Same reason: a relative path must not be able to climb out of the directory it resolves against.' ),
			'a file:// URL'       => array( 'file:///etc/shadow', false, 'A scheme that is not http(s) is an arbitrary local read wearing a URL.' ),
			'an unparseable URL'  => array( 'https://', false, 'Nothing to fetch.' ),
			'an empty reference'  => array( '', false, 'A blank line in the textarea is not a list.' ),
		);
	}
}
