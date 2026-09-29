<?php
/**
 * Credentials in referenced lists, and credentials bound to a host, across an export and import.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Transfer\Exporter;
use Kanopi\BasicFirewall\Transfer\Importer;
use Kanopi\BasicFirewall\Transfer\Secret_Paths;
use Symfony\Component\Yaml\Yaml;

/**
 * What an export leaves out, and what an import is willing to put back.
 *
 * Two defects. A rule type named its list credentials with `*` for the list
 * index -- `sources.*.advanced.upstream.auth.token` -- and the exporter looked
 * that up as a literal key called `*`, so a paid feed's token went out in every
 * export; condition types did not name them at all. And the importer restored
 * a stored password whenever a document left it out, even when the document
 * pointed it at another host.
 *
 * @covers \Kanopi\BasicFirewall\Transfer\Secret_Paths
 * @covers \Kanopi\BasicFirewall\Transfer\Exporter
 * @covers \Kanopi\BasicFirewall\Transfer\Importer
 * @covers \Kanopi\BasicFirewall\RuleType\Has_Sources
 * @covers \Kanopi\BasicFirewall\Support\Schema
 */
final class SourceCredentialTransferTest extends Settings_Snapshot {

	private const FEED_TOKEN = 'SECRET-feed-token-must-never-leak';

	private const FEED_HEADER = 'SECRET-feed-header-must-never-leak';

	private const PATH_TOKEN = 'SECRET-path-feed-token-must-never-leak';

	private const URL_PASSWORD = 'SECRET-url-password-must-never-leak';

	private const URL_KEY = 'SECRET-url-key-must-never-leak';

	private const REDIS_PASSWORD = 'SECRET-redis-password-must-never-leak';

	/**
	 * Every list credential, and every URL credential, is out of the export and named.
	 */
	public function test_an_export_strips_list_credentials_and_names_them(): void {
		$this->given_settings( $this->document() );

		$export = ( new Exporter() )->export();
		$yaml   = ( new Exporter() )->to_yaml();

		foreach ( array( self::FEED_TOKEN, self::FEED_HEADER, self::PATH_TOKEN, self::URL_PASSWORD, self::URL_KEY ) as $secret ) {
			$this->assertStringNotContainsString( $secret, $yaml, 'A list credential reached the exported document.' );
		}

		$addresses = $this->index_of( $export['document'], 'feed-addresses' );
		$paths     = $this->index_of( $export['document'], 'feed-paths' );

		foreach ( array(
			"rules.$addresses.settings.sources.0.advanced.upstream.auth.token",
			"rules.$addresses.settings.sources.0.advanced.upstream.headers",
			"rules.$paths.settings.sources.0.advanced.upstream.auth.token",
			"rules.$addresses.settings.sources.1.url",
		) as $path ) {
			$this->assertContains( $path, $export['redacted'] );
			$this->assertStringContainsString( '#   - ' . $path, $yaml, 'The header must name every path that was removed or altered.' );
		}

		$this->assertSame( array( "rules.$addresses.settings.sources.1.url" ), $export['redacted_urls'] );

		// The URL stays, with the credential replaced, so the rule still says where its list is.
		$url = (string) $export['document']['rules'][ $addresses ]['settings']['sources'][1]['url'];
		$this->assertStringContainsString( 'feeds.example.com/allow.txt', $url );
		$this->assertStringContainsString( '***', $url );
		$this->assertStringContainsString( 'format=txt', $url, 'A parameter that is not a credential was altered.' );

		// And the username of basic auth, the auth type and a header's name are not credentials.
		$this->assertSame( 'bearer', $export['document']['rules'][ $addresses ]['settings']['sources'][0]['advanced']['upstream']['auth']['type'] ?? null );

		// Semantically, too: nothing the parsed export holds at a secret path is live.
		$document = Yaml::parse( $yaml )['basic_firewall']['settings'];

		foreach ( Secret_Paths::in( $document ) as $path ) {
			$value = Secret_Paths::get( $document, $path );

			$this->assertTrue( Secret_Paths::is_empty( $value ) || Secret_Paths::is_token( $value ), sprintf( 'The export carries a live credential at %s.', $path ) );
		}
	}

	/**
	 * Every type that takes a list names its credentials, not only the IP rule.
	 */
	public function test_every_type_with_sources_names_the_list_credentials(): void {
		$checked = 0;

		foreach ( Plugin::instance()->rule_types()->all() as $type ) {
			if ( ! method_exists( $type, 'source_secret_settings' ) ) {
				continue;
			}

			$document = array(
				'rules' => array(
					array(
						'id'       => 'probe',
						'type'     => $type->id(),
						'settings' => array(
							'sources' => array(
								array(
									'url'      => 'https://feeds.example.com/list.txt',
									'advanced' => array(
										'upstream' => array(
											'auth'    => array(
												'type'  => 'bearer',
												'token' => self::FEED_TOKEN,
											),
											'headers' => array( 'X.Api.Key' => self::FEED_HEADER ),
										),
									),
								),
							),
						),
					),
				),
			);

			$redacted = Exporter::redact( $document );

			$this->assertStringNotContainsString( self::FEED_TOKEN, (string) wp_json_encode( $redacted['document'] ), sprintf( 'The %s rule type exports its list token.', $type->id() ) );
			$this->assertStringNotContainsString( self::FEED_HEADER, (string) wp_json_encode( $redacted['document'] ), sprintf( 'The %s rule type exports its list headers.', $type->id() ) );

			++$checked;
		}

		$this->assertGreaterThan( 1, $checked, 'Only one rule type takes a list; the condition types were meant to as well.' );
	}

	/**
	 * A site importing its own export gets every list credential back.
	 */
	public function test_importing_an_export_keeps_list_credentials_for_the_same_urls(): void {
		$this->given_settings( $this->document() );

		$result = ( new Importer() )->import( ( new Exporter() )->to_yaml(), 'replace' );

		$this->assertTrue( $result['ok'], (string) $result['error'] );
		$this->assertSame( array(), $result['summary']['credentials_withheld'] );

		$addresses = $this->stored_rule( 'feed-addresses' )['settings']['sources'];

		$this->assertSame( self::FEED_TOKEN, $addresses[0]['advanced']['upstream']['auth']['token'] ?? null );
		$this->assertSame( array( 'X-Api-Key' => self::FEED_HEADER ), $addresses[0]['advanced']['upstream']['headers'] ?? null );
		$this->assertSame( $this->allow_url(), $addresses[1]['url'], 'A URL exported with *** was not restored from the stored copy.' );

		$this->assertSame( self::PATH_TOKEN, $this->stored_rule( 'feed-paths' )['settings']['sources'][0]['advanced']['upstream']['auth']['token'] ?? null );
	}

	/**
	 * A list moved to another URL does not take this site's token with it.
	 */
	public function test_a_list_pointed_elsewhere_does_not_keep_the_stored_token(): void {
		$this->given_settings( $this->document() );

		$export = ( new Exporter() )->export();
		$index  = $this->index_of( $export['document'], 'feed-addresses' );

		$export['document']['rules'][ $index ]['settings']['sources'][0]['url'] = 'https://attacker.example/list.txt';

		$yaml    = Yaml::dump( array( 'basic_firewall' => array( 'settings' => $export['document'] ) ), 12, 2 );
		$preview = ( new Importer() )->preview( $yaml, 'merge' );

		$this->assertTrue( $preview['ok'] );
		$this->assertNotSame( array(), array_filter( $preview['summary']['credentials_withheld'], static fn ( string $line ): bool => false !== strpos( $line, 'auth.token' ) ), 'The preview did not say the token is not kept.' );

		( new Importer() )->import( $yaml, 'merge' );

		$sources = $this->stored_rule( 'feed-addresses' )['settings']['sources'];

		$this->assertSame( 'https://attacker.example/list.txt', $sources[0]['url'] );
		$this->assertTrue( Secret_Paths::is_empty( $sources[0]['advanced']['upstream']['auth']['token'] ?? null ), 'The stored token was sent to a list at another URL.' );
		$this->assertTrue( Secret_Paths::is_empty( $sources[0]['advanced']['upstream']['headers'] ?? null ), 'The stored headers were sent to a list at another URL.' );

		// The other rule's list did not move, so its token stays.
		$this->assertSame( self::PATH_TOKEN, $this->stored_rule( 'feed-paths' )['settings']['sources'][0]['advanced']['upstream']['auth']['token'] ?? null );
	}

	/**
	 * A Redis password stays with the same Redis, and only with it.
	 */
	public function test_a_redis_password_does_not_follow_a_new_host(): void {
		$this->given_settings( $this->document() );

		$same   = "basic_firewall:\n  settings:\n    storage:\n      redis:\n        host: 10.0.0.5\n        port: '6380'\n";
		$result = ( new Importer() )->import( $same, 'merge' );

		$this->assertSame( array(), $result['summary']['credentials_withheld'] );
		$this->assertSame( self::REDIS_PASSWORD, $this->stored( 'storage.redis.password' ), 'The password was dropped although the Redis it belongs to did not change.' );

		$moved   = "basic_firewall:\n  settings:\n    storage:\n      redis:\n        host: redis.attacker.example\n";
		$preview = ( new Importer() )->preview( $moved, 'merge' );

		$this->assertCount( 1, $preview['summary']['credentials_withheld'] );
		$this->assertStringContainsString( 'storage.redis.password', $preview['summary']['credentials_withheld'][0] );
		$this->assertStringContainsString( 'storage.redis.host', $preview['summary']['credentials_withheld'][0] );

		( new Importer() )->import( $moved, 'merge' );

		$this->assertSame( '', $this->stored( 'storage.redis.password' ), 'The stored Redis password was carried to a new host.' );
		$this->assertSame( 'redis.attacker.example', $this->stored( 'storage.redis.host' ) );
	}

	/**
	 * A document that carries the password itself sets it, wherever it points.
	 */
	public function test_a_password_the_document_carries_is_applied_with_a_new_host(): void {
		$this->given_settings( $this->document() );

		( new Importer() )->import( "basic_firewall:\n  settings:\n    storage:\n      redis:\n        host: redis.new.example\n        password: NEW-password\n", 'merge' );

		$this->assertSame( 'NEW-password', $this->stored( 'storage.redis.password' ) );
	}

	/**
	 * The database password stays with the same server.
	 */
	public function test_a_database_password_does_not_follow_a_new_server(): void {
		$this->given_settings(
			array(
				'storage' => array(
					'database' => array(
						'connection_source' => 'parameters',
						'parameters'        => array(
							'host'     => 'db.internal',
							'user'     => 'firewall',
							'password' => self::REDIS_PASSWORD,
						),
					),
				),
			)
		);

		( new Importer() )->import( "basic_firewall:\n  settings:\n    storage:\n      database:\n        parameters:\n          host: db.attacker.example\n", 'merge' );

		$this->assertSame( '', $this->stored( 'storage.database.parameters.password' ) );
	}

	/**
	 * A rate limit's Redis password stays with the rate limit's Redis.
	 */
	public function test_a_rate_limit_redis_password_does_not_follow_a_new_host(): void {
		$rule = array(
			'id'       => 'login-limit',
			'type'     => 'rate_limit',
			'label'    => 'Login',
			'enabled'  => true,
			'response' => 'block',
			'weight'   => 30,
			'settings' => array(
				'paths'   => array( '/wp-login.php 20 60' ),
				'storage' => array(
					'backend'        => 'redis',
					'redis_host'     => '10.0.0.9',
					'redis_port'     => 6379,
					'redis_password' => self::REDIS_PASSWORD,
				),
			),
		);

		$this->given_settings( array( 'rules' => array( $rule ) ) );

		$export = ( new Exporter() )->export();

		$this->assertStringNotContainsString( self::REDIS_PASSWORD, ( new Exporter() )->to_yaml() );

		( new Importer() )->import( Yaml::dump( array( 'basic_firewall' => array( 'settings' => $export['document'] ) ), 12, 2 ), 'merge' );

		$this->assertSame( self::REDIS_PASSWORD, $this->stored_rule( 'login-limit' )['settings']['storage']['redis_password'], 'The password was dropped although the Redis did not change.' );

		$export['document']['rules'][0]['settings']['storage']['redis_host'] = 'redis.attacker.example';

		( new Importer() )->import( Yaml::dump( array( 'basic_firewall' => array( 'settings' => $export['document'] ) ), 12, 2 ), 'merge' );

		$this->assertSame( '', $this->stored_rule( 'login-limit' )['settings']['storage']['redis_password'], 'The rate limit\'s Redis password was carried to a new host.' );
	}

	/**
	 * A credential follows its rule by identifier, not by position.
	 */
	public function test_a_credential_follows_its_rule_when_the_order_changes(): void {
		$this->given_settings( $this->document() );

		$export = ( new Exporter() )->export();
		$rules  = array_reverse( $export['document']['rules'] );

		( new Importer() )->import( Yaml::dump( array( 'rules' => $rules ), 12, 2 ), 'replace' );

		$this->assertSame( self::FEED_TOKEN, $this->stored_rule( 'feed-addresses' )['settings']['sources'][0]['advanced']['upstream']['auth']['token'] ?? null );
		$this->assertSame( self::PATH_TOKEN, $this->stored_rule( 'feed-paths' )['settings']['sources'][0]['advanced']['upstream']['auth']['token'] ?? null );
	}

	/**
	 * A stored setting.
	 *
	 * @param string $path Dotted path.
	 *
	 * @return mixed
	 */
	private function stored( string $path ) {
		Plugin::instance()->settings()->flush();

		return Plugin::instance()->settings()->get( $path );
	}

	/**
	 * A stored rule by id.
	 *
	 * @param string $id Rule id.
	 *
	 * @return array<string, mixed>
	 */
	private function stored_rule( string $id ): array {
		Plugin::instance()->settings()->flush();

		foreach ( (array) Plugin::instance()->settings()->get( 'rules', array() ) as $rule ) {
			if ( is_array( $rule ) && ( $rule['id'] ?? '' ) === $id ) {
				return $rule;
			}
		}

		$this->fail( "There is no stored rule $id." );
	}

	/**
	 * Where a rule is in a document.
	 *
	 * @param array<string, mixed> $document Settings document.
	 * @param string               $id       Rule id.
	 */
	private function index_of( array $document, string $id ): int {
		foreach ( (array) ( $document['rules'] ?? array() ) as $index => $rule ) {
			if ( is_array( $rule ) && ( $rule['id'] ?? '' ) === $id ) {
				return (int) $index;
			}
		}

		$this->fail( "The document has no rule $id." );
	}

	/**
	 * A list URL with a password and a key in it.
	 */
	private function allow_url(): string {
		return 'https://reader:' . self::URL_PASSWORD . '@feeds.example.com/allow.txt?format=txt&api_key=' . self::URL_KEY;
	}

	/**
	 * Two rules taking lists behind credentials, and a Redis block list with a password.
	 *
	 * @return array<string, mixed>
	 */
	private function document(): array {
		return array(
			'storage' => array(
				'redis' => array(
					'host'     => '10.0.0.5',
					'port'     => 6380,
					'username' => 'firewall',
					'password' => self::REDIS_PASSWORD,
				),
			),
			'rules'   => array(
				array(
					'id'       => 'feed-addresses',
					'type'     => 'ip_address',
					'label'    => 'Feed addresses',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 10,
					'settings' => array(
						'addresses' => array(),
						'sources'   => array(
							array(
								'url'      => 'https://feeds.example.com/bad.txt',
								'advanced' => array(
									'upstream' => array(
										'auth'    => array(
											'type'  => 'bearer',
											'token' => self::FEED_TOKEN,
										),
										'headers' => array( 'X-Api-Key' => self::FEED_HEADER ),
									),
								),
							),
							array( 'url' => $this->allow_url() ),
						),
					),
				),
				array(
					'id'       => 'feed-paths',
					'type'     => 'url',
					'label'    => 'Feed paths',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 20,
					'settings' => array(
						'match_type' => 'any',
						'conditions' => array(),
						'sources'    => array(
							array(
								'url'      => 'https://feeds.example.com/paths.txt',
								'variable' => 'path',
								'operator' => 'contains',
								'advanced' => array(
									'upstream' => array(
										'auth' => array(
											'type'  => 'bearer',
											'token' => self::PATH_TOKEN,
										),
									),
								),
							),
						),
					),
				),
			),
		);
	}
}
