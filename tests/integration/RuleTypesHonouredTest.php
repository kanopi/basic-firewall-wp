<?php
/**
 * Every setting of every offered rule type, against the library that enforces it.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Compiler\Config_Compiler;
use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Registry;
use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use Kanopi\BasicFirewall\RuleType\Types\Url;
use Kanopi\BasicFirewall\RuleType\Types\User_Agent;
use Kanopi\Firewall\Plugins\UserAgent;
use Kanopi\Firewall\RateLimitStorage\DatabaseRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage;
use Kanopi\Firewall\Source\SourceDefinition;
use Symfony\Component\HttpFoundation\Request;

/**
 * That the library does what each rule type's settings say.
 *
 * A pre-release review found five settings compiling to keys the library has
 * never read -- a Core Rule Set threshold, the bot source, AbuseIPDB's report
 * age, the rate limit table, and an explicit list format that stopped the rule
 * constructing at all. Every one of them saved, compiled, loaded and reported
 * itself healthy.
 *
 * Each test here saves a rule through the settings option (and so through its
 * type's own validator), rebuilds the compiled file, starts the library on it
 * exactly as the runner does, and then asks the library -- by evaluating a
 * request, or by reading the effective value off the object that enforces it.
 *
 * The first test is the one that keeps this honest. It enumerates the registry
 * and every setting each offered type stores, and fails on any it finds no
 * entry for below. A new rule type, or a new field on an existing one, cannot
 * ship without somebody writing down how the library is shown to honour it.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Ip_Address
 * @covers \Kanopi\BasicFirewall\RuleType\Types\User_Agent
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Url
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Rate_Limit
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Edge_Signal
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Asn
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Geo_Location
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Abuse_Ipdb
 * @covers \Kanopi\BasicFirewall\RuleType\Types\Crs
 * @covers \Kanopi\BasicFirewall\RuleType\Has_Sources
 */
final class RuleTypesHonouredTest extends Honoured_Settings {

	/**
	 * Every stored setting of every offered type, and the test proving it.
	 *
	 * Keyed by type, then by the dotted path of the setting as
	 * `default_settings()` holds it. The value names the test method below that
	 * shows the library acting on it.
	 *
	 * @var array<string, array<string, string>>
	 */
	private const COVERAGE = array(
		'ip_address'  => array(
			'addresses' => 'test_ip_address',
			'sources'   => 'test_every_source_format_constructs',
		),
		'user_agent'  => array(
			'match_type'      => 'test_user_agent_conditions',
			'conditions'      => 'test_user_agent_conditions',
			'sources'         => 'test_every_source_format_constructs',
			'cache_detection' => 'test_user_agent_cache',
			'bot_source'      => 'test_user_agent_bot_source',
			'verify'          => 'test_user_agent_verification',
			'verify_suffixes' => 'test_user_agent_verification',
		),
		'url'         => array(
			'match_type' => 'test_url_conditions',
			'conditions' => 'test_url_conditions',
			'sources'    => 'test_every_source_format_constructs',
		),
		'asn'         => array(
			'match_type'         => 'test_asn',
			'conditions'         => 'test_asn',
			'sources'            => 'test_every_source_format_constructs',
			'reader.source'      => 'test_asn',
			'reader.database'    => 'test_asn',
			'reader.license_key' => 'test_asn',
			'reader.edge'        => 'test_asn',
			'reader.headers'     => 'test_asn',
		),
		'edge_signal' => array(
			'match_type'     => 'test_edge_signal',
			'conditions'     => 'test_edge_signal',
			'sources'        => 'test_every_source_format_constructs',
			'provider'       => 'test_edge_signal',
			'custom_headers' => 'test_edge_signal',
		),
		'geolocation' => array(
			'match_type'         => 'test_geolocation',
			'conditions'         => 'test_geolocation',
			'sources'            => 'test_every_source_format_constructs',
			'reader.source'      => 'test_geolocation',
			'reader.database'    => 'test_geolocation',
			'reader.license_key' => 'test_geolocation',
			'reader.edge'        => 'test_geolocation',
			'reader.headers'     => 'test_geolocation',
		),
		'rate_limit'  => array(
			'paths'                     => 'test_rate_limit_counts',
			'default_limit'             => 'test_rate_limit_counts',
			'default_window'            => 'test_rate_limit_counts',
			'limit_unlisted_paths'      => 'test_rate_limit_counts',
			'storage.backend'           => 'test_rate_limit_storage',
			'storage.file'              => 'test_rate_limit_counts',
			'storage.connection_source' => 'test_rate_limit_storage',
			'storage.dsn'               => 'test_rate_limit_storage',
			'storage.table'             => 'test_rate_limit_storage',
			'storage.redis_host'        => 'test_rate_limit_storage',
			'storage.redis_port'        => 'test_rate_limit_storage',
			'storage.redis_password'    => 'test_rate_limit_storage',
			'storage.key_prefix'        => 'test_rate_limit_storage',
		),
		'abuse_ipdb'  => array(
			'threshold'    => 'test_abuse_ipdb',
			'api_key'      => 'test_abuse_ipdb',
			'cache_ttl'    => 'test_abuse_ipdb',
			'timeout'      => 'test_abuse_ipdb',
			'max_age_days' => 'test_abuse_ipdb',
		),
		'crs'         => array(
			'mode'                => 'test_crs',
			'paranoia'            => 'test_crs',
			'inbound'             => 'test_crs',
			'outbound'            => 'test_crs',
			'disabled_rules'      => 'test_crs',
			'disabled_categories' => 'test_crs',
		),
	);

	/**
	 * An unmistakable SQL injection, and a request with nothing in it.
	 */
	private const ATTACK = "/?id=1'%20UNION%20SELECT%201,2,3--";

	/**
	 * Every offered type, and every setting it stores, has a test below.
	 *
	 * The same shape as the variable check in GeoVariableTest: rather than
	 * trusting a list to be complete, ask the registry what the screens offer
	 * and fail on anything the list does not cover.
	 */
	public function test_every_offered_setting_is_covered(): void {
		$registry = Plugin::instance()->rule_types();
		$shipped  = $registry->shipped_ids();

		foreach ( $registry->all() as $id => $type ) {
			if ( ! in_array( $id, $shipped, true ) ) {
				continue;
			}

			$this->assertArrayHasKey( $id, self::COVERAGE, "The $id rule type is offered, and nothing here proves the library honours any of its settings." );

			$stored  = self::leaves( $type->default_settings() );
			$covered = array_keys( self::COVERAGE[ $id ] );

			$this->assertSame( array(), array_values( array_diff( $stored, $covered ) ), "These $id settings are stored and nothing here proves the library reads them." );
			$this->assertSame( array(), array_values( array_diff( $covered, $stored ) ), "These $id settings are listed as covered but the type no longer stores them." );

			foreach ( self::COVERAGE[ $id ] as $setting => $method ) {
				$this->assertTrue( method_exists( $this, $method ), "$id.$setting names $method, which does not exist." );
			}
		}

		$this->assertSame( array(), array_values( array_diff( array_keys( self::COVERAGE ), array_keys( $registry->all() ) ) ), 'A type listed here is no longer offered.' );
	}

	/**
	 * The vulnerability score type is withdrawn: not offered, never compiled,
	 * and a stored rule kept and named.
	 *
	 * It compiled a threshold and weights; the library scores with its own
	 * model and reads neither, so the rule never matched whatever it was set
	 * to. Kept, because it is somebody's configuration; reported, because
	 * silence was the defect.
	 */
	public function test_vulnerability_score_is_withdrawn(): void {
		$registry = Plugin::instance()->rule_types();

		$this->assertTrue( Registry::is_withdrawn( 'vulnerability_score' ) );
		$this->assertFalse( $registry->has( 'vulnerability_score' ) );
		$this->assertNotContains( 'vulnerability_score', $registry->shipped_ids() );

		$claim = static function ( array $types ): array {
			$types['vulnerability_score'] = new Url();

			return $types;
		};

		add_filter( 'basic_firewall_rule_types', $claim );
		$registry->reset();

		try {
			$this->assertFalse( $registry->has( 'vulnerability_score' ), 'Another plugin claimed a withdrawn type, and stored rules would compile to it.' );
		} finally {
			remove_filter( 'basic_firewall_rule_types', $claim );
			$registry->reset();
		}

		$stored = $this->rule(
			'old-score',
			'vulnerability_score',
			array(
				'threshold' => 30,
				'weights'   => array( 'method' => 20 ),
			)
		);

		$firewall = $this->build(
			array(
				'rules' => array(
					$stored,
					$this->rule( 'still-here', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/x' ) ) ) ),
				),
			)
		);

		$this->plugin_named( $firewall, 'still-here' );
		$this->assertNull( $this->bucket_of( $firewall, 'old-score' ), 'A withdrawn rule was compiled.' );
		$this->assertNotEmpty( preg_grep( '/"old-score".*withdrawn/', $this->problems ), 'A skipped withdrawn rule was not reported.' );

		$kept = array_column( (array) Plugin::instance()->settings()->get( 'rules', array() ), null, 'id' );

		$this->assertSame( $stored['settings'], $kept['old-score']['settings'] ?? null, 'Saving the settings changed or dropped a withdrawn rule.' );
	}

	/**
	 * Addresses, CIDR blocks and ranges all match, and nothing else does.
	 */
	public function test_ip_address(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'ips', 'ip_address', array( 'addresses' => "203.0.113.5\n198.51.100.0/24\n2001:db8::1-2001:db8::ff" ) ),
				),
			)
		);

		$plugin = $this->plugin_named( $firewall, 'ips' );

		foreach ( array( '203.0.113.5', '198.51.100.77', '2001:db8::10' ) as $ip ) {
			$this->assertTrue( (bool) $plugin->evaluate( self::request( '/', $ip ) ), "$ip is listed and did not match." );
		}

		$this->assertFalse( (bool) $plugin->evaluate( self::request( '/', '192.0.2.1' ) ), 'An unlisted address matched.' );
	}

	/**
	 * Every format a source can be given constructs, and so does a stored xml.
	 *
	 * The library decodes six formats. The screen offered a seventh, `xml`,
	 * which the library infers from a `.xml` URL but refuses when it is
	 * declared -- so choosing it stopped the rule constructing, and a block
	 * rule that does not construct is a rule that is not running.
	 */
	public function test_every_source_format_constructs(): void {
		$formats = array_values( array_filter( array_keys( Ip_Address::formats() ), static fn ( $format ): bool => '' !== $format ) );

		$this->assertSame( array(), array_values( array_diff( $formats, SourceDefinition::FORMATS ) ), 'The screen offers a list format the library refuses when it is declared.' );

		$rules    = array();
		$registry = Plugin::instance()->rule_types();

		foreach ( array( 'ip_address', 'user_agent', 'url', 'asn', 'edge_signal', 'geolocation' ) as $type ) {
			$sources = array();

			foreach ( array_merge( array( '' ), $formats, array( 'xml' ) ) as $index => $format ) {
				$sources[] = array_merge(
					$registry->get( $type )::source_defaults(),
					array(
						'url'      => 'https://example.com/list-' . $index . '.' . ( '' === $format ? 'txt' : $format ),
						'format'   => $format,
						'variable' => 'ip_address' === $type ? '' : $this->source_variable( $type ),
						// An ASN list compared by number compiles to a guarded pattern; it has to construct too.
						'operator' => 'asn' === $type ? 'equals' : 'contains',
					)
				);
			}

			$rules[] = $this->rule( 'src-' . $type, $type, array( 'sources' => $sources ) + ( 'ip_address' === $type ? array( 'addresses' => '192.0.2.250' ) : array( 'conditions' => array( self::condition( $this->source_variable( $type ), 'equals', 'x' ) ) ) ) );
		}

		// Written raw, as a site that saved `xml` before it was withdrawn has it.
		$firewall = $this->build( array( 'rules' => $rules ), true );

		foreach ( array( 'ip_address', 'user_agent', 'url', 'asn', 'edge_signal', 'geolocation' ) as $type ) {
			$this->plugin_named( $firewall, 'src-' . $type );
		}
	}

	/**
	 * Any matches on one condition; all needs every one.
	 */
	public function test_url_conditions(): void {
		$this->assert_match_type(
			'url',
			array(),
			self::condition( 'path', 'equals', '/wp-admin/install.php' ),
			self::request( '/wp-admin/install.php' ),
			self::request( '/about' )
		);
	}

	/**
	 * What each variable the Request / URL screen offers is compared against.
	 *
	 * Operator and value, chosen to match url_request(). A family is written
	 * with a member, since the family on its own reads nothing; the test below
	 * checks every family the screen offers has one here.
	 *
	 * @var array<string, array{0: string, 1: string}>
	 */
	private const URL_MATCHES = array(
		'method'         => array( 'equals', 'POST' ),
		'path'           => array( 'equals', '/wp-login.php' ),
		'host'           => array( 'equals', 'example.com' ),
		'scheme'         => array( 'equals', 'https' ),
		'port'           => array( 'equals', '8443' ),
		'query.x'        => array( 'equals', '1' ),
		'post.log'       => array( 'equals', 'admin' ),
		'header.referer' => array( 'contains', 'evil.test' ),
		'cookie.session' => array( 'equals', 'abc123' ),
	);

	/**
	 * A request carrying something for every URL variable.
	 */
	private static function url_request(): Request {
		$request = Request::create(
			'https://example.com:8443/wp-login.php?x=1&redirect_to=%2F',
			'POST',
			array( 'log' => 'admin' ),
			array( 'session' => 'abc123' ),
			array(),
			array(
				'REMOTE_ADDR'  => '203.0.113.200',
				'HTTP_REFERER' => 'https://evil.test/',
				'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
			)
		);

		return $request;
	}

	/**
	 * Every variable the Request / URL screen offers is one the library reads.
	 *
	 * The screen offered `uri`, `body`, `content_type`, `referer` and the
	 * `server` family, none of which the library resolves: each compared
	 * against nothing, so a negated condition on one matched every request.
	 * Rather than trusting a list of names, ask the type what it offers, save a
	 * rule on each through the settings, start the library on the compiled
	 * file, and make it evaluate a request.
	 */
	public function test_every_offered_url_variable_resolves(): void {
		$type     = Plugin::instance()->rule_types()->get( 'url' );
		$offered  = array_keys( (array) self::invoke( $type, 'variable_options' ) );
		$families = (array) self::invoke( $type, 'variable_prefixes' );

		foreach ( $offered as $variable ) {
			$this->assertArrayHasKey( $variable, self::URL_MATCHES, "The URL screen offers $variable and nothing here proves the library reads it." );
		}

		foreach ( $families as $family ) {
			$this->assertNotEmpty(
				array_filter( array_keys( self::URL_MATCHES ), static fn ( string $key ): bool => 0 === strpos( $key, $family . '.' ) ),
				"The URL screen offers the $family family and nothing here proves the library reads a member of it."
			);
		}

		foreach ( array_keys( self::URL_MATCHES ) as $variable ) {
			$family = strstr( $variable, '.', true );

			$this->assertTrue( in_array( $variable, $offered, true ) || in_array( $family, $families, true ), "$variable is tested here but no longer offered." );
		}

		$rules = array();
		$index = 0;

		foreach ( self::URL_MATCHES as $variable => list( $operator, $value ) ) {
			$rules[] = $this->rule( 'url-var-' . ( $index++ ), 'url', array( 'conditions' => array( self::condition( $variable, $operator, $value ) ) ) );
		}

		$firewall = $this->build( array( 'rules' => $rules ) );
		$index    = 0;

		foreach ( self::URL_MATCHES as $variable => list( $operator, $value ) ) {
			$plugin = $this->plugin_named( $firewall, 'url-var-' . ( $index++ ) );

			$this->assertTrue( (bool) $plugin->evaluate( self::url_request() ), "$variable $operator $value did not match a request carrying it." );
			$this->assertFalse( (bool) $plugin->evaluate( self::request( 'http://other.test/' ) ), "$variable $operator $value matched a request that does not carry it." );
		}
	}

	/**
	 * A condition stored on an old name is saved and compiled as the header it is.
	 *
	 * Written raw, as a site on the previous release has it, so the compiler's
	 * own translation is what is being tested rather than the validator's.
	 *
	 * @dataProvider renamed_url_variables
	 *
	 * @param string $old     Stored name.
	 * @param string $library The library's name.
	 * @param string $value   What the request carries.
	 */
	public function test_an_old_url_name_compiles_to_the_header( string $old, string $library, string $value ): void {
		$condition           = self::condition( $old, 'not_contains', $value );
		$condition['negate'] = false;

		$firewall = $this->build( array( 'rules' => array( $this->rule( 'old-name', 'url', array( 'conditions' => array( $condition ) ) ) ) ), true );

		$compiled = array_values( array_filter( $this->compiled['plugins'], static fn ( array $entry ): bool => 'old-name' === ( $entry['metadata']['name'] ?? '' ) ) );

		$this->assertSame( $library, $compiled[0]['config'][0]['variable'] );

		$plugin = $this->plugin_named( $firewall, 'old-name' );

		$this->assertFalse( (bool) $plugin->evaluate( self::url_request() ), "A request carrying $value matched \"$old does not contain $value\"." );
		$this->assertTrue( (bool) $plugin->evaluate( self::request( '/' ) ), "A request without $value did not match \"$old does not contain $value\"." );
	}

	/**
	 * The renamed URL variables, and something the request carries in each.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public static function renamed_url_variables(): array {
		return array(
			'referer'      => array( 'referer', 'header.referer', 'evil.test' ),
			'content_type' => array( 'content_type', 'header.content-type', 'x-www-form-urlencoded' ),
		);
	}

	/**
	 * Every rename is tested above.
	 */
	public function test_every_url_rename_is_tested(): void {
		$this->assertSame( Url::RENAMED_VARIABLES, array_combine( array_column( self::renamed_url_variables(), 0 ), array_column( self::renamed_url_variables(), 1 ) ) );
	}

	/**
	 * A condition on a variable the library cannot read is kept, and reported.
	 *
	 * Negated, inside an "all" rule, which is the case that makes dropping it
	 * wrong: without the condition the rule matches more than it was written
	 * to. With it, it compares against nothing -- which is also wrong, and
	 * which is why it is reported rather than left to look healthy.
	 *
	 * @dataProvider retired_url_variables
	 *
	 * @param string $variable A retired variable.
	 */
	public function test_a_retired_url_variable_is_kept_and_reported( string $variable ): void {
		$retired           = self::condition( $variable, 'contains', 'x' );
		$retired['negate'] = true;

		$this->given_settings(
			self::merge(
				$this->base_settings(),
				array(
					'rules' => array(
						$this->rule(
							'retired',
							'url',
							array(
								'match_type' => 'all',
								'conditions' => array( self::condition( 'path', 'starts_with', '/wp-admin' ), $retired ),
							)
						),
					),
				)
			)
		);

		/*
		 * Compiled directly rather than started. The library's own linter
		 * agrees the condition cannot match, and says so as an error -- which
		 * is the point, and which start() rightly treats as a failure.
		 */
		$compiler = new Config_Compiler();
		$compiler->compile();

		$this->problems = $compiler->problems();

		$kept = array_column( (array) Plugin::instance()->settings()->get( 'rules', array() ), null, 'id' );

		$this->assertSame( array( 'path', $variable ), array_column( $kept['retired']['settings']['conditions'], 'variable' ), 'A settings write dropped the condition.' );
		$this->assertNotEmpty( preg_grep( '/"retired".*' . preg_quote( $variable, '/' ) . '/', $this->problems ), 'The compiler did not report the condition.' );
		$this->assertNotEmpty( preg_grep( '/' . preg_quote( $variable, '/' ) . '/', Plugin::instance()->rule_types()->get( 'url' )->check_requirements( $kept['retired']['settings'] ) ), 'The rule screen does not report the condition.' );
		$this->assertArrayNotHasKey( $variable, (array) self::invoke( Plugin::instance()->rule_types()->get( 'url' ), 'variable_options' ), 'A retired variable is still offered.' );
	}

	/**
	 * The variables the Request / URL type offered and the library never read.
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function retired_url_variables(): array {
		return array(
			'uri'    => array( 'uri' ),
			'body'   => array( 'body' ),
			'server' => array( 'server.SERVER_NAME' ),
		);
	}

	/**
	 * A port compares as the number the request holds.
	 *
	 * @dataProvider port_comparisons
	 *
	 * @param string $operator Comparison.
	 * @param string $value    As typed.
	 * @param bool   $matches  Whether a request on 8443 matches.
	 */
	public function test_a_port_compares_as_a_number( string $operator, string $value, bool $matches ): void {
		$firewall = $this->build( array( 'rules' => array( $this->rule( 'port', 'url', array( 'conditions' => array( self::condition( 'port', $operator, $value ) ) ) ) ) ) );

		$this->assertSame( $matches, (bool) $this->plugin_named( $firewall, 'port' )->evaluate( self::url_request() ) );
	}

	/**
	 * Port comparisons against a request on 8443.
	 *
	 * @return array<string, array{0: string, 1: string, 2: bool}>
	 */
	public static function port_comparisons(): array {
		return array(
			'equals'            => array( 'equals', '8443', true ),
			'equals another'    => array( 'equals', '443', false ),
			'not equal to 8443' => array( 'not_equals', '8443', false ),
			'not equal to 443'  => array( 'not_equals', '443', true ),
			'one of'            => array( 'in', '443, 8443', true ),
			'not one of'        => array( 'in', '80, 443', false ),
			'greater than'      => array( 'gt', '8000', true ),
		);
	}

	/**
	 * The same for user agent conditions.
	 */
	public function test_user_agent_conditions(): void {
		$this->assert_match_type(
			'user_agent',
			array( 'bot_source' => 'curated' ),
			self::condition( 'client.name', 'contains', 'curl' ),
			self::request( '/', '203.0.113.200', array( 'User-Agent' => 'curl/8.4.0' ) ),
			self::request( '/' )
		);
	}

	/**
	 * Which list `bot` consults is the library's `bot_detector`.
	 *
	 * The screen stored `bot_source` and the compiler wrote it as-is. The
	 * library has never read that key, so every choice behaved as the default:
	 * sqlmap is not in the curated database, and "the wider list" let it
	 * through exactly as "curated" did.
	 *
	 * @dataProvider bot_sources
	 *
	 * @param string $source   What the screen stores.
	 * @param string $detector What the library should end up using.
	 * @param bool   $catches  Whether `bot equals true` catches sqlmap.
	 */
	public function test_user_agent_bot_source( string $source, string $detector, bool $catches ): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'bots',
						'user_agent',
						array(
							'match_type' => 'any',
							'conditions' => array( self::condition( 'bot', 'equals', 'true' ) ),
							'bot_source' => $source,
						)
					),
				),
			)
		);

		$plugin = $this->plugin_named( $firewall, 'bots' );

		$this->assertSame( $detector, self::invoke( $plugin, 'botDetector' ) );
		$this->assertSame(
			$catches,
			(bool) $plugin->evaluate( self::request( '/', '203.0.113.200', array( 'User-Agent' => 'sqlmap/1.7.2#stable (https://sqlmap.org)' ) ) ),
			"With the bot source at $source, bot equals true should " . ( $catches ? '' : 'not ' ) . 'catch sqlmap.'
		);
	}

	/**
	 * The three sources.
	 *
	 * @return array<string, array{0: string, 1: string, 2: bool}>
	 */
	public static function bot_sources(): array {
		return array(
			'curated' => array( 'curated', 'device-detector', false ),
			'wider'   => array( 'wider', 'crawler-detect', true ),
			'either'  => array( 'either', 'both', true ),
		);
	}

	/**
	 * Every choice the screen stores maps to a detector the library knows.
	 */
	public function test_every_bot_source_is_a_library_detector(): void {
		$this->assertSame( array_keys( self::bot_sources() ), array_keys( User_Agent::BOT_DETECTORS ), 'A bot source is offered that no test above evaluates.' );
		$this->assertSame( array(), array_values( array_diff( User_Agent::BOT_DETECTORS, UserAgent::BOT_DETECTORS ) ) );
	}

	/**
	 * Turning the detection cache off is honoured, and leaving it on caches.
	 */
	public function test_user_agent_cache(): void {
		$conditions = array( self::condition( 'bot', 'equals', 'true' ) );

		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'cached',
						'user_agent',
						array(
							'conditions'      => $conditions,
							'cache_detection' => true,
						)
					),
					$this->rule(
						'uncached',
						'user_agent',
						array(
							'conditions'      => $conditions,
							'cache_detection' => false,
						)
					),
				),
			)
		);

		$this->assertNotNull( self::invoke( $this->plugin_named( $firewall, 'cached' ), 'cache' ), 'Detection is not cached although the rule asks for it.' );
		$this->assertNull( self::invoke( $this->plugin_named( $firewall, 'uncached' ), 'cache' ), 'Detection is cached although the rule turned it off.' );
	}

	/**
	 * A verifying rule does not believe an agent string on its own.
	 *
	 * Checked from the loopback address, whose reverse name is never in a
	 * crawler's domain, so the answer is quick and certain.
	 */
	public function test_user_agent_verification(): void {
		$settings = array(
			'conditions'      => array( self::condition( 'bot.name', 'contains', 'Googlebot' ) ),
			'verify_suffixes' => array( 'googlebot.com', 'google.com' ),
		);

		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'trusting', 'user_agent', array( 'verify' => false ) + $settings ),
					$this->rule( 'verifying', 'user_agent', array( 'verify' => true ) + $settings, array( 'weight' => 5 ) ),
				),
			)
		);

		$googlebot = static fn (): Request => self::request( '/', '127.0.0.1', array( 'User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' ) );

		$trusting  = $this->plugin_named( $firewall, 'trusting' );
		$verifying = $this->plugin_named( $firewall, 'verifying' );

		$this->assertTrue( (bool) $trusting->evaluate( $googlebot() ), 'The agent string alone should match a rule that does not verify.' );
		$this->assertTrue( (bool) $verifying->evaluate( $googlebot() ), 'Verification comes after the conditions; the conditions should still match.' );
		$this->assertTrue( method_exists( $verifying, 'passesIdentityVerification' ) );
		$this->assertTrue( $trusting->passesIdentityVerification( $googlebot() ), 'A rule that does not verify has nothing to pass.' );
		$this->assertFalse( $verifying->passesIdentityVerification( $googlebot() ), 'The loopback address verified as Googlebot.' );
	}

	/**
	 * Edge signals are read from the named CDN's headers, and from a custom map.
	 */
	public function test_edge_signal(): void {
		Request::setTrustedProxies( array( '10.0.0.1' ), Request::HEADER_X_FORWARDED_FOR );

		$firewall = $this->build(
			array(
				'global' => array( 'behind_proxy' => 'yes' ),
				'rules'  => array(
					$this->rule(
						'cf',
						'edge_signal',
						array(
							'match_type' => 'all',
							'conditions' => array( self::condition( 'bot_score', 'lte', '5' ), self::condition( 'verified_bot', 'equals', 'false' ) ),
							'provider'   => 'cloudflare',
						)
					),
					$this->rule(
						'mine',
						'edge_signal',
						array(
							'match_type'     => 'any',
							'conditions'     => array( self::condition( 'bot_score', 'lte', '5' ) ),
							'provider'       => 'custom',
							'custom_headers' => array( 'bot_score: X-Edge-Score' ),
						)
					),
				),
			)
		);

		$proxied = static function ( array $headers ): Request {
			return self::request( '/', '10.0.0.1', array( 'X-Forwarded-For' => '203.0.113.9' ) + $headers );
		};

		$cloudflare = $this->plugin_named( $firewall, 'cf' );
		$custom     = $this->plugin_named( $firewall, 'mine' );

		$this->assertTrue(
			(bool) $cloudflare->evaluate(
				$proxied(
					array(
						'Cf-Bot-Score'    => '2',
						'Cf-Verified-Bot' => 'false',
					)
				)
			),
			'All conditions hold on the Cloudflare headers.'
		);
		$this->assertFalse(
			(bool) $cloudflare->evaluate(
				$proxied(
					array(
						'Cf-Bot-Score'    => '2',
						'Cf-Verified-Bot' => 'true',
					)
				)
			),
			'An "all" rule matched with one condition failing.'
		);
		$this->assertTrue( (bool) $custom->evaluate( $proxied( array( 'X-Edge-Score' => '1' ) ) ), 'The custom header map was not read.' );
		$this->assertFalse( (bool) $custom->evaluate( $proxied( array( 'X-Edge-Score' => '80' ) ) ) );
	}

	/**
	 * Geolocation from the edge, and from a database.
	 *
	 * The license key is deliberately never compiled -- nothing in the library
	 * reads it for a local database -- so what is shown is that a rule with one
	 * still constructs and still reads its database.
	 */
	public function test_geolocation(): void {
		Request::setTrustedProxies( array( '10.0.0.1' ), Request::HEADER_X_FORWARDED_FOR );

		$firewall = $this->build(
			array(
				'global' => array( 'behind_proxy' => 'yes' ),
				'rules'  => array(
					$this->rule(
						'edge-geo',
						'geolocation',
						array(
							'match_type' => 'all',
							'conditions' => array( self::condition( 'country', 'equals', 'GB' ), self::condition( 'country', 'not_equals', 'FR' ) ),
							'reader'     => array(
								'source' => 'edge',
								'edge'   => 'cloudflare',
							),
						)
					),
					$this->rule(
						'custom-geo',
						'geolocation',
						array(
							'conditions' => array( self::condition( 'country', 'equals', 'GB' ) ),
							'reader'     => array(
								'source'  => 'edge',
								'edge'    => 'custom',
								'headers' => array( 'country: X-Visitor-Country' ),
							),
						)
					),
					$this->rule(
						'db-geo',
						'geolocation',
						array(
							'conditions' => array( self::condition( 'city', 'equals', 'London' ) ),
							'reader'     => array(
								'source'      => 'database',
								'database'    => $this->scratch . '/GeoLite2-City.mmdb',
								'license_key' => 'not-compiled',
							),
						)
					),
				),
			)
		);

		$proxied = static fn ( array $headers ): Request => self::request( '/', '10.0.0.1', array( 'X-Forwarded-For' => '203.0.113.10' ) + $headers );

		$this->assertTrue( (bool) $this->plugin_named( $firewall, 'edge-geo' )->evaluate( $proxied( array( 'Cf-Ipcountry' => 'GB' ) ) ) );
		$this->assertFalse( (bool) $this->plugin_named( $firewall, 'edge-geo' )->evaluate( $proxied( array( 'Cf-Ipcountry' => 'FR' ) ) ) );
		$this->assertTrue( (bool) $this->plugin_named( $firewall, 'custom-geo' )->evaluate( $proxied( array( 'X-Visitor-Country' => 'GB' ) ) ), 'The custom header map was not read.' );

		$database = $this->plugin_named( $firewall, 'db-geo' );

		$this->assertSame( $this->scratch . '/GeoLite2-City.mmdb', $this->compiled_rule( 'db-geo' )['metadata']['reader']['db'] ?? null );
		$this->assertStringNotContainsString( 'not-compiled', (string) wp_json_encode( $this->compiled ) );

		self::set_property( $database, 'reader', new Fake_Geo_Reader() );

		$this->assertTrue( (bool) $database->evaluate( self::request( '/', '203.0.113.10' ) ), 'The database reader was not consulted.' );
	}

	/**
	 * ASN from a database. The edge settings are stored but not offered here:
	 * no CDN sends an ASN header, so the type ignores them.
	 */
	public function test_asn(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'net',
						'asn',
						array(
							'match_type' => 'all',
							'conditions' => array( self::condition( 'asn', 'equals', '16509' ), self::condition( 'asn_org', 'contains', 'amazon' ) ),
							'reader'     => array(
								'source'      => 'edge',
								'database'    => $this->scratch . '/GeoLite2-ASN.mmdb',
								'license_key' => 'not-compiled',
								'edge'        => 'cloudflare',
								'headers'     => array(),
							),
						)
					),
				),
			)
		);

		$this->assertSame( $this->scratch . '/GeoLite2-ASN.mmdb', $this->compiled_rule( 'net' )['metadata']['reader']['db'] ?? null, 'An ASN rule read from the edge, which no CDN supplies.' );

		$plugin = $this->plugin_named( $firewall, 'net' );

		self::set_property( $plugin, 'reader', new Fake_Geo_Reader() );

		$this->assertTrue( (bool) $plugin->evaluate( self::request( '/', '203.0.113.10' ) ) );
	}

	/**
	 * Listed limits, the fallback allowance, and whether it applies at all.
	 */
	public function test_rate_limit_counts(): void {
		$settings = array(
			'paths'                => array( '/rl-test 2 60' ),
			'default_limit'        => 3,
			'default_window'       => 45,
			'limit_unlisted_paths' => false,
			'storage'              => array(
				'backend' => 'file',
				'file'    => $this->scratch . '/ratelimit.data',
			),
		);

		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'listed-only', 'rate_limit', $settings ),
					$this->rule(
						'everything',
						'rate_limit',
						array_merge(
							$settings,
							array(
								'limit_unlisted_paths' => true,
								'paths'                => array( '/elsewhere 50 60' ),
							)
						)
					),
				),
			)
		);

		$listed = $this->plugin_named( $firewall, 'listed-only' );
		$all    = $this->plugin_named( $firewall, 'everything' );

		$this->assertInstanceOf( FileRateLimitStorage::class, self::property( $listed, 'storage' ) );
		$this->assertSame( $this->scratch . '/ratelimit.data', self::property( self::property( $listed, 'storage' ), 'config' )['file'] ?? null );

		$this->assertFalse( self::invoke( $listed, 'limitsUnlistedPaths' ) );
		$this->assertTrue( self::invoke( $all, 'limitsUnlistedPaths' ) );

		// Read off the plugin, because the constructor defaults these keys in
		// place: a misspelled key leaves the library's 10 here instead.
		$this->assertSame( 3, (int) self::property( $all, 'metadata' )['default_rate'] );
		$this->assertSame( 45, (int) self::property( $all, 'metadata' )['default_sample'] );

		$results = array();

		for ( $i = 0; $i < 3; $i++ ) {
			$results[] = (bool) $listed->evaluate( self::request( '/rl-test', '203.0.113.60' ) );
		}

		$this->assertSame( array( false, false, true ), $results, 'The listed limit of two was not enforced on the third request.' );

		$unlisted = array();

		for ( $i = 0; $i < 5; $i++ ) {
			$unlisted[] = (bool) $listed->evaluate( self::request( '/somewhere-else', '203.0.113.61' ) );
		}

		$this->assertNotContains( true, $unlisted, 'An unlisted path was limited although the rule said not to.' );

		$fallback = array();

		for ( $i = 0; $i < 4; $i++ ) {
			$fallback[] = (bool) $all->evaluate( self::request( '/somewhere-else', '203.0.113.62' ) );
		}

		$this->assertSame( array( false, false, false, true ), $fallback, 'The fallback allowance of three was not enforced.' );
		$this->assertSame( 429, $all->getStatusCode(), 'The library answers a rate limit with 429, whatever else is configured.' );
	}

	/**
	 * Counters go to the table the plugin means, and to Redis where asked.
	 *
	 * The compiler wrote `storage-table`. The library reads `storage_table`, so
	 * every WordPress-backed rate limit counted into the library's own default
	 * table, unprefixed -- one table shared by every site in the database, and
	 * not the one the uninstaller removes.
	 */
	public function test_rate_limit_storage(): void {
		global $wpdb;

		$credentials = new Database_Credentials();
		$table       = $credentials->prefix_table( 'basic_firewall_ratelimit' );
		$existed     = $table === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );

		// The library's default, where a regression would send the counters.
		$fallback_existed = 'firewall_rate_limit_storage' === $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', 'firewall_rate_limit_storage' ) );
		$named            = 'bfw_honoured_' . bin2hex( random_bytes( 3 ) );

		$parameters = $credentials->get_connection_parameters();
		$dsn        = sprintf(
			'pdo-mysql://%s:%s@%s:%d/%s',
			rawurlencode( (string) $parameters['user'] ),
			rawurlencode( (string) $parameters['password'] ),
			(string) ( $parameters['host'] ?? 'localhost' ),
			(int) ( $parameters['port'] ?? 3306 ),
			rawurlencode( (string) $parameters['dbname'] )
		);

		try {
			$firewall = $this->build(
				array(
					'rules' => array(
						$this->rule(
							'wp-db',
							'rate_limit',
							array(
								'paths'   => array( '/rl-db 5 60' ),
								'storage' => array(
									'backend'           => 'database',
									'connection_source' => 'wordpress',
									'table'             => 'basic_firewall_ratelimit',
								),
							)
						),
						$this->rule(
							'dsn-db',
							'rate_limit',
							array(
								'paths'   => array( '/rl-dsn 5 60' ),
								'storage' => array(
									'backend'           => 'database',
									'connection_source' => 'dsn',
									'dsn'               => $dsn,
									'table'             => $named,
								),
							)
						),
						$this->rule(
							'redis',
							'rate_limit',
							array(
								'paths'   => array( '/rl-redis 5 60' ),
								'storage' => array(
									'backend'        => 'redis',
									'redis_host'     => '192.0.2.44',
									'redis_port'     => 6380,
									'redis_password' => 'hunter2',
									'key_prefix'     => 'honoured:',
								),
							)
						),
					),
				)
			);

			$wordpress = self::property( $this->plugin_named( $firewall, 'wp-db' ), 'storage' );

			$this->assertInstanceOf( DatabaseRateLimitStorage::class, $wordpress );
			$this->assertSame( $table, self::property( $wordpress, 'config' )['storage_table'] ?? null, 'Counters are not going to the table the plugin intends.' );

			$this->plugin_named( $firewall, 'wp-db' )->evaluate( self::request( '/rl-db', '203.0.113.70' ) );

			$this->assertSame( $table, $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ), 'Nothing was counted into the intended table.' );

			$supplied = self::property( $this->plugin_named( $firewall, 'dsn-db' ), 'storage' );

			$this->assertInstanceOf( DatabaseRateLimitStorage::class, $supplied );
			$this->assertSame( $named, self::property( $supplied, 'config' )['storage_table'] ?? null, 'A table named for a supplied connection must not be prefixed or renamed.' );

			$this->plugin_named( $firewall, 'dsn-db' )->evaluate( self::request( '/rl-dsn', '203.0.113.71' ) );

			$this->assertSame( $named, $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $named ) ), 'The supplied connection was not used.' );

			$redis = self::property( $this->plugin_named( $firewall, 'redis' ), 'storage' );

			$this->assertInstanceOf( RedisRateLimitStorage::class, $redis );

			$options = self::property( $redis, 'config' )['redis'] ?? array();

			$this->assertSame( '192.0.2.44', $options['host'] ?? null );
			$this->assertSame( 6380, $options['port'] ?? null );
			$this->assertSame( 'hunter2', $options['auth'] ?? null );
			$this->assertSame( 'honoured:', $options['prefix'] ?? null );
		} finally {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- test cleanup of tables this test created.
			$wpdb->query( "DROP TABLE IF EXISTS `$named`" );

			if ( ! $existed ) {
				$wpdb->query( "DROP TABLE IF EXISTS `$table`" );
			}

			if ( ! $fallback_existed ) {
				$wpdb->query( 'DROP TABLE IF EXISTS `firewall_rate_limit_storage`' );
			}
			// phpcs:enable
		}
	}

	/**
	 * Every AbuseIPDB setting reaches the provider that makes the call.
	 *
	 * No request is evaluated: that would spend quota on a real key, or fail
	 * against a fake one. The values are read off the objects that would make
	 * the call, which is where a misspelled key shows up as the default.
	 */
	public function test_abuse_ipdb(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'rep',
						'abuse_ipdb',
						array(
							'threshold'    => 60,
							'api_key'      => 'honoured-test-key',
							'cache_ttl'    => 7200,
							'timeout'      => 3,
							'max_age_days' => 7,
						)
					),
				),
			)
		);

		$plugin   = $this->plugin_named( $firewall, 'rep' );
		$provider = self::invoke( $plugin, 'provider' );

		$this->assertSame( 60.0, (float) self::invoke( $plugin, 'threshold' ) );
		$this->assertSame( 7200, self::invoke( $plugin, 'cacheTtl' ) );
		$this->assertSame( 'honoured-test-key', self::invoke( $provider, 'apiKey' ) );
		$this->assertSame( 3.0, (float) self::invoke( $provider, 'timeout' ) );
		$this->assertSame( 7, self::invoke( $provider, 'maxAgeInDays' ), 'The report age is not the one configured.' );
	}

	/**
	 * The Core Rule Set's mode, paranoia, thresholds and exclusions.
	 *
	 * The threshold is proved by behaviour as well as read back: raised far
	 * enough, an injection that scores well above the default must stop
	 * matching. When the compiler wrote `anomaly_threshold` it did not.
	 */
	public function test_crs(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'crs-default', 'crs', array( 'mode' => 'block' ) ),
					$this->rule(
						'crs-tolerant',
						'crs',
						array(
							'mode'     => 'block',
							'inbound'  => 1000,
							'outbound' => 900,
						)
					),
					$this->rule( 'crs-monitor', 'crs', array( 'mode' => 'monitor' ) ),
					$this->rule(
						'crs-tuned',
						'crs',
						array(
							'mode'                => 'block',
							'paranoia'            => 3,
							'disabled_rules'      => "942100\n942190",
							'disabled_categories' => 'protocol-attack',
						)
					),
				),
			)
		);

		$attack = static fn (): Request => self::request( self::ATTACK );

		$this->assertTrue( (bool) $this->plugin_named( $firewall, 'crs-default' )->evaluate( $attack() ), 'The injection should score over the default threshold.' );
		$this->assertFalse( (bool) $this->plugin_named( $firewall, 'crs-tolerant' )->evaluate( $attack() ), 'A threshold of 1000 was not applied.' );
		$this->assertSame(
			array(
				'inbound'  => 1000,
				'outbound' => 900,
			),
			self::invoke( $this->plugin_named( $firewall, 'crs-tolerant' ), 'anomalyThresholds' )
		);
		$this->assertFalse( (bool) $this->plugin_named( $firewall, 'crs-monitor' )->evaluate( $attack() ), 'Monitor mode rejected a request.' );

		$config = self::property( self::invoke( $this->plugin_named( $firewall, 'crs-tuned' ), 'getEngine' ), 'crsConfig' );

		$this->assertSame( 3, self::property( $config, 'paranoia' ) );
		$this->assertSame( array( 942100, 942190 ), self::property( $config, 'disabledRules' ) );
		$this->assertSame( array( 'protocol-attack' ), self::property( $config, 'disabledCategories' ) );
	}

	/**
	 * Any versus all, on one type.
	 *
	 * @param string               $type     Rule type.
	 * @param array<string, mixed> $extra    Other settings.
	 * @param array<string, mixed> $matches  A condition the matching request meets.
	 * @param Request              $hit      A request meeting it.
	 * @param Request              $miss     A request that does not.
	 */
	private function assert_match_type( string $type, array $extra, array $matches, Request $hit, Request $miss ): void {
		$never = self::condition( 'ip_address' === $type ? 'ip' : $matches['variable'], 'equals', 'never-this-value-' . $type );

		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'any-' . $type,
						$type,
						$extra + array(
							'match_type' => 'any',
							'conditions' => array( $matches, $never ),
						)
					),
					$this->rule(
						'all-' . $type,
						$type,
						$extra + array(
							'match_type' => 'all',
							'conditions' => array( $matches, $never ),
						)
					),
				),
			)
		);

		$any = $this->plugin_named( $firewall, 'any-' . $type );
		$all = $this->plugin_named( $firewall, 'all-' . $type );

		$this->assertTrue( (bool) $any->evaluate( $hit ), "An \"any\" $type rule did not match on the one condition that holds." );
		$this->assertFalse( (bool) $any->evaluate( $miss ), "An \"any\" $type rule matched a request meeting none of its conditions." );
		$this->assertFalse( (bool) $all->evaluate( $hit ), "An \"all\" $type rule matched with one condition failing." );
	}

	/**
	 * A variable a source can feed, per type.
	 *
	 * @param string $type Rule type.
	 */
	private function source_variable( string $type ): string {
		return array(
			'user_agent'  => 'bot.name',
			'url'         => 'path',
			'asn'         => 'asn',
			'edge_signal' => 'ja4',
			'geolocation' => 'country',
		)[ $type ] ?? '';
	}

	/**
	 * A compiled plugin entry by rule id.
	 *
	 * @param string $id Rule id.
	 *
	 * @return array<string, mixed>
	 */
	private function compiled_rule( string $id ): array {
		foreach ( (array) ( $this->compiled['plugins'] ?? array() ) as $entry ) {
			$name = (string) ( $entry['metadata']['name'] ?? '' );

			if ( $name === $id ) {
				return $entry;
			}
		}

		$this->fail( "Rule $id was not compiled." );
	}
}
