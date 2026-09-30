<?php
/**
 * Credentials in the Advanced screen's YAML.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Transfer\Advanced_Yaml_Secrets;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * What counts as a credential there, and the placeholder round trip (#47).
 *
 * @covers \Kanopi\BasicFirewall\Transfer\Advanced_Yaml_Secrets
 */
final class AdvancedYamlSecretsTest extends TestCase {

	/**
	 * A document with a credential of every shape the rule recognises.
	 */
	private const DOCUMENT = <<<'YAML'
# Redis for the block list.
storage:
  config:
    redis:
      host: redis.internal
      port: 6380
      auth: s3cret-redis-pass # the requirepass
      prefix: site1:
plugins:
  - type: ratelimit
    metadata:
      default_key: [client_ip, path]
      storage:
        config:
          redis:
            host: redis.internal
            auth: [acl-user, acl-pass-9876]
  - type: reputation
    metadata:
      api_key: "abuse-key-1234567"
      cookie_name: bfw_pass
      token_ttl: 300
      site_key: public-site-key
      sources:
        - url: https://feed-user:feed-pass-4444@lists.example/feed?format=txt&token=qtok-5555
          upstream:
            headers:
              Authorization: Bearer hdr-6666
              X-Frame-Options: DENY
            auth:
              type: bearer
              token: '%env(FEED_TOKEN)%'
logger:
  dsn: 'mysql:host=db;dbname=logs;password=dsn-pass-7777'
challenge:
  secret: '%env(CHALLENGE_SECRET)%'
YAML;

	/**
	 * Every credential, and nothing else, is found.
	 */
	public function test_the_rule_finds_credentials_and_leaves_the_rest(): void {
		$this->assertSame(
			array(
				'storage.config.redis.auth',
				'plugins.0.metadata.storage.config.redis.auth.0',
				'plugins.0.metadata.storage.config.redis.auth.1',
				'plugins.1.metadata.api_key',
				'plugins.1.metadata.sources.0.url',
				'plugins.1.metadata.sources.0.upstream.headers.Authorization',
				'logger.dsn',
			),
			Advanced_Yaml_Secrets::paths( self::DOCUMENT )
		);
	}

	/**
	 * The masked text keeps comments and layout, shows tokens, and holds no credential.
	 */
	public function test_masking_keeps_the_text_and_drops_every_credential(): void {
		$masked = Advanced_Yaml_Secrets::mask( self::DOCUMENT );

		foreach ( array( 's3cret-redis-pass', 'acl-pass-9876', 'abuse-key-1234567', 'feed-pass-4444', 'qtok-5555', 'hdr-6666', 'dsn-pass-7777' ) as $secret ) {
			$this->assertStringNotContainsString( $secret, $masked['text'] );
		}

		$this->assertStringContainsString( '# Redis for the block list.', $masked['text'], 'The comments went.' );
		$this->assertStringContainsString( '# the requirepass', $masked['text'] );
		$this->assertStringContainsString( '%env(FEED_TOKEN)%', $masked['text'] );
		$this->assertStringContainsString( '%env(CHALLENGE_SECRET)%', $masked['text'] );
		$this->assertStringContainsString( 'https://feed-user:[redacted]@lists.example/feed?format=txt&token=[redacted]', $masked['text'], 'Only the credential in a URL is masked.' );
		$this->assertStringContainsString( 'password=[redacted]', $masked['text'] );
		$this->assertStringContainsString( 'cookie_name: bfw_pass', $masked['text'] );
		$this->assertStringContainsString( 'X-Frame-Options: DENY', $masked['text'] );
		$this->assertStringContainsString( 'site_key: public-site-key', $masked['text'] );
		$this->assertCount( 7, $masked['redacted'] );
	}

	/**
	 * Posting back exactly what was shown stores exactly what was there.
	 */
	public function test_the_masked_text_posted_back_restores_the_original(): void {
		$masked   = Advanced_Yaml_Secrets::mask( self::DOCUMENT );
		$restored = Advanced_Yaml_Secrets::restore( $masked['text'], self::DOCUMENT );

		$this->assertTrue( $restored['ok'] );
		$this->assertSame( self::DOCUMENT, $restored['text'] );
	}

	/**
	 * An edit elsewhere in the document still restores the credentials.
	 */
	public function test_an_unrelated_edit_keeps_the_credentials(): void {
		$masked = Advanced_Yaml_Secrets::mask( self::DOCUMENT );
		$edited = str_replace( 'prefix: site1:', 'prefix: site2:', $masked['text'] );

		$restored = Advanced_Yaml_Secrets::restore( $edited, self::DOCUMENT );

		$this->assertTrue( $restored['ok'] );
		$this->assertSame( str_replace( 'prefix: site1:', 'prefix: site2:', self::DOCUMENT ), $restored['text'] );
	}

	/**
	 * A placeholder that moved cannot be restored, and says where.
	 */
	public function test_a_moved_placeholder_is_refused(): void {
		$masked = Advanced_Yaml_Secrets::mask( self::DOCUMENT );
		$edited = str_replace( "      auth: '[redacted]'", "      password: '[redacted]'", $masked['text'] );

		$restored = Advanced_Yaml_Secrets::restore( $edited, self::DOCUMENT );

		$this->assertFalse( $restored['ok'] );
		$this->assertSame( array( 'storage.config.redis.password' ), $restored['unrestored'] );
	}

	/**
	 * Pointing the connection somewhere else does not carry its password there.
	 */
	public function test_a_changed_host_is_refused(): void {
		$masked = Advanced_Yaml_Secrets::mask( "redis:\n  host: a.internal\n  auth: pw-123456\n" );
		$edited = str_replace( 'a.internal', 'b.internal', $masked['text'] );

		$restored = Advanced_Yaml_Secrets::restore( $edited, "redis:\n  host: a.internal\n  auth: pw-123456\n" );

		$this->assertFalse( $restored['ok'] );
		$this->assertSame( array( 'redis.auth' ), $restored['unrestored'] );
	}

	/**
	 * A URL edited around its placeholder is refused rather than stored.
	 */
	public function test_an_edited_url_is_refused(): void {
		$masked = Advanced_Yaml_Secrets::mask( self::DOCUMENT );
		$edited = str_replace( '@lists.example/', '@evil.example/', $masked['text'] );

		$this->assertFalse( Advanced_Yaml_Secrets::restore( $edited, self::DOCUMENT )['ok'] );
	}

	/**
	 * The placeholder typed without quotes is still the placeholder.
	 */
	public function test_an_unquoted_placeholder_is_recognised(): void {
		$stored   = "redis:\n  host: a\n  auth: pw-123456\n";
		$restored = Advanced_Yaml_Secrets::restore( "redis:\n  host: a\n  auth: [redacted]\n", $stored );

		$this->assertTrue( $restored['ok'] );
		$this->assertSame( $stored, $restored['text'] );
	}

	/**
	 * An import drops what it cannot restore, rather than storing the placeholder.
	 */
	public function test_an_import_drops_what_it_cannot_restore(): void {
		$restored = Advanced_Yaml_Secrets::restore( "redis:\n  host: a\n  auth: '[redacted]'\n", '', true );

		$this->assertTrue( $restored['ok'] );
		$this->assertSame( array( 'redis.auth' ), $restored['unrestored'] );
		$this->assertSame( array( 'redis' => array( 'host' => 'a' ) ), Yaml::parse( $restored['text'] ) );
	}

	/**
	 * A credential repeated in a comment falls back to a dump, never shown.
	 */
	public function test_a_credential_in_a_comment_is_not_shown(): void {
		$masked = Advanced_Yaml_Secrets::mask( "# old password was pw-123456\nredis:\n  auth: pw-123456\n" );

		$this->assertStringNotContainsString( 'pw-123456', $masked['text'] );
		$this->assertSame( array( 'redis' => array( 'auth' => '[redacted]' ) ), Yaml::parse( $masked['text'] ) );
	}

	/**
	 * A bare `key` is a rate limit's key, not a credential.
	 */
	public function test_a_bare_key_is_not_a_credential(): void {
		$this->assertSame( array(), Advanced_Yaml_Secrets::paths( "plugins:\n  - metadata:\n      rules:\n        - key: [client_ip]\n          cache_key: abc\n          public_key: xyz\n" ) );
	}

	/**
	 * A document with nothing to hide is returned untouched.
	 */
	public function test_a_document_without_credentials_is_untouched(): void {
		$yaml = "# nothing here\nglobal:\n  mode: observe\n";

		$this->assertSame( $yaml, Advanced_Yaml_Secrets::mask( $yaml )['text'] );
		$this->assertSame( $yaml, Advanced_Yaml_Secrets::restore( $yaml, '' )['text'] );
	}
}
