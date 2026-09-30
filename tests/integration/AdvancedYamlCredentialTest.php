<?php
/**
 * Credentials typed into the Advanced screen's YAML.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Advanced_Screen;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Transfer\Exporter;
use Kanopi\BasicFirewall\Transfer\Importer;
use Kanopi\BasicFirewall\Transfer\Secret_Paths;
use Symfony\Component\Yaml\Yaml;

/**
 * The box shows `[redacted]`, a save keeps the value, an export strips it (#47).
 *
 * The advanced YAML is a free-form pass-through rather than a declared secret
 * path, so the redaction the rest of the plugin applies did not reach it: a
 * Redis password or an API key typed there went back into the page as typed
 * and into every export in the clear.
 *
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Advanced_Screen
 * @covers \Kanopi\BasicFirewall\Transfer\Advanced_Yaml_Secrets
 * @covers \Kanopi\BasicFirewall\Transfer\Exporter
 * @covers \Kanopi\BasicFirewall\Transfer\Importer
 */
final class AdvancedYamlCredentialTest extends Settings_Snapshot {

	use Rendered_Rule_Form;

	private const PASSWORD = 'ADV-REDIS-PASS-7c1e';
	private const HEADER   = 'ADV-HEADER-TOKEN-2b9f';

	/**
	 * A block with two literal credentials, a token and a comment.
	 */
	private const YAML = <<<'YAML'
# Kept as typed.
storage:
  config:
    redis:
      host: redis.internal
      port: 6379
      auth: ADV-REDIS-PASS-7c1e
logger:
  handlers:
    - type: http
      headers:
        Authorization: 'Bearer ADV-HEADER-TOKEN-2b9f'
challenge:
  secret: '%env(ADV_CHALLENGE_SECRET)%'
YAML;

	/**
	 * Request globals, put back after each test.
	 *
	 * @var array{get: array<mixed>, post: array<mixed>, user: int}
	 */
	private array $globals;

	/**
	 * Remember the request globals.
	 */
	protected function setUp(): void {
		parent::setUp();

		require_once ABSPATH . 'wp-admin/includes/template.php';

		$this->globals = array(
			'get'  => $_GET, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'post' => $_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'user' => get_current_user_id(),
		);

		$this->given_settings( array( 'advanced_yaml' => self::YAML ) );
	}

	/**
	 * Put them back, and drop any notices a screen queued.
	 */
	protected function tearDown(): void {
		delete_transient( 'basic_firewall_notices_' . get_current_user_id() );
		remove_all_filters( 'wp_redirect' );

		$_GET  = $this->globals['get'];
		$_POST = $this->globals['post'];
		wp_set_current_user( $this->globals['user'] );

		parent::tearDown();
	}

	/**
	 * The credentials are not in the page; the token and the comment are.
	 */
	public function test_the_box_masks_credentials_and_shows_tokens(): void {
		$fields = $this->rendered_screen_fields( new Advanced_Screen() );
		$box    = (string) ( $fields['advanced_yaml'] ?? '' );

		$this->assertStringNotContainsString( self::PASSWORD, $this->rendered_html, 'The Redis password is in the page.' );
		$this->assertStringNotContainsString( self::HEADER, $this->rendered_html, 'The header token is in the page.' );
		$this->assertStringContainsString( Secret_Paths::REDACTED, $box );
		$this->assertStringContainsString( '%env(ADV_CHALLENGE_SECRET)%', $box, 'A token is a reference, and is shown.' );
		$this->assertStringContainsString( '# Kept as typed.', $box, 'The comments were lost.' );
		$this->assertStringContainsString( 'host: redis.internal', $box );
	}

	/**
	 * Posting back exactly what was rendered stores exactly what was there.
	 */
	public function test_saving_as_rendered_keeps_the_block_unchanged(): void {
		$this->assertTrue( $this->save_screen_as_rendered( new Advanced_Screen() ), 'The screen refused its own rendering.' );

		Plugin::instance()->settings()->flush();

		$this->assertSame( self::YAML, Plugin::instance()->settings()->get( 'advanced_yaml' ) );
	}

	/**
	 * A placeholder that moved is refused, and nothing is stored.
	 */
	public function test_a_changed_placeholder_refuses_the_save(): void {
		$fields = $this->rendered_screen_fields( new Advanced_Screen() );
		$moved  = str_replace( "      auth: '[redacted]'", "      password: '[redacted]'", (string) $fields['advanced_yaml'] );

		$this->assertNotSame( $moved, $fields['advanced_yaml'], 'The fixture did not render the placeholder where expected.' );

		$this->save_screen_as_rendered( new Advanced_Screen(), array(), array( 'advanced_yaml' => $moved ) );

		Plugin::instance()->settings()->flush();

		$stored = (string) Plugin::instance()->settings()->get( 'advanced_yaml' );

		$this->assertSame( self::YAML, $stored, 'A save with an unrestorable placeholder went through.' );
		$this->assertStringNotContainsString( Secret_Paths::REDACTED, $stored );
	}

	/**
	 * A new credential typed over the placeholder is stored as typed.
	 */
	public function test_a_typed_credential_replaces_the_stored_one(): void {
		$fields = $this->rendered_screen_fields( new Advanced_Screen() );
		$typed  = str_replace( "      auth: '[redacted]'", '      auth: NEW-PASS-4d2a', (string) $fields['advanced_yaml'] );

		$this->assertTrue( $this->save_screen_as_rendered( new Advanced_Screen(), array(), array( 'advanced_yaml' => $typed ) ) );

		Plugin::instance()->settings()->flush();

		$this->assertSame( str_replace( self::PASSWORD, 'NEW-PASS-4d2a', self::YAML ), Plugin::instance()->settings()->get( 'advanced_yaml' ) );
	}

	/**
	 * An export masks the credentials and lists them.
	 */
	public function test_an_export_redacts_and_lists_the_credentials(): void {
		$yaml = ( new Exporter() )->to_yaml();

		$this->assertStringNotContainsString( self::PASSWORD, $yaml );
		$this->assertStringNotContainsString( self::HEADER, $yaml );
		$this->assertStringContainsString( '%env(ADV_CHALLENGE_SECRET)%', $yaml );
		$this->assertStringContainsString( '#   - advanced_yaml: storage.config.redis.auth', $yaml, 'The header does not name what was removed.' );
		$this->assertStringContainsString( '#   - advanced_yaml: logger.handlers.0.headers.Authorization', $yaml );

		$document = Yaml::parse( $yaml );

		$this->assertContains( 'advanced_yaml: storage.config.redis.auth', $document['basic_firewall']['redacted'] );
	}

	/**
	 * Importing this site's own export keeps its credentials.
	 */
	public function test_importing_the_export_on_the_same_site_keeps_the_block(): void {
		$result = ( new Importer() )->import( ( new Exporter() )->to_yaml() );

		$this->assertTrue( $result['ok'] );

		Plugin::instance()->settings()->flush();

		$this->assertSame( self::YAML, Plugin::instance()->settings()->get( 'advanced_yaml' ) );
	}

	/**
	 * Elsewhere, a placeholder is dropped and reported, never stored.
	 */
	public function test_importing_elsewhere_drops_the_placeholder(): void {
		$export = ( new Exporter() )->to_yaml();

		$this->given_settings( array( 'advanced_yaml' => '' ) );

		$preview = ( new Importer() )->preview( $export );
		$stored  = (string) ( $preview['result']['advanced_yaml'] ?? '' );

		$this->assertStringNotContainsString( Secret_Paths::REDACTED, $stored );
		$this->assertSame( 'redis.internal', Yaml::parse( $stored )['storage']['config']['redis']['host'] ?? null );
		$this->assertStringContainsString( 'storage.config.redis.auth', implode( "\n", $preview['summary']['credentials_withheld'] ) );
	}

	/**
	 * A document carrying a credential in its advanced YAML is kept, and named.
	 */
	public function test_an_imported_credential_is_kept_and_reported(): void {
		$this->given_settings( array( 'advanced_yaml' => '' ) );

		$document = Yaml::dump( array( 'basic_firewall' => array( 'settings' => array( 'advanced_yaml' => self::YAML ) ) ), 6, 2 );
		$preview  = ( new Importer() )->preview( $document );

		$this->assertSame( self::YAML, $preview['result']['advanced_yaml'] ?? null );
		$this->assertSame(
			array( 'storage.config.redis.auth', 'logger.handlers.0.headers.Authorization' ),
			$preview['summary']['advanced_credentials']
		);
	}
}
