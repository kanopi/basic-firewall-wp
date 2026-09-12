<?php
/**
 * The security invariants around credentials.
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
 * Non-negotiable behaviours 1 to 5, each with a test that fails if it regresses.
 *
 * @covers \Kanopi\BasicFirewall\Transfer\Exporter
 * @covers \Kanopi\BasicFirewall\Transfer\Importer
 * @covers \Kanopi\BasicFirewall\Transfer\Secret_Paths
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 */
final class CredentialHandlingTest extends Settings_Snapshot {

	/**
	 * A recognisable value, so a leak is unambiguous in an assertion failure.
	 */
	private const TURNSTILE_SECRET = 'SECRET-turnstile-must-never-leak';

	/**
	 * Another one.
	 */
	private const ABUSEIPDB_KEY = 'SECRET-abuseipdb-must-never-leak';

	/**
	 * And the signing secret.
	 */
	private const CHALLENGE_SECRET = 'SECRET-challenge-must-never-leak';

	/**
	 * A settings document carrying one of everything sensitive.
	 *
	 * @return array<string, mixed>
	 */
	private function document_with_credentials(): array {
		return array(
			'challenge' => array(
				'provider'         => 'turnstile',
				'secret'           => self::CHALLENGE_SECRET,
				'provider_options' => array(
					'turnstile' => array(
						'site_key'   => 'PUBLIC-site-key',
						'secret_key' => self::TURNSTILE_SECRET,
					),
				),
			),
			'storage'   => array(
				'backend'  => 'database',
				'database' => array(
					'connection_source' => 'wordpress',
					'storage_table'     => 'basic_firewall_blocked',
					'offenses_table'    => 'basic_firewall_offenses',
				),
			),
			'rules'     => array(
				array(
					'id'       => 'reputation',
					'type'     => 'abuse_ipdb',
					'label'    => 'IP reputation',
					'enabled'  => true,
					'response' => 'block',
					'weight'   => 20,
					'settings' => array(
						'threshold' => 75,
						'api_key'   => self::ABUSEIPDB_KEY,
						'cache_ttl' => 86400,
					),
				),
			),
		);
	}

	/**
	 * 1. Exports strip credentials and list what was removed.
	 */
	public function test_export_strips_credentials_and_names_them(): void {
		$this->given_settings( $this->document_with_credentials() );

		$export = ( new Exporter() )->export();
		$yaml   = ( new Exporter() )->to_yaml();

		foreach ( array( self::CHALLENGE_SECRET, self::TURNSTILE_SECRET, self::ABUSEIPDB_KEY ) as $secret ) {
			$this->assertStringNotContainsString(
				$secret,
				$yaml,
				'A credential reached the exported document.'
			);
		}

		// And the export says what it removed, rather than dropping it silently.
		$this->assertContains( 'challenge.secret', $export['redacted'] );
		$this->assertContains( 'challenge.provider_options.turnstile.secret_key', $export['redacted'] );
		$this->assertContains( 'rules.0.settings.api_key', $export['redacted'] );

		foreach ( $export['redacted'] as $path ) {
			$this->assertStringContainsString( $path, $yaml, 'The header must name every redacted path.' );
		}
	}

	/**
	 * A public site key is not a credential and must survive.
	 *
	 * Redacting it would protect nothing -- it is rendered into the page source
	 * -- and would break the receiving site's challenge.
	 */
	public function test_export_keeps_public_site_keys(): void {
		$this->given_settings( $this->document_with_credentials() );

		$this->assertStringContainsString( 'PUBLIC-site-key', ( new Exporter() )->to_yaml() );
	}

	/**
	 * 2. `%env(NAME)%` tokens are references, not secrets, and survive intact.
	 */
	public function test_env_tokens_survive_an_export(): void {
		$this->given_settings(
			array(
				'challenge' => array(
					'provider'         => 'turnstile',
					'secret'           => '%env(FIREWALL_CHALLENGE_SECRET)%',
					'provider_options' => array(
						'turnstile' => array(
							'site_key'   => 'PUBLIC-site-key',
							'secret_key' => '%env(TURNSTILE_SECRET_KEY)%',
						),
					),
				),
			)
		);

		$export = ( new Exporter() )->export();
		$yaml   = ( new Exporter() )->to_yaml();

		$this->assertStringContainsString( '%env(FIREWALL_CHALLENGE_SECRET)%', $yaml );
		$this->assertStringContainsString( '%env(TURNSTILE_SECRET_KEY)%', $yaml );

		$this->assertNotContains( 'challenge.secret', $export['redacted'], 'A token names a variable; it is not a secret to strip.' );
	}

	/**
	 * A %file() token is a reference too.
	 */
	public function test_file_tokens_survive_an_export(): void {
		$this->given_settings(
			array( 'challenge' => array( 'secret' => '%file(/run/secrets/firewall)%' ) )
		);

		$this->assertStringContainsString( '%file(/run/secrets/firewall)%', ( new Exporter() )->to_yaml() );
	}

	/**
	 * 3. An empty credential on import means "not carried", never "set to nothing".
	 *
	 * This is the direction that does damage. A stripped export written over a
	 * receiving site would erase its challenge secret -- and a firewall that
	 * cannot start fails open, so every rule silently stops being enforced while
	 * the interface goes on reporting "Blocking".
	 */
	public function test_import_never_blanks_an_existing_credential(): void {
		$this->given_settings( $this->document_with_credentials() );

		// A stripped export, exactly as it would arrive from another site.
		$stripped = ( new Exporter() )->to_yaml();

		$result = ( new Importer() )->import( $stripped, 'merge' );

		$this->assertTrue( $result['ok'], (string) $result['error'] );

		$settings = Plugin::instance()->settings();
		$settings->flush();

		$this->assertSame(
			self::CHALLENGE_SECRET,
			$settings->get( 'challenge.secret' ),
			'Importing a stripped export erased the challenge secret. The firewall would now fail open.'
		);

		$this->assertSame(
			self::TURNSTILE_SECRET,
			$settings->get( 'challenge.provider_options.turnstile.secret_key' )
		);

		$rules = (array) $settings->get( 'rules', array() );

		$this->assertSame( self::ABUSEIPDB_KEY, $rules[0]['settings']['api_key'] );
	}

	/**
	 * The same protection applies in replace mode.
	 *
	 * Replace is the mode somebody chooses when they mean "use this document
	 * instead of what I have", which makes it the one most likely to be reached
	 * for with a stripped export in hand.
	 */
	public function test_replace_mode_also_preserves_credentials(): void {
		$this->given_settings( $this->document_with_credentials() );

		$stripped = ( new Exporter() )->to_yaml();
		$result   = ( new Importer() )->import( $stripped, 'replace' );

		$this->assertTrue( $result['ok'], (string) $result['error'] );

		Plugin::instance()->settings()->flush();

		$this->assertSame(
			self::CHALLENGE_SECRET,
			Plugin::instance()->settings()->get( 'challenge.secret' )
		);
	}

	/**
	 * An import that does carry a credential still sets it.
	 *
	 * The guard must preserve, not freeze. A site legitimately rotating a key
	 * through an import has to be able to.
	 */
	public function test_import_applies_a_credential_that_is_present(): void {
		$this->given_settings( $this->document_with_credentials() );

		$document = "basic_firewall:\n  settings:\n    challenge:\n      secret: 'ROTATED-secret'\n";

		$result = ( new Importer() )->import( $document, 'merge' );

		$this->assertTrue( $result['ok'], (string) $result['error'] );

		Plugin::instance()->settings()->flush();

		$this->assertSame( 'ROTATED-secret', Plugin::instance()->settings()->get( 'challenge.secret' ) );
	}

	/**
	 * 4. Database credentials are never written into the compiled file.
	 *
	 * They are injected at request time instead, which is also what makes a
	 * rotated password take effect immediately rather than at the next rebuild.
	 */
	public function test_database_credentials_never_reach_the_compiled_file(): void {
		$this->given_settings( $this->document_with_credentials() );

		$rebuild = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $rebuild['written'], 'The compiled file was not written.' );

		$contents = (string) Plugin::instance()->compiled()->contents();

		$this->assertNotSame( '', $contents );

		/*
		 * Asserted structurally rather than by searching for the password's
		 * literal value.
		 *
		 * The first version of this test looked for DB_PASSWORD in the output.
		 * On the DDEV site it runs against, that password is the two-character
		 * string "db" -- which appears inside "abuse_ipdb", and inside the word
		 * "and" nowhere but inside plenty of others. The test failed on a file
		 * containing no credentials at all, and on a site whose password
		 * happened to be "a" it would have failed on everything forever.
		 *
		 * The inverse is worse: a site with a long random password makes the
		 * search pass trivially, so it would have gone green while proving
		 * nothing about a *different* credential being leaked.
		 *
		 * What actually matters is that no connection block is emitted at all,
		 * which is a property of the compiler rather than of this site's
		 * password. That is what is asserted.
		 */
		$this->assertStringNotContainsString(
			'connection:',
			$contents,
			'A connection block reached the compiled file; credentials must be injected at runtime instead.'
		);

		$this->assertStringNotContainsString(
			'dbname:',
			$contents,
			'A database name reached the compiled file, which means a connection block did too.'
		);

		$this->assertLiteralPasswordAbsent( $contents );

		// And the table names, which are not secret, are present.
		$this->assertStringContainsString( 'storage_table:', $contents );

		// The injection path was recorded for the runner.
		$this->assertContains(
			'[storage][config][connection]',
			Plugin::instance()->compiled()->connection_paths(),
			'The compiler must record where the runner injects credentials.'
		);
	}

	/**
	 * 5. Credentials never reach CLI or screen output.
	 *
	 * Checked here on the exporter's rendered document, which is what the export
	 * screen shows and what `wp basic-firewall export` writes to stdout.
	 */
	public function test_rendered_export_is_safe_to_paste_into_a_ticket(): void {
		$this->given_settings( $this->document_with_credentials() );

		$yaml = ( new Exporter() )->to_yaml();

		foreach ( array( self::CHALLENGE_SECRET, self::TURNSTILE_SECRET, self::ABUSEIPDB_KEY ) as $secret ) {
			$this->assertStringNotContainsString( $secret, $yaml );
		}

		$this->assertStringNotContainsString( 'connection:', $yaml );

		/*
		 * Asserted by parsing rather than by string matching.
		 *
		 * An earlier version asserted the document contained no "password:" at
		 * all, and failed -- correctly, in the sense that the string was there,
		 * and wrongly, in the sense that it was `password: ''`. An empty
		 * credential key is not a leak, and it is not even untidy: the schema
		 * has the field, so the document has the key, and the importer's rule is
		 * that an empty credential means "not carried". Removing the key and
		 * emptying it behave identically on import.
		 *
		 * What has to be true is semantic -- every secret-bearing path is absent,
		 * empty, or a token -- so that is what is checked.
		 */
		$parsed   = Yaml::parse( $yaml );
		$document = $parsed['basic_firewall']['settings'] ?? array();

		$this->assertIsArray( $document );

		foreach ( Secret_Paths::in( $document ) as $path ) {
			$value = Secret_Paths::get( $document, $path );

			$this->assertTrue(
				null === $value || '' === $value || Secret_Paths::is_token( $value ),
				sprintf( 'The export carries a live credential at %s.', $path )
			);
		}

		$this->assertLiteralPasswordAbsent( $yaml );
	}

	/**
	 * Assert the site's real database password is absent, where that is meaningful.
	 *
	 * A short or dictionary-word password makes a substring search useless in
	 * both directions -- it fails on output containing no credentials, and it
	 * passes trivially on a site with a long random one. So the check runs only
	 * when the value is distinctive enough for the result to mean something,
	 * and says so out loud when it is skipped rather than reporting a pass
	 * nobody has earned.
	 *
	 * @param string $output Rendered output to search.
	 */
	private function assertLiteralPasswordAbsent( string $output ): void {
		$password = defined( 'DB_PASSWORD' ) ? (string) constant( 'DB_PASSWORD' ) : '';

		if ( strlen( $password ) < 12 ) {
			$this->addWarning(
				sprintf(
					'Literal password search skipped: this site\'s DB_PASSWORD is %d characters, too short for a substring search to prove anything. The structural assertions above still ran.',
					strlen( $password )
				)
			);

			return;
		}

		$this->assertStringNotContainsString( $password, $output, 'The database password reached the output.' );
	}

	/**
	 * A per-rule export is redacted the same way.
	 *
	 * The rule listing offers this even for a rule whose type this site cannot
	 * render, which makes it the export most likely to be pasted into a ticket.
	 */
	public function test_single_rule_export_is_redacted(): void {
		$this->given_settings( $this->document_with_credentials() );

		$yaml = ( new Exporter() )->rule_to_yaml( 'reputation' );

		$this->assertIsString( $yaml );
		$this->assertStringNotContainsString( self::ABUSEIPDB_KEY, (string) $yaml );
		$this->assertStringContainsString( 'rules.0.settings.api_key', (string) $yaml );
	}
}
