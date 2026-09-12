<?php
/**
 * The schema's shipped defaults and its secret declarations.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Support\Schema;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Kanopi\BasicFirewall\Support\Schema
 */
final class SchemaTest extends TestCase {

	/**
	 * A fresh install must not block anything.
	 *
	 * This is the single most important default in the plugin. A firewall that
	 * starts blocking the moment it is activated can make a site unreachable
	 * before its owner has seen a single screen, and the person best placed to
	 * fix it is the one who has just been locked out.
	 */
	public function test_ships_in_log_only_mode_with_no_rules(): void {
		$defaults = Schema::defaults();

		$this->assertSame( 'log', $defaults['global']['mode'], 'A new install must observe traffic, not block it.' );
		$this->assertSame( array(), $defaults['rules'], 'A new install must ship no rules.' );
		$this->assertSame( array(), $defaults['presets'], 'A new install must ship no presets enabled.' );
		$this->assertSame( array(), $defaults['global']['bypass_roles'], 'No role may be exempt by default.' );
	}

	/**
	 * "Nobody has answered" and "there is no proxy" are different answers.
	 *
	 * Defaulting this to a silent "no" would answer an open security question on
	 * the administrator's behalf, in the direction that hides it: it silences
	 * the warning that an unconfigured proxy makes every IP rule forgeable.
	 */
	public function test_proxy_question_defaults_to_unanswered(): void {
		$defaults = Schema::defaults();

		$this->assertSame( 'unknown', $defaults['global']['behind_proxy'] );

		$choices = Schema::definition()['children']['global']['children']['behind_proxy']['choices'];

		$this->assertContains( 'unknown', $choices );
		$this->assertContains( 'no', $choices );
		$this->assertContains( 'yes', $choices );
	}

	/**
	 * A configuration that fails to load must be reported, not absorbed.
	 *
	 * The library loads leniently, so a broken compiled file yields an empty
	 * ruleset that allows everything and looks exactly like a working firewall.
	 */
	public function test_defaults_to_reporting_a_configuration_that_fails_to_load(): void {
		$this->assertTrue( Schema::defaults()['global']['require_config'] );
	}

	/**
	 * Debug logging costs ~100 KB per allowed request. It is never the default.
	 */
	public function test_log_handler_defaults_to_warning_not_debug(): void {
		$definition = Schema::definition();
		$handler    = $definition['children']['logger']['of'];

		$this->assertSame( 'warning', $handler['children']['level']['default'] );
	}

	/**
	 * Every credential in the schema is declared as one.
	 *
	 * The exporter reads these declarations rather than a hand-maintained list,
	 * so this test is what makes "a new secret field is redacted the day it is
	 * added" true rather than aspirational.
	 */
	public function test_every_credential_is_declared_secret(): void {
		$secrets = Schema::secret_paths();

		$expected = array(
			'storage.database.dsn',
			'storage.database.parameters.password',
			'challenge.secret',
			'challenge.provider_options.turnstile.secret_key',
			'challenge.provider_options.recaptcha.secret_key',
			'logger.*.dsn',
			'logger.*.parameters.password',
		);

		foreach ( $expected as $path ) {
			$this->assertContains( $path, $secrets, sprintf( '%s holds a credential and must be declared secret.', $path ) );
		}
	}

	/**
	 * A site key is public and must not be redacted.
	 *
	 * Turnstile and reCAPTCHA site keys are rendered into the page source. An
	 * export that stripped them would protect nothing and would break the
	 * receiving site's challenge, which is the worst of both.
	 */
	public function test_public_site_keys_are_not_treated_as_secret(): void {
		$secrets = Schema::secret_paths();

		$this->assertNotContains( 'challenge.provider_options.turnstile.site_key', $secrets );
		$this->assertNotContains( 'challenge.provider_options.recaptcha.site_key', $secrets );
	}

	/**
	 * Zero means opposite things by response, so it is never a default.
	 */
	public function test_rule_expiration_defaults_to_an_hour_not_zero(): void {
		$rule = Schema::definition()['children']['rules']['of'];

		$this->assertSame( 3600, $rule['children']['expiration']['default'] );
	}
}
