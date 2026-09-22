<?php
/**
 * What a rule type must be able to do.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

/**
 * One kind of rule: how it is configured, validated, compiled and described.
 *
 * The translation of the module's plugin attribute discovery. Drupal finds
 * these by scanning for an attribute; WordPress has no discovery, so they are
 * registered into a registry and third parties add their own through the
 * `basic_firewall_rule_types` filter.
 *
 * A type owns its own `settings` sub-tree end to end -- default, validate,
 * compile, summarise, and declare which of its settings are credentials. That
 * last one is why the exporter never needs to know a type exists in order to
 * redact its API key.
 */
interface Rule_Type {

	/**
	 * Machine name, stored in the rule's `type` field.
	 */
	public function id(): string;

	/**
	 * Human-readable name, shown in the rule type chooser.
	 */
	public function label(): string;

	/**
	 * One or two sentences on what this matches.
	 */
	public function description(): string;

	/**
	 * The library plugin class this compiles to.
	 *
	 * Returned as a class-string from a `::class` constant, never a quoted
	 * string, so a scoped build rewrites it. A string here compiles to a class
	 * name that no longer exists, which the library skips silently.
	 *
	 * @return class-string
	 */
	public function library_class(): string;

	/**
	 * Where this type sorts in the chooser. Lower is earlier.
	 */
	public function weight(): int;

	/**
	 * Responses this type can produce.
	 *
	 * @return list<string>
	 */
	public function allowed_responses(): array;

	/**
	 * Whether the shared status code metadata applies to this type.
	 *
	 * False for the types that read a status code out of their own
	 * configuration -- writing the shared one would advertise a value the
	 * library plugin ignores.
	 */
	public function supports_shared_status_code(): bool;

	/**
	 * Whether the shared expiration metadata applies to this type.
	 */
	public function supports_shared_expiration(): bool;

	/**
	 * Whether this type can take its match list from an imported source.
	 */
	public function supports_sources(): bool;

	/**
	 * Presentation for individual settings keys.
	 *
	 * Keyed by settings key, each entry optionally carrying `label`,
	 * `description` and `choices`. Anything absent falls back to what the rule
	 * screen can derive from the default value, which is a humanised key and a
	 * control picked from the type -- adequate for `addresses`, and not for a
	 * field whose whole meaning is in what it does rather than what it holds.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function settings_help(): array;

	/**
	 * The settings a new rule of this type starts with.
	 *
	 * @return array<string, mixed>
	 */
	public function default_settings(): array;

	/**
	 * Coerce and validate submitted settings.
	 *
	 * Returns the cleaned settings. Problems are appended to $errors as
	 * `field => message`, which the rule screen renders against the field.
	 *
	 * @param array<string, mixed>  $settings Raw settings.
	 * @param array<string, string> $errors   Collected problems, by reference.
	 *
	 * @return array<string, mixed>
	 */
	public function validate_settings( array $settings, array &$errors ): array;

	/**
	 * Compile one rule into a library plugin entry.
	 *
	 * @param array<string, mixed> $rule The whole rule, settings included.
	 *
	 * @return array<string, mixed>
	 */
	public function compile( array $rule ): array;

	/**
	 * A short description of what this rule is currently configured to do.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return list<string>
	 */
	public function summarize( array $settings ): array;

	/**
	 * Anything that would stop this rule working, as human-readable strings.
	 *
	 * Used by the rule screen and by Site Health. A missing MaxMind database or
	 * an absent library class belongs here.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return list<string>
	 */
	public function check_requirements( array $settings ): array;

	/**
	 * Which of this type's settings are credentials.
	 *
	 * Keys within the rule's `settings`, dotted for nesting. The exporter reads
	 * this to decide what to strip, which is what lets a type contributed by
	 * another plugin have its API key redacted without the exporter knowing the
	 * type exists.
	 *
	 * @return list<string>
	 */
	public function secret_settings(): array;

	/**
	 * Whether the installed library can actually provide this type.
	 *
	 * The library's documentation has historically run ahead of its releases, so
	 * a type whose plugin class is absent is not offered and its screen 404s
	 * rather than saving a rule that compiles to nothing.
	 */
	public function is_available(): bool;
}
