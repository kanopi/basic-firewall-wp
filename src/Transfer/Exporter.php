<?php
/**
 * Produces a portable configuration document.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Transfer;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;
use Symfony\Component\Yaml\Yaml;

/**
 * Exports the rule set as something safe to hand to somebody else.
 *
 * Drupal gets `drush config:export` for moving configuration between
 * environments of the same site. WordPress has no equivalent at all, so this is
 * not a convenience here -- **it is the deployment story**, and it carries more
 * weight than the module's does rather than less.
 *
 * **Credentials are stripped, and the document says which.** Not silently: an
 * export that quietly dropped an API key would be discovered by the person
 * importing it, at the point the rule stopped working, with no indication why.
 * The header names every path that was removed.
 *
 * **A token is not a secret.** `%env(ABUSEIPDB_API_KEY)%` names an environment
 * variable rather than holding one, so it survives intact -- stripping it would
 * break the receiving site and protect nothing.
 */
final class Exporter {

	/**
	 * Export the current settings.
	 *
	 * @return array{document: array<string, mixed>, redacted: list<string>}
	 */
	public function export(): array {
		return $this->export_document( Plugin::instance()->settings()->all() );
	}

	/**
	 * Export one rule.
	 *
	 * Offered even for a rule whose type this site cannot render -- that is
	 * exactly the rule somebody wants to hand to a site that can.
	 *
	 * @param string $id Rule identifier.
	 *
	 * @return array{document: array<string, mixed>, redacted: list<string>}|null
	 */
	public function export_rule( string $id ): ?array {
		foreach ( (array) Plugin::instance()->settings()->get( 'rules', array() ) as $rule ) {
			if ( is_array( $rule ) && (string) ( $rule['id'] ?? '' ) === $id ) {
				return $this->export_document( array( 'rules' => array( $rule ) ) );
			}
		}

		return null;
	}

	/**
	 * Strip credentials from a document and record what went.
	 *
	 * @param array<string, mixed> $document Settings document.
	 *
	 * @return array{document: array<string, mixed>, redacted: list<string>}
	 */
	private function export_document( array $document ): array {
		$redacted = array();

		foreach ( Secret_Paths::in( $document ) as $path ) {
			$value = Secret_Paths::get( $document, $path );

			if ( null === $value || '' === $value ) {
				// Nothing there to redact. Saying so would be noise.
				continue;
			}

			if ( Secret_Paths::is_token( $value ) ) {
				// A reference, not a value. It travels.
				continue;
			}

			/*
			 * Removed rather than emptied. An empty string in the document
			 * would be indistinguishable from "the sending site had none", and
			 * the importer's rule is that an empty credential means "not
			 * carried" -- so both spellings behave the same on import. Removing
			 * is the honest one: the key is simply not present.
			 */
			Secret_Paths::unset_at( $document, $path );

			$redacted[] = $path;
		}

		return array(
			'document' => $document,
			'redacted' => $redacted,
		);
	}

	/**
	 * Render an export as YAML, with the header.
	 *
	 * @return string
	 */
	public function to_yaml(): string {
		$export = $this->export();

		return $this->render( $export['document'], $export['redacted'] );
	}

	/**
	 * Render one rule as YAML.
	 *
	 * @param string $id Rule identifier.
	 */
	public function rule_to_yaml( string $id ): ?string {
		$export = $this->export_rule( $id );

		return null === $export ? null : $this->render( $export['document'], $export['redacted'] );
	}

	/**
	 * Build the document text.
	 *
	 * @param array<string, mixed> $document Redacted document.
	 * @param list<string>         $redacted Paths that were removed.
	 */
	private function render( array $document, array $redacted ): string {
		$header = "# Basic Firewall configuration export\n"
			. '# Exported ' . gmdate( 'c' ) . "\n"
			. '# Plugin version ' . BASIC_FIREWALL_VERSION . "\n"
			. '# Schema version ' . Schema::VERSION . "\n#\n";

		if ( array() === $redacted ) {
			$header .= "# No credentials were found in this configuration, so none were removed.\n";
		} else {
			$header .= "# The following credentials were REMOVED from this export and are not\n"
				. "# included below. The receiving site keeps whatever it already has for\n"
				. "# these -- importing this document will not blank them -- but a site that\n"
				. "# has none will need them supplied by hand.\n#\n";

			foreach ( $redacted as $path ) {
				$header .= '#   - ' . $path . "\n";
			}

			$header .= "#\n# An %env(NAME)% or %file(/path)% token is a reference rather than a\n"
				. "# secret, so any of those were left intact.\n";
		}

		$payload = array(
			'basic_firewall' => array(
				'schema_version' => Schema::VERSION,
				'exported'       => gmdate( 'c' ),
				'redacted'       => $redacted,
				'settings'       => $document,
			),
		);

		return $header . "\n" . Yaml::dump( $payload, 12, 2, Yaml::DUMP_MULTI_LINE_LITERAL_BLOCK );
	}
}
