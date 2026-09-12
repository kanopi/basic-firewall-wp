<?php
/**
 * The user agent rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\Firewall\Plugins\UserAgent;

/**
 * Matches on a parsed user agent rather than on the header as a string.
 *
 * The one thing to know before writing a rule here is the difference between
 * `bot` and `automated`, because it decides whether the rule stops scanners:
 *
 * | Agent                  | `bot:true` | `automated:true` |
 * |------------------------|------------|------------------|
 * | `sqlmap/1.7`           | allowed    | **blocked**      |
 * | `Nikto/2.5.0`          | allowed    | **blocked**      |
 * | `curl/8.0`             | allowed    | **blocked**      |
 * | `python-requests/2.31` | allowed    | **blocked**      |
 * | `Googlebot/2.1`        | blocked    | blocked          |
 * | iPhone Safari          | allowed    | allowed          |
 *
 * `bot` is backed by a curated database of known crawlers, which does not
 * classify scanners or generic HTTP client libraries. **A rule written as
 * `bot equals true` has been letting sqlmap and nikto straight through.**
 * `automated` is that database plus a broader crawler list, and is almost always
 * the condition somebody means.
 *
 * The rule screen says this at the point the variable is chosen, because the
 * names do not suggest it and the failure is invisible.
 */
final class User_Agent extends Condition_Rule_Type_Base {

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'user_agent';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'User agent', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Matches a parsed user agent: whether it is automated, which browser, device, operating system or brand. Parsed, not string-matched.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return UserAgent::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return -90;
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return parent::default_settings() + array(

			/*
			 * Identifying an agent means compiling a 1.7 MB pattern set -- about
			 * 618 ms the first time each PHP process does it, and every php-fpm
			 * worker pays it again after a recycle. Cached into the private
			 * directory rather than the system temporary directory, because a
			 * temp directory gets cleared and every clear costs that 618 ms
			 * again on every worker.
			 */
			'cache_detection' => true,

			/*
			 * Which list `bot` consults. Widening it changes what an existing
			 * bot rule blocks, so it is a stored choice rather than a default
			 * that moved underneath somebody.
			 */
			'bot_source'      => 'curated',
		);
	}

	/**
	 * {@inheritDoc}
	 */
	protected function variable_options(): array {
		/*
		 * Exactly the vocabulary UserAgent::getValue() understands, and no more.
		 *
		 * This list is what the validator checks a condition against, so an
		 * entry here that the library does not resolve produces a rule that
		 * saves, reports itself as active, and matches nothing -- the failure
		 * this plugin exists to prevent. There is deliberately no `user_agent`
		 * variable: the plugin matches a *parsed* agent, and the raw header is
		 * reached through a Request / URL rule on `header.user-agent` instead.
		 */
		return array(
			'automated'      => __( 'Automated — the curated bot database plus the wider crawler list. This is the one that stops scanners.', 'basic-firewall' ),
			'bot'            => __( 'Bot — the curated crawler database only. Does not classify sqlmap, nikto, curl or python-requests.', 'basic-firewall' ),
			'bot.name'       => __( 'Bot name', 'basic-firewall' ),
			'bot.category'   => __( 'Bot category — only populated by the curated database', 'basic-firewall' ),
			'bot.producer'   => __( 'Bot producer — only populated by the curated database', 'basic-firewall' ),
			'bot.url'        => __( 'Bot URL — only populated by the curated database', 'basic-firewall' ),
			'client.name'    => __( 'Client name, such as Chrome or curl', 'basic-firewall' ),
			'client.type'    => __( 'Client type, such as browser or library', 'basic-firewall' ),
			'client.version' => __( 'Client version', 'basic-firewall' ),
			'os.name'        => __( 'Operating system name', 'basic-firewall' ),
			'os.short_name'  => __( 'Operating system short name', 'basic-firewall' ),
			'os.version'     => __( 'Operating system version', 'basic-firewall' ),
			'device.type'    => __( 'Device type, such as desktop or smartphone', 'basic-firewall' ),
			'brand'          => __( 'Device brand', 'basic-firewall' ),
			'model'          => __( 'Device model', 'basic-firewall' ),
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed>  $settings Described by the interface.
	 * @param array<string, string> $errors Described by the interface.
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		$clean = parent::validate_settings( $settings, $errors );

		$source = (string) ( $settings['bot_source'] ?? 'curated' );

		$clean['bot_source']      = in_array( $source, array( 'curated', 'wider', 'either' ), true ) ? $source : 'curated';
		$clean['cache_detection'] = ! empty( $settings['cache_detection'] );

		return $clean;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry    = parent::compile( $rule );
		$settings = $rule['settings'] ?? array();

		$metadata = $entry['metadata'] ?? array();

		if ( empty( $settings['cache_detection'] ) ) {
			$metadata['cache'] = false;
		} else {
			$metadata['cache_dir'] = \Kanopi\BasicFirewall\Plugin::instance()->paths()->base() . '/device-detector';
		}

		$source = (string) ( $settings['bot_source'] ?? 'curated' );

		if ( 'curated' !== $source ) {
			$metadata['bot_source'] = $source;
		}

		$entry['metadata'] = $metadata;

		return $entry;
	}
}
