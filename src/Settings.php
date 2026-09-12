<?php
/**
 * Reads and writes the settings option.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

use Kanopi\BasicFirewall\Support\Schema;
use Kanopi\BasicFirewall\Support\Validator;

/**
 * The source of truth, wrapped in something that validates.
 *
 * One option, `autoload = no`. The non-autoload part is the whole reason a
 * single option is safe here: a large rule set would otherwise be unserialized
 * on every request on the site, including the ones the firewall is meant to
 * make cheap. Nothing on the front end reads this option -- the runtime reads
 * the *compiled file* -- so the cost lands only on admin screens and WP-CLI.
 *
 * @see DECISIONS.md section 2.
 */
final class Settings {

	/**
	 * In-request cache of the validated document.
	 *
	 * @var array<string, mixed>|null
	 */
	private ?array $cache = null;

	/**
	 * Problems found the last time the stored document was validated.
	 *
	 * @var list<array{path: string, message: string}>
	 */
	private array $errors = array();

	/**
	 * The whole settings document, validated and with defaults filled in.
	 *
	 * @return array<string, mixed>
	 */
	public function all(): array {
		if ( null !== $this->cache ) {
			return $this->cache;
		}

		$stored = get_option( Schema::OPTION, array() );

		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		$validator    = new Validator();
		$this->cache  = $validator->validate( $stored );
		$this->errors = $validator->errors();

		return $this->cache;
	}

	/**
	 * One value, by dotted path.
	 *
	 * @param string $path    Dotted path, for example `global.mode`.
	 * @param mixed  $fallback Returned when the path is absent.
	 *
	 * @return mixed
	 */
	public function get( string $path, $fallback = null ) {
		$value = $this->all();

		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! is_array( $value ) || ! array_key_exists( $segment, $value ) ) {
				return $fallback;
			}

			$value = $value[ $segment ];
		}

		return $value;
	}

	/**
	 * Replace the whole document.
	 *
	 * Validates before writing, so nothing outside the schema's shape is ever
	 * stored. Returns the validation problems; an empty array means a clean
	 * save. The write happens either way, because every invalid value has
	 * already been replaced with its default and refusing to write would leave
	 * the worse of the two documents in the database.
	 *
	 * @param array<string, mixed> $values New settings.
	 *
	 * @return list<array{path: string, message: string}>
	 */
	public function replace( array $values ): array {
		$validator = new Validator();
		$clean     = $validator->validate( $values );

		/*
		 * autoload = no. See the class docblock.
		 *
		 * update_option() returns false both when the write fails and when the
		 * value is unchanged, so its return value is not a useful signal and is
		 * deliberately not checked here.
		 */
		update_option( Schema::OPTION, $clean, false );

		$this->cache  = $clean;
		$this->errors = $validator->errors();

		/**
		 * Fires after the settings have been written.
		 *
		 * The compiler listens for this: the compiled file is a cache of this
		 * option, so it is rebuilt whenever the option changes rather than on a
		 * timer or on a request that happens to notice.
		 *
		 * @param array<string, mixed> $clean The document as stored.
		 */
		do_action( 'basic_firewall_settings_saved', $clean );

		return $this->errors;
	}

	/**
	 * Write one value, by dotted path.
	 *
	 * @param string $path  Dotted path.
	 * @param mixed  $value New value.
	 *
	 * @return list<array{path: string, message: string}>
	 */
	public function set( string $path, $value ): array {
		$all      = $this->all();
		$segments = explode( '.', $path );
		$cursor   = &$all;

		foreach ( $segments as $index => $segment ) {
			if ( count( $segments ) - 1 === $index ) {
				$cursor[ $segment ] = $value;
				break;
			}

			if ( ! isset( $cursor[ $segment ] ) || ! is_array( $cursor[ $segment ] ) ) {
				$cursor[ $segment ] = array();
			}

			$cursor = &$cursor[ $segment ];
		}

		unset( $cursor );

		return $this->replace( $all );
	}

	/**
	 * Problems found validating the stored document.
	 *
	 * Non-empty here means what is in the database does not match the schema --
	 * usually a hand-edited option, a failed upgrade routine, or an import from
	 * a newer version. Surfaced in Site Health rather than silently repaired.
	 *
	 * @return list<array{path: string, message: string}>
	 */
	public function errors(): array {
		$this->all();

		return $this->errors;
	}

	/**
	 * Whether the option has ever been written.
	 */
	public function is_installed(): bool {
		return false !== get_option( Schema::OPTION, false );
	}

	/**
	 * Drop the in-request cache.
	 */
	public function flush(): void {
		$this->cache  = null;
		$this->errors = array();
	}
}
