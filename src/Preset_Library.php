<?php
/**
 * The library's shipped rule sets, and any a site contributes.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

use Symfony\Component\Yaml\Yaml;

/**
 * Presets, enabled by reference rather than copied in.
 *
 * Including by reference rather than importing the rules means two things:
 * a preset's rules update when the library updates, with no re-import step; and
 * an exported document records only which presets are on, so several hundred
 * patterns never appear in a diff.
 *
 * Preset rules cannot be edited here. To carve out an exception, add an **allow**
 * rule with a lower weight -- allow rules are evaluated first and a match ends
 * evaluation.
 */
final class Preset_Library {

	/**
	 * Resolved preset definitions, keyed by name.
	 *
	 * @var array<string, array<string, mixed>>|null
	 */
	private ?array $presets = null;

	/**
	 * Problems from the last resolve_paths() call.
	 *
	 * @var list<string>
	 */
	private array $problems = array();

	/**
	 * Every available preset.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function all(): array {
		if ( null !== $this->presets ) {
			return $this->presets;
		}

		$presets = $this->shipped();

		/**
		 * Filters the available firewall presets.
		 *
		 * A plugin or theme contributes a rule set by adding an entry keyed by
		 * name, with a `label` and either a `file` (absolute path to a YAML
		 * file) or an inline `config` array.
		 *
		 * A contributed preset cannot take the name of one the library ships:
		 * the shipped one wins and the collision is recorded. Otherwise a plugin
		 * could change what an existing, ticked preset does without anything in
		 * the interface changing.
		 *
		 * @param array<string, array<string, mixed>> $presets Available presets.
		 */
		$filtered = apply_filters( 'basic_firewall_presets', $presets );

		$resolved = is_array( $filtered ) ? $filtered : $presets;

		// Shipped presets win a name collision.
		foreach ( $this->shipped() as $name => $preset ) {
			$resolved[ $name ] = $preset;
		}

		$this->presets = $resolved;

		return $this->presets;
	}

	/**
	 * The presets the library ships.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function shipped(): array {
		$dir = $this->library_preset_dir();

		if ( null === $dir ) {
			return array();
		}

		$presets = array();

		foreach ( (array) glob( $dir . '/*.yml' ) as $file ) {
			$name = basename( (string) $file, '.yml' );

			/*
			 * The library ships worked examples alongside the real rule sets.
			 * They are documentation, not policy -- several deliberately
			 * demonstrate a configuration nobody should enable on a live site --
			 * so they are not offered.
			 */
			if ( 0 === strpos( $name, 'example-' ) || 'config' === $name ) {
				continue;
			}

			$presets[ $name ] = array(
				'label'   => $this->humanize( $name ),
				'file'    => (string) $file,
				'shipped' => true,
			);
		}

		ksort( $presets );

		return $presets;
	}

	/**
	 * Where the library keeps its presets.
	 */
	private function library_preset_dir(): ?string {
		if ( ! class_exists( \Kanopi\Firewall\Firewall::class ) ) {
			return null;
		}

		$reflector = new \ReflectionClass( \Kanopi\Firewall\Firewall::class );
		$file      = $reflector->getFileName();

		if ( false === $file ) {
			return null;
		}

		$dir = dirname( $file, 2 ) . '/presets';

		return is_dir( $dir ) ? $dir : null;
	}

	/**
	 * Why a preset must not be used on this site, or null when it is fine.
	 *
	 * A preset named for a platform blocks **that platform's own endpoints**,
	 * which makes it a tool for sites *not* running it. `wordpress.yml` turns
	 * away requests for `/wp-admin`, `/wp-login.php`, `/xmlrpc.php` and
	 * `/wp-json` -- exactly right on a Drupal site, where every one of those is
	 * a probe by definition, and catastrophic here, where they are the
	 * administrator's own login and the REST API the block editor runs on.
	 *
	 * This plugin had the test inverted: it hid the Drupal presets, which block
	 * paths WordPress does not serve and are harmless here, and offered the
	 * WordPress one, which is a single tick away from locking somebody out of
	 * their own site. A preset list is exactly where that kind of mistake is
	 * least likely to be noticed before it is made.
	 *
	 * @param string $name Preset name.
	 */
	public function incompatible_reason( string $name ): ?string {
		if ( 0 !== strpos( $name, 'wordpress' ) ) {
			return null;
		}

		return __( 'This rule set blocks WordPress\'s own endpoints — /wp-admin, /wp-login.php, /xmlrpc.php and the /wp-json REST API. It is written for sites that do not run WordPress, where those paths are only ever probes. Enabling it here would lock every administrator out of this site and break the block editor.', 'basic-firewall' );
	}

	/**
	 * Presets this site may use.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function applicable(): array {
		$applicable = array();

		foreach ( $this->all() as $name => $preset ) {
			if ( null === $this->incompatible_reason( (string) $name ) ) {
				$applicable[ $name ] = $preset;
			}
		}

		return $applicable;
	}

	/**
	 * Presets excluded from this site, with the reason for each.
	 *
	 * Listed rather than silently dropped. A rule set that is simply absent
	 * invites somebody to go looking for it, or to paste it into the Advanced
	 * screen by hand -- which is the same mistake with the guard removed.
	 *
	 * @return array<string, string>
	 */
	public function incompatible(): array {
		$incompatible = array();

		foreach ( array_keys( $this->all() ) as $name ) {
			$reason = $this->incompatible_reason( (string) $name );

			if ( null !== $reason ) {
				$incompatible[ (string) $name ] = $reason;
			}
		}

		return $incompatible;
	}

	/**
	 * Resolve enabled preset names to file paths for the compiled `configs` key.
	 *
	 * @param array<int, mixed> $enabled Enabled preset names.
	 *
	 * @return list<string>
	 */
	public function resolve_paths( array $enabled ): array {
		$all   = $this->all();
		$paths = array();

		$this->problems = array();

		foreach ( $enabled as $name ) {
			$preset = $all[ (string) $name ] ?? null;

			if ( null === $preset ) {
				continue;
			}

			/*
			 * Refused here, not just hidden on the screen.
			 *
			 * Hiding it from the list stops somebody ticking it; it does not
			 * stop `presets: [wordpress]` arriving in an imported document from
			 * a Drupal site, where enabling it was the right call. Compiling it
			 * there would block this site's own login. So the check lives on the
			 * path everything goes through, and says so rather than dropping it
			 * quietly.
			 */
			$reason = $this->incompatible_reason( (string) $name );

			if ( null !== $reason ) {
				$this->problems[] = sprintf(
					/* translators: 1: preset name, 2: why it cannot be used. */
					__( 'The preset "%1$s" was not enabled. %2$s', 'basic-firewall' ),
					(string) $name,
					$reason
				);

				continue;
			}

			if ( isset( $preset['file'] ) && is_readable( (string) $preset['file'] ) ) {
				$paths[] = (string) $preset['file'];

				continue;
			}

			/*
			 * An inline preset is written out to the private directory so it
			 * loads through exactly the same path a file preset does, rather
			 * than through a second merge mechanism that would have to be kept
			 * in step with the library's own.
			 */
			if ( isset( $preset['config'] ) && is_array( $preset['config'] ) ) {
				$written = $this->write_inline( (string) $name, $preset['config'] );

				if ( null !== $written ) {
					$paths[] = $written;
				}
			}
		}

		return $paths;
	}

	/**
	 * Problems from the last resolve_paths() call.
	 *
	 * @return list<string>
	 */
	public function problems(): array {
		return $this->problems;
	}

	/**
	 * Write an inline preset to disk.
	 *
	 * @param string               $name   Preset name.
	 * @param array<string, mixed> $config Inline configuration.
	 */
	private function write_inline( string $name, array $config ): ?string {
		$dir = Plugin::instance()->paths()->base() . '/presets';

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return null;
		}

		$path = $dir . '/' . sanitize_file_name( $name ) . '.yml';

		$written = file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			$path,
			"# Written by Basic Firewall from a contributed preset. DO NOT EDIT.\n" . Yaml::dump( $config, 8, 2 )
		);

		return false === $written ? null : $path;
	}

	/**
	 * Read a preset's contents, for the preview screen.
	 *
	 * @param string $name Preset name.
	 *
	 * @return array{config: array<string, mixed>, raw: string}|null
	 */
	public function read( string $name ): ?array {
		$preset = $this->all()[ $name ] ?? null;

		if ( null === $preset ) {
			return null;
		}

		if ( isset( $preset['config'] ) && is_array( $preset['config'] ) ) {
			return array(
				'config' => $preset['config'],
				'raw'    => Yaml::dump( $preset['config'], 8, 2 ),
			);
		}

		if ( ! isset( $preset['file'] ) || ! is_readable( (string) $preset['file'] ) ) {
			return null;
		}

		$raw = (string) file_get_contents( (string) $preset['file'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file, not a remote URL; WP_Filesystem is not loaded this early.

		try {
			$config = Yaml::parse( $raw );
		} catch ( \Throwable $e ) {
			return null;
		}

		return array(
			'config' => is_array( $config ) ? $config : array(),
			// The raw file, comments included. The comments are frequently the
			// clearest explanation of why a pattern is there.
			'raw'    => $raw,
		);
	}

	/**
	 * Whether any enabled preset needs the challenge section compiled.
	 *
	 * One of the shipped presets responds with `challenge`, and a challenge
	 * plugin without a signing secret is a configuration the library refuses to
	 * load -- which this plugin fails open on, taking the whole ruleset with it.
	 *
	 * @param array<int, mixed> $enabled Enabled preset names.
	 */
	public function requires_challenge( array $enabled ): bool {
		foreach ( $enabled as $name ) {
			$preset = $this->read( (string) $name );

			if ( null === $preset ) {
				continue;
			}

			foreach ( $preset['config']['plugins'] ?? array() as $plugin ) {
				if ( is_array( $plugin ) && 'challenge' === ( $plugin['response'] ?? '' ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Turn a preset filename into a readable label.
	 *
	 * @param string $name Preset name.
	 */
	private function humanize( string $name ): string {
		$label = ucwords( str_replace( array( '-', '_' ), ' ', $name ) );

		/*
		 * ucwords() produces "Ai Crawlers" and "WordPress", both of which read
		 * as a typo in a list somebody is deciding what to enable from. These
		 * are the names as they are actually spelled.
		 */
		$spellings = array(
			'Ai '       => 'AI ',
			'Wordpress' => 'WordPress',
			'Crs'       => 'CRS',
			'Url'       => 'URL',
			'Urls'      => 'URLs',
			'Ip '       => 'IP ',
			'Asn'       => 'ASN',
		);

		return strtr( $label, $spellings );
	}

	/**
	 * Forget resolved presets. Test seam.
	 *
	 * @internal
	 */
	public function reset(): void {
		$this->presets = null;
	}
}
