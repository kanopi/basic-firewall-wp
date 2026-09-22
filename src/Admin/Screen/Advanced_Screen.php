<?php
/**
 * Raw YAML merged over the compiled configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Symfony\Component\Yaml\Yaml;

/**
 * The escape hatch.
 */
final class Advanced_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-advanced';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Advanced', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return wp_kses_post(
			__( 'YAML merged over everything the screens produce. For conditions the forms cannot express — groups nested inside groups — and for anything the firewall library gains before this plugin has a screen for it. <strong>This overrides the screens</strong>, so a key set here wins and the screen that owns it will appear to be ignored.', 'basic-firewall' )
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$yaml = $this->posted_textarea( 'advanced_yaml' );

		if ( '' !== trim( $yaml ) ) {
			try {
				$parsed = Yaml::parse( $yaml );
			} catch ( \Throwable $e ) {
				Notices::add(
					sprintf(
						/* translators: %s: parser error. */
						__( 'That YAML could not be parsed, so nothing was saved: %s', 'basic-firewall' ),
						esc_html( $e->getMessage() )
					),
					'error'
				);

				$this->redirect( $this->slug() );
			}

			if ( ! is_array( $parsed ?? null ) ) {
				Notices::add( __( 'That YAML does not describe a set of configuration keys, so nothing was saved.', 'basic-firewall' ), 'error' );

				$this->redirect( $this->slug() );
			}
		}

		$this->plugin()->settings()->set( 'advanced_yaml', $yaml );

		Notices::add( __( 'Advanced configuration saved, and the firewall recompiled. Check the Compiled screen to confirm the result is what you intended.', 'basic-firewall' ) );

		$this->redirect( $this->slug() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		printf(
			'<div class="bfw-warning"><p>%s</p></div>',
			wp_kses_post(
				/* translators: %s: the value described in the sentence. */
				__( 'Two things worth knowing before using this. A <strong>list</strong> written here replaces the corresponding list rather than adding to it — writing a <code>plugins</code> key means "these", not "these as well as my rules". And a <code>%file()%</code> token reaches the library from here just as it does from anywhere else, which is why the directories it may read from are an explicit allowlist in wp-config.php rather than open by default.', 'basic-firewall' )
			)
		);

		$this->open_form();

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Additional YAML', 'basic-firewall' ),
			self::textarea( 'advanced_yaml', (string) $this->plugin()->settings()->get( 'advanced_yaml', '' ), 20, true ),
			__( 'Parsed on save. Invalid YAML is refused rather than stored, because a configuration the firewall cannot load means it starts with an empty rule set that allows everything.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		$this->close_form();
	}
}
