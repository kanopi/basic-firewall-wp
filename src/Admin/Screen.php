<?php
/**
 * Base class for administrative screens.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin;

use Kanopi\BasicFirewall\Install\Capabilities;
use Kanopi\BasicFirewall\Plugin;

/**
 * One administrative screen.
 *
 * Three rules hold for every subclass without exception, and they are enforced
 * here rather than left to each screen to remember:
 *
 * - `capability()` is checked before the screen renders and before its
 *   submission is handled.
 * - Every write is nonce-checked, through `verify()`.
 * - Everything printed goes through an `esc_*` function.
 */
abstract class Screen {

	/**
	 * The screen's slug, used as the `page` query argument.
	 */
	abstract public function slug(): string;

	/**
	 * Title shown at the top of the page.
	 */
	abstract public function page_title(): string;

	/**
	 * Render the screen body.
	 */
	abstract public function render(): void;

	/**
	 * Title shown in the menu.
	 */
	public function menu_title(): string {
		return $this->page_title();
	}

	/**
	 * Whether this screen appears in the menu.
	 */
	public function in_menu(): bool {
		return true;
	}

	/**
	 * The capability required to reach it.
	 */
	public function capability(): string {
		return Capabilities::MANAGE;
	}

	/**
	 * An introductory paragraph, or an empty string.
	 */
	public function intro(): string {
		return '';
	}

	/**
	 * Handle a submission. Called on admin_init.
	 */
	public function handle(): void {}

	/**
	 * The nonce action for this screen.
	 */
	protected function nonce_action(): string {
		return 'basic_firewall_' . $this->slug();
	}

	/**
	 * Print the nonce field.
	 */
	protected function nonce_field(): void {
		wp_nonce_field( $this->nonce_action(), 'basic_firewall_nonce' );
	}

	/**
	 * Whether this request is a valid, authorised submission of this screen.
	 *
	 * Both halves matter and neither is sufficient. The capability check says
	 * this user is allowed to do it; the nonce says this user *meant* to,
	 * rather than having been walked into it by another site.
	 */
	protected function verify(): bool {
		if ( ! isset( $_POST['basic_firewall_nonce'] ) ) {
			return false;
		}

		if ( ! current_user_can( $this->capability() ) ) {
			return false;
		}

		$nonce = sanitize_text_field( wp_unslash( (string) $_POST['basic_firewall_nonce'] ) );

		return (bool) wp_verify_nonce( $nonce, $this->nonce_action() );
	}

	/**
	 * A POSTed string, sanitised.
	 *
	 * @param string $key      Field name.
	 * @param string $fallback Returned when absent.
	 */
	protected function posted( string $key, string $fallback = '' ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verify() is called by the caller.
		if ( ! isset( $_POST[ $key ] ) || is_array( $_POST[ $key ] ) ) {
			return $fallback;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return sanitize_text_field( wp_unslash( (string) $_POST[ $key ] ) );
	}

	/**
	 * A POSTed textarea, with newlines preserved.
	 *
	 * `sanitize_text_field()` collapses newlines, which would turn a list of
	 * addresses or a YAML document into one line.
	 *
	 * @param string $key Field name.
	 */
	protected function posted_textarea( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! isset( $_POST[ $key ] ) || is_array( $_POST[ $key ] ) ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return sanitize_textarea_field( wp_unslash( (string) $_POST[ $key ] ) );
	}

	/**
	 * A POSTed array, recursively sanitised.
	 *
	 * @param string $key Field name.
	 *
	 * @return array<string, mixed>
	 */
	protected function posted_array( string $key ): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! isset( $_POST[ $key ] ) || ! is_array( $_POST[ $key ] ) ) {
			return array();
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		return self::sanitize_deep( wp_unslash( $_POST[ $key ] ) );
	}

	/**
	 * Recursively sanitise an array of submitted values.
	 *
	 * @param mixed $value Raw value.
	 *
	 * @return mixed
	 */
	protected static function sanitize_deep( $value ) {
		if ( is_array( $value ) ) {
			$clean = array();

			foreach ( $value as $key => $item ) {
				$clean[ is_string( $key ) ? sanitize_key( $key ) : $key ] = self::sanitize_deep( $item );
			}

			return $clean;
		}

		if ( is_string( $value ) ) {
			// Newlines survive; the schema validator coerces types afterwards.
			return sanitize_textarea_field( $value );
		}

		return $value;
	}

	/**
	 * A GET parameter, sanitised.
	 *
	 * @param string $key      Parameter name.
	 * @param string $fallback Returned when absent.
	 */
	protected function query( string $key, string $fallback = '' ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET[ $key ] ) || is_array( $_GET[ $key ] ) ) {
			return $fallback;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) );
	}

	/**
	 * Redirect back to a screen after handling a submission.
	 *
	 * @param string               $slug Screen slug.
	 * @param array<string, mixed> $args Query arguments.
	 */
	protected function redirect( string $slug, array $args = array() ): void {
		wp_safe_redirect( Admin::url( $slug, $args ) );

		exit;
	}

	/**
	 * The plugin container.
	 */
	protected function plugin(): Plugin {
		return Plugin::instance();
	}

	/**
	 * Open a form that posts back to this screen.
	 */
	protected function open_form(): void {
		printf( '<form method="post" action="%s">', esc_url( Admin::url( $this->slug() ) ) );

		$this->nonce_field();
	}

	/**
	 * Close a form, with a submit button.
	 *
	 * @param string $label Button label.
	 */
	protected function close_form( string $label = '' ): void {
		submit_button( '' === $label ? __( 'Save changes', 'basic-firewall' ) : $label );

		echo '</form>';
	}

	/**
	 * Render a table row for one field.
	 *
	 * @param string $label       Field label.
	 * @param string $control     The control markup, already escaped.
	 * @param string $description Help text.
	 * @param string $show_when   Optional condition, as `field:value` or
	 *                            `field:value|other`. The row is shown only
	 *                            while that control holds one of those values.
	 */
	protected function row( string $label, string $control, string $description = '', string $show_when = '' ): void {
		printf(
			'<tr%s><th scope="row">%s</th><td>%s%s</td></tr>',
			'' === $show_when ? '' : sprintf( ' data-bfw-show-when="%s"', esc_attr( $show_when ) ),
			esc_html( $label ),
			wp_kses( $control, self::allowed_control_html() ),
			'' === $description ? '' : '<p class="description">' . wp_kses_post( $description ) . '</p>'
		);
	}

	/**
	 * Open a section that only applies to some selections.
	 *
	 * Renders the heading and an optional lead paragraph inside a wrapper the
	 * admin script can hide. Everything is still rendered and still submitted;
	 * only its visibility depends on the condition, so a screen behaves exactly
	 * as it did before when JavaScript is unavailable.
	 *
	 * @param string $title     Section heading.
	 * @param string $show_when Condition, as `field:value` or `field:value|other`.
	 * @param string $intro     Optional lead paragraph, already translated.
	 */
	protected function open_section( string $title, string $show_when = '', string $intro = '' ): void {
		printf(
			'<div class="bfw-section"%s>',
			'' === $show_when ? '' : sprintf( ' data-bfw-show-when="%s"', esc_attr( $show_when ) )
		);

		printf( '<h2>%s</h2>', esc_html( $title ) );

		if ( '' !== $intro ) {
			printf( '<p class="description" style="max-width:48rem">%s</p>', wp_kses_post( $intro ) );
		}
	}

	/**
	 * Close a section opened with open_section().
	 */
	protected function close_section(): void {
		echo '</div>';
	}

	/**
	 * The HTML a form control may contain.
	 *
	 * @return array<string, array<string, bool>>
	 */
	protected static function allowed_control_html(): array {
		$attributes = array(
			'id'          => true,
			'name'        => true,
			'type'        => true,
			'value'       => true,
			'class'       => true,
			'checked'     => true,
			'selected'    => true,
			'disabled'    => true,
			'readonly'    => true,
			'rows'        => true,
			'cols'        => true,
			'min'         => true,
			'max'         => true,
			'step'        => true,
			'placeholder' => true,
			'style'       => true,
			'multiple'    => true,
			'data-*'      => true,
		);

		return array(
			'input'    => $attributes,
			'select'   => $attributes,
			'option'   => $attributes,
			'textarea' => $attributes,
			'label'    => $attributes,
			'span'     => $attributes,
			'code'     => $attributes,
			'strong'   => $attributes,
			'em'       => $attributes,
			'br'       => array(),
			'fieldset' => $attributes,
			'legend'   => $attributes,
			'div'      => $attributes,
			'p'        => $attributes,
			'a'        => $attributes + array( 'href' => true ),
		);
	}

	/**
	 * A text input.
	 *
	 * @param string $name  Field name.
	 * @param string $value Current value.
	 * @param string $type  Input type.
	 * @param string $extra Extra attributes, already escaped.
	 */
	protected static function text( string $name, string $value, string $type = 'text', string $extra = '' ): string {
		return sprintf(
			'<input type="%s" name="%s" id="%s" value="%s" class="regular-text" %s />',
			esc_attr( $type ),
			esc_attr( $name ),
			esc_attr( $name ),
			esc_attr( $value ),
			$extra
		);
	}

	/**
	 * A textarea.
	 *
	 * @param string $name  Field name.
	 * @param string $value Current value.
	 * @param int    $rows  Height.
	 * @param bool   $yaml  Whether the content is YAML and wants the editor.
	 */
	protected static function textarea( string $name, string $value, int $rows = 6, bool $yaml = false ): string {
		return sprintf(
			'<textarea name="%s" id="%s" rows="%d" class="large-text code"%s>%s</textarea>',
			esc_attr( $name ),
			esc_attr( $name ),
			$rows,
			// Marks it for the editor. An attribute rather than a class so a
			// theme restyling `.code` cannot turn one on or off by accident.
			$yaml ? ' data-bfw-yaml="1"' : '',
			esc_textarea( $value )
		);
	}

	/**
	 * A select.
	 *
	 * @param string                   $name    Field name.
	 * @param array<array-key, string> $options Value to label. Keys are array-key
	 *                                          rather than string because PHP
	 *                                          casts a numeric-string key to an
	 *                                          int, so array( '302' => ... ) is
	 *                                          an int-keyed array however it was
	 *                                          written.
	 * @param string                   $current Current value.
	 */
	protected static function select( string $name, array $options, string $current ): string {
		$markup = sprintf( '<select name="%s" id="%s">', esc_attr( $name ), esc_attr( $name ) );

		foreach ( $options as $value => $label ) {
			$markup .= sprintf(
				'<option value="%s"%s>%s</option>',
				esc_attr( (string) $value ),
				selected( (string) $value, $current, false ),
				esc_html( $label )
			);
		}

		return $markup . '</select>';
	}

	/**
	 * A checkbox.
	 *
	 * @param string $name    Field name.
	 * @param bool   $checked Whether it is ticked.
	 * @param string $label   Label beside the box.
	 */
	protected static function checkbox( string $name, bool $checked, string $label ): string {
		return sprintf(
			'<label><input type="checkbox" name="%s" id="%s" value="1"%s /> %s</label>',
			esc_attr( $name ),
			esc_attr( $name ),
			checked( $checked, true, false ),
			esc_html( $label )
		);
	}
}
