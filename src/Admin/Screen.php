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
use Kanopi\BasicFirewall\Support\Schema;

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
	 * A POSTed textarea exactly as typed, less control characters.
	 *
	 * For a box whose content is a document the firewall parses -- the
	 * Advanced YAML, an import, a pasted rule -- rather than prose. The
	 * textarea sanitiser strips anything tag-shaped and deletes every
	 * percent-encoded octet, so a pattern such as `(<|%3c)script` arrived as
	 * `(&lt;|)script`: a different rule, stored without a word (#60). What
	 * is read here is parsed and validated, never printed unescaped.
	 *
	 * @param string $key Field name.
	 */
	protected function posted_typed_textarea( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verify() is called by the caller.
		if ( ! isset( $_POST[ $key ] ) || is_array( $_POST[ $key ] ) ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read as typed on purpose; see above.
		return self::typed( wp_unslash( (string) $_POST[ $key ] ), true );
	}

	/**
	 * A POSTed one-line string exactly as typed, less control characters.
	 *
	 * The posted() counterpart of posted_typed_textarea(), for a field whose
	 * value is matched against rather than displayed -- a request path, a
	 * user agent. See there for why.
	 *
	 * @param string $key      Field name.
	 * @param string $fallback Returned when absent.
	 */
	protected function posted_typed( string $key, string $fallback = '' ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verify() is called by the caller.
		if ( ! isset( $_POST[ $key ] ) || is_array( $_POST[ $key ] ) ) {
			return $fallback;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read as typed on purpose; see posted_typed_textarea().
		return self::typed( wp_unslash( (string) $_POST[ $key ] ) );
	}

	/**
	 * A value as typed, with the control characters nobody types removed.
	 *
	 * NUL and the other C0 controls (and DEL) are dropped because no browser
	 * field produces them and every one of them is trouble downstream -- a
	 * NUL truncates a C string, a stray escape survives into a log line.
	 * A tab is kept: it is a character a pattern can legitimately contain.
	 * Line breaks are kept only where the field is a multi-line box; a
	 * one-line field never posts one, so one there is not something typed.
	 *
	 * Everything else is left alone. Escaping is the output's job, and
	 * whether the value is acceptable is the validator's.
	 *
	 * @param string $value     The value, already unslashed.
	 * @param bool   $multiline Whether line breaks belong in it.
	 */
	public static function typed( string $value, bool $multiline = false ): string {
		$pattern = $multiline ? '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/' : '/[\x00-\x08\x0A-\x1F\x7F]/';

		return (string) preg_replace( $pattern, '', $value );
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
			'id'           => true,
			'name'         => true,
			'type'         => true,
			'value'        => true,
			'class'        => true,
			'checked'      => true,
			'selected'     => true,
			'disabled'     => true,
			'readonly'     => true,
			'rows'         => true,
			'cols'         => true,
			'min'          => true,
			'max'          => true,
			'step'         => true,
			'placeholder'  => true,
			'autocomplete' => true,
			'style'        => true,
			'multiple'     => true,
			'data-*'       => true,
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
			self::attribute( $value ),
			$extra
		);
	}

	/**
	 * A stored value escaped for an attribute, so that it posts back unchanged.
	 *
	 * `esc_attr()` does not encode an ampersand that already starts an
	 * entity, which is right for markup and wrong for a value: a condition on
	 * `&lt;` was printed as `value="&lt;"`, which the browser reads as `<`,
	 * and the next save stored `<` instead. Every ampersand is encoded here,
	 * so what the browser shows -- and posts -- is what is stored.
	 *
	 * @param string $value The value as stored.
	 */
	protected static function attribute( string $value ): string {
		return htmlspecialchars( $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8', true );
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
				self::attribute( (string) $value ),
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

	/**
	 * A credential control: typed, never shown.
	 *
	 * The stored value is not put back into the page, where it would sit in
	 * the page source, the browser's form cache and every screenshot of the
	 * screen. Blank keeps it; the box, offered only when something is stored,
	 * removes it. Read back with kept_secret().
	 *
	 * @param string $name       Field name.
	 * @param string $clear_name The "remove" box's field name.
	 * @param bool   $stored     Whether a value is stored.
	 */
	protected static function secret_text( string $name, string $clear_name, bool $stored ): string {
		return self::text( $name, '', 'password', 'autocomplete="new-password"' )
			. ( $stored ? '<br>' . self::checkbox( $clear_name, false, __( 'Remove the stored value', 'basic-firewall' ) ) : '' );
	}

	/**
	 * The credential to store, given what a secret_text() control posted.
	 *
	 * What was typed wins. Otherwise the stored value is kept, unless the box
	 * asked for it to go, or what it belongs with has changed -- a password
	 * for one host is not a password for another, the same rule the importer
	 * applies.
	 *
	 * @param string $typed       What was typed.
	 * @param bool   $clear       Whether "remove the stored value" was ticked.
	 * @param string $stored      What is stored.
	 * @param bool   $still_bound Whether what the credential belongs with is unchanged.
	 */
	protected static function kept_secret( string $typed, bool $clear, string $stored, bool $still_bound ): string {
		if ( '' !== $typed ) {
			return $typed;
		}

		return $clear || ! $still_bound ? '' : $stored;
	}

	/**
	 * The rows for a database connection given as individual parameters.
	 *
	 * Shared by the Storage and Logging screens, which store the same shape
	 * under different keys. The password is a credential and is never
	 * rendered; see secret_text().
	 *
	 * @param string               $name       Field name prefix, such as `parameters`.
	 * @param array<string, mixed> $parameters What is stored.
	 * @param string               $show_when  When the rows are shown.
	 */
	protected function render_connection_parameters( string $name, array $parameters, string $show_when ): void {
		$field = static fn ( string $key ): string => $name . '[' . $key . ']';

		$this->row(
			__( 'Driver', 'basic-firewall' ),
			self::select( $field( 'driver' ), array_combine( Schema::CONNECTION_DRIVERS, Schema::CONNECTION_DRIVERS ), (string) ( $parameters['driver'] ?? 'pdo_mysql' ) ),
			wp_kses_post( __( 'A Doctrine driver name, not a database name: <code>pdo_mysql</code> or <code>mysqli</code> for MySQL and MariaDB.', 'basic-firewall' ) ),
			$show_when
		);

		$this->row( __( 'Host', 'basic-firewall' ), self::text( $field( 'host' ), (string) ( $parameters['host'] ?? '' ) ), '', $show_when );

		$this->row(
			__( 'Port', 'basic-firewall' ),
			self::text( $field( 'port' ), (string) (int) ( $parameters['port'] ?? 0 ), 'number', 'min="0" max="65535"' ),
			esc_html__( '0 for the driver\'s default.', 'basic-firewall' ),
			$show_when
		);

		$this->row( __( 'Database name', 'basic-firewall' ), self::text( $field( 'dbname' ), (string) ( $parameters['dbname'] ?? '' ) ), '', $show_when );
		$this->row( __( 'User', 'basic-firewall' ), self::text( $field( 'user' ), (string) ( $parameters['user'] ?? '' ) ), '', $show_when );

		$stored = '' !== (string) ( $parameters['password'] ?? '' );

		$this->row(
			__( 'Password', 'basic-firewall' ),
			self::secret_text( $field( 'password' ), $field( 'password_clear' ), $stored ),
			wp_kses_post(
				trim(
					( $stored ? __( 'A value is stored. Leave blank to keep it.', 'basic-firewall' ) . ' ' : '' )
					/* translators: the %env()% below is a literal token the firewall reads, not a placeholder. */
					. __( 'Prefer a token — <code>%env(MY_VARIABLE)%</code> — over the value itself. Exports strip a literal value, and a stored one is kept only while the driver, host, port and user are unchanged.', 'basic-firewall' )
				)
			),
			$show_when
		);
	}

	/**
	 * Connection parameters as posted by render_connection_parameters().
	 *
	 * @param array<string, mixed> $posted What the form posted under the prefix.
	 * @param array<string, mixed> $stored What is stored.
	 *
	 * @return array<string, mixed>
	 */
	protected static function posted_connection_parameters( array $posted, array $stored ): array {
		$parameters = array(
			'driver' => (string) ( $posted['driver'] ?? ( $stored['driver'] ?? 'pdo_mysql' ) ),
			'host'   => trim( (string) ( $posted['host'] ?? '' ) ),
			'port'   => (int) ( $posted['port'] ?? 0 ),
			'dbname' => trim( (string) ( $posted['dbname'] ?? '' ) ),
			'user'   => trim( (string) ( $posted['user'] ?? '' ) ),
		);

		$bound = true;

		foreach ( array( 'driver', 'host', 'port', 'user' ) as $key ) {
			$was   = (string) ( $stored[ $key ] ?? ( 'port' === $key ? 0 : '' ) );
			$bound = $bound && (string) $parameters[ $key ] === $was;
		}

		$parameters['password'] = self::kept_secret(
			(string) ( $posted['password'] ?? '' ),
			! empty( $posted['password_clear'] ),
			(string) ( $stored['password'] ?? '' ),
			$bound
		);

		return $parameters;
	}
}
