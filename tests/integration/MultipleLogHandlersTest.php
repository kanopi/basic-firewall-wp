<?php
/**
 * More than one log handler at a time.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;

/**
 * Several handlers is the normal arrangement, not the exception.
 *
 * A rotating file at warning to keep, a database handler at notice so the Log
 * screen has something to show, a stream to `php://stderr` where the platform
 * collects process output. Each decides its own level, so one configuration
 * cannot serve all three.
 *
 * The settings schema always allowed a list. What did not exist was a way to
 * see it: the screen rendered handlers as an undifferentiated run of fields
 * with one blank row at the end, so adding a second meant saving, scrolling,
 * and knowing that the blank row at the bottom was the way to do it.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 */
final class MultipleLogHandlersTest extends Settings_Snapshot {

	/**
	 * Three handlers, three classes, three levels.
	 */
	public function test_several_handlers_compile_independently(): void {
		$this->given_settings(
			array(
				'logger' => array(
					array(
						'type'      => 'rotating_file',
						'enabled'   => true,
						'level'     => 'warning',
						'path'      => 'logs/firewall.log',
						'max_files' => 14,
					),
					array(
						'type'        => 'database',
						'enabled'     => true,
						'level'       => 'notice',
						'table'       => 'basic_firewall_log',
						'retain_days' => 30,
						'buffered'    => true,
					),
					array(
						'type'    => 'stream',
						'enabled' => true,
						'level'   => 'error',
						'path'    => 'php://stderr',
					),
				),
			)
		);

		$rebuild = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $rebuild['written'], 'The configuration did not compile.' );

		$contents = (string) Plugin::instance()->compiled()->contents();

		foreach ( array( 'RotatingFileHandler', 'DatabaseHandler', 'StreamHandler' ) as $class ) {
			$this->assertStringContainsString(
				$class,
				$contents,
				sprintf( '%s did not reach the compiled configuration, so that handler is silently not logging.', $class )
			);
		}

		/*
		 * The levels, because a single shared level would defeat the point of
		 * running several: the file handler exists to keep less than the
		 * database one shows.
		 */
		foreach ( array( 'Warning', 'Notice', 'Error' ) as $level ) {
			$this->assertStringContainsString(
				'Monolog\\Level::' . $level,
				$contents,
				sprintf( 'The %s level was not carried through, so handlers are not deciding independently.', $level )
			);
		}
	}

	/**
	 * A stream path is not rewritten into the private directory.
	 *
	 * `php://stderr` is the reason a containerised host would add a stream
	 * handler at all. Treated as a relative path it became `php:/stderr` inside
	 * the private directory — a directory named `php:` holding a file nobody
	 * reads.
	 */
	public function test_a_stream_handler_keeps_its_wrapper(): void {
		$this->given_settings(
			array(
				'logger' => array(
					array(
						'type'    => 'stream',
						'enabled' => true,
						'level'   => 'error',
						'path'    => 'php://stderr',
					),
				),
			)
		);

		Plugin::instance()->compiled()->rebuild();

		$contents = (string) Plugin::instance()->compiled()->contents();

		$this->assertStringContainsString( 'php://stderr', $contents );
		$this->assertStringNotContainsString( 'php:/stderr', str_replace( 'php://stderr', '', $contents ) );
	}

	/**
	 * A handler set back to "none" is dropped rather than stored empty.
	 */
	public function test_a_handler_without_a_type_is_dropped(): void {
		$this->given_settings(
			array(
				'logger' => array(
					array(
						'type'    => 'rotating_file',
						'enabled' => true,
						'level'   => 'warning',
						'path'    => 'logs/firewall.log',
					),
					array(
						'type'    => '',
						'enabled' => true,
						'level'   => 'notice',
					),
				),
			)
		);

		Plugin::instance()->compiled()->rebuild();

		$contents = (string) Plugin::instance()->compiled()->contents();

		$this->assertSame(
			1,
			substr_count( $contents, 'class:' ),
			'An empty handler reached the compiled configuration, where the library has to decide what to make of it.'
		);
	}
}
