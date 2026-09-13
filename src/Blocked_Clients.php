<?php
/**
 * Reads and modifies the block list.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\Firewall\Storage\QueryableStorageInterface;
use Kanopi\Firewall\Storage\StorageInterface;

/**
 * The list of clients the firewall is currently refusing.
 *
 * Listing goes through the library's own `QueryableStorageInterface`, so file
 * and database storage answer the same way and a custom backend that cannot
 * enumerate its keys says so rather than reporting an empty list -- the
 * difference between "nobody is blocked" and "I cannot tell you who is blocked"
 * matters a great deal to somebody investigating a complaint.
 */
final class Blocked_Clients {

	/**
	 * The configured storage backend, built lazily.
	 *
	 * @var StorageInterface|null
	 */
	private ?StorageInterface $storage = null;

	/**
	 * Build the storage backend the firewall is actually using.
	 */
	private function storage(): ?StorageInterface {
		if ( null !== $this->storage ) {
			return $this->storage;
		}

		$settings = Plugin::instance()->settings();
		$backend  = (string) $settings->get( 'storage.backend', 'file' );
		$class    = Library_Map::resolve( Library_Map::STORAGE, $backend, 'file' );

		$config = array();

		if ( 'database' === $backend ) {
			$credentials = new Database_Credentials();
			$database    = (array) $settings->get( 'storage.database', array() );
			$source      = (string) ( $database['connection_source'] ?? 'wordpress' );

			$config = array(
				'storage_table'  => 'wordpress' === $source
					? $credentials->prefix_table( (string) ( $database['storage_table'] ?? 'basic_firewall_blocked' ) )
					: (string) ( $database['storage_table'] ?? 'basic_firewall_blocked' ),
				'offenses_table' => 'wordpress' === $source
					? $credentials->prefix_table( (string) ( $database['offenses_table'] ?? 'basic_firewall_offenses' ) )
					: (string) ( $database['offenses_table'] ?? 'basic_firewall_offenses' ),
			);

			if ( 'wordpress' === $source ) {
				$config['connection'] = $credentials->get_connection_parameters();
			} elseif ( '' !== trim( (string) ( $database['dsn'] ?? '' ) ) ) {
				$config['connection'] = array( 'dsn' => trim( (string) $database['dsn'] ) );
			}
		} else {
			$paths  = Plugin::instance()->paths();
			$file   = (array) $settings->get( 'storage.file', array() );
			$target = $paths->resolve( (string) ( $file['storage_file'] ?? 'blocked.data' ) );

			$config = array(
				'storage_file' => $target,
				'offense_file' => '' !== trim( (string) ( $file['offense_file'] ?? '' ) )
					? $paths->resolve( (string) $file['offense_file'] )
					: $target . '.offenses',
			);
		}

		try {
			$storage = new $class( $config );
		} catch ( \Throwable $e ) {
			return null;
		}

		$this->storage = $storage instanceof StorageInterface ? $storage : null;

		return $this->storage;
	}

	/**
	 * Every currently blocked client.
	 *
	 * Permanent blocks first, then the longest remaining.
	 *
	 * @return array{supported: bool, clients: list<array<string, mixed>>}
	 */
	public function all(): array {
		$storage = $this->storage();

		if ( ! $storage instanceof QueryableStorageInterface ) {
			/*
			 * Says so rather than reporting an empty list. "Nobody is blocked"
			 * and "I cannot tell you who is blocked" are different answers, and
			 * only one of them should stop somebody investigating.
			 */
			return array(
				'supported' => false,
				'clients'   => array(),
			);
		}

		$records = array();

		/*
		 * find() refuses an empty pattern -- deliberately, because the caller's
		 * next move is often to delete what came back and a pattern that matched
		 * everything would be a loaded gun. So "everything" is spelled out as
		 * the two default routes, which between them cover every address.
		 *
		 * The library excludes expired-but-not-yet-collected records itself, so
		 * what comes back is what is actually in force.
		 */
		foreach ( array( '0.0.0.0/0', '::/0' ) as $pattern ) {
			try {
				$found = $storage->find( $pattern );
			} catch ( \Throwable $e ) {
				continue;
			}

			$records += $found;
		}

		$clients = array();

		foreach ( $records as $ip => $record ) {
			if ( ! is_array( $record ) ) {
				continue;
			}

			$expires = (int) ( $record['expire'] ?? 0 );

			/*
			 * find() wraps the stored payload: the block's own fields live under
			 * `value`, with `expire`, `expires_at` and `offenses` alongside. The
			 * payload is flattened here so callers do not each have to know that
			 * -- and so a listing does not quietly render every rule and reason
			 * as blank, which is what reading the top level gives you.
			 */
			$payload = is_array( $record['value'] ?? null ) ? $record['value'] : $record;

			$clients[] = array(
				'ip'        => (string) $ip,
				'expires'   => $expires,
				'permanent' => 0 === $expires,
				'offenses'  => (int) ( $record['offenses'] ?? 0 ),
				'record'    => $payload,
			);
		}

		usort(
			$clients,
			static function ( array $a, array $b ): int {
				if ( $a['permanent'] !== $b['permanent'] ) {
					// Permanent first.
					return $a['permanent'] ? -1 : 1;
				}

				// Then the longest remaining.
				return $b['expires'] <=> $a['expires'];
			}
		);

		return array(
			'supported' => true,
			'clients'   => $clients,
		);
	}

	/**
	 * Whether one address is blocked.
	 *
	 * Queries the backend directly, so it answers for every backend -- including
	 * the ones that cannot be enumerated, where looking a single address up is
	 * the only way to get an answer at all.
	 *
	 * @param string $ip Client address.
	 *
	 * @return array{blocked: bool, backend: string, record: array<string, mixed>|null}
	 */
	public function check( string $ip ): array {
		$backend = (string) Plugin::instance()->settings()->get( 'storage.backend', 'file' );
		$storage = $this->storage();

		$answer = array(
			'blocked' => false,
			'backend' => $backend,
			'record'  => null,
		);

		if ( null === $storage ) {
			return $answer;
		}

		try {
			$record = $storage->isBlocked( $ip );
		} catch ( \Throwable $e ) {
			return $answer;
		}

		if ( ! is_array( $record ) ) {
			return $answer;
		}

		$answer['blocked'] = true;
		$answer['record']  = is_array( $record['value'] ?? null ) ? $record['value'] : $record;

		return $answer;
	}

	/**
	 * Block one address by hand.
	 *
	 * This adds an entry to the block list, which is what the firewall consults
	 * before evaluating rules. It does not create a rule: the entry expires like
	 * any other and is not part of an exported document. If the decision should
	 * travel with the site, add an IP address rule instead.
	 *
	 * @param string $ip       Client address.
	 * @param int    $duration Seconds, 0 for permanent.
	 * @param string $reason   Why.
	 */
	public function block( string $ip, int $duration = 3600, string $reason = '' ): bool {
		$storage = $this->storage();

		if ( null === $storage ) {
			return false;
		}

		try {
			/*
			 * Deleted first, so re-blocking an already-blocked address takes the
			 * new duration. The storage layer would otherwise keep the original
			 * expiry and silently ignore the new one -- an administrator
			 * extending a block would believe they had, and would not have.
			 */
			$storage->delete( $ip );

			return $storage->set(
				$ip,
				array(
					'plugin'    => 'Manual',
					'reason'    => $reason,
					'timestamp' => gmdate( 'c' ),
					'event_id'  => strtoupper( bin2hex( random_bytes( 8 ) ) ),
				),
				$duration
			);
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Release one address.
	 *
	 * @param string $ip Client address.
	 */
	public function unblock( string $ip ): bool {
		$storage = $this->storage();

		if ( null === $storage ) {
			return false;
		}

		try {
			/*
			 * deleteMatching() where the backend supports it, because it clears
			 * the offense history along with the block. Without that,
			 * blocking_escalation escalates a just-released address straight back
			 * to a longer ban on its next request -- the block would read as
			 * lifted and would not be.
			 */
			if ( $storage instanceof QueryableStorageInterface ) {
				return $storage->deleteMatching( array( $ip ) ) > 0;
			}

			return $storage->delete( $ip );
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Empty the block list.
	 *
	 * @return int How many clients were released, or -1 if the backend cannot say.
	 */
	public function clear(): int {
		$storage = $this->storage();

		if ( null === $storage ) {
			return -1;
		}

		$listing = $this->all();
		$before  = $listing['supported'] ? count( $listing['clients'] ) : -1;

		try {
			// reset() drops blocks and offense history together.
			if ( ! $storage->reset() ) {
				return -1;
			}
		} catch ( \Throwable $e ) {
			return -1;
		}

		return $before;
	}

	/**
	 * Whether the configured backend keeps blocks at all.
	 *
	 * In-memory discards everything when the request ends, so the firewall
	 * evaluates rules and throws the result away while reporting itself enabled.
	 */
	public function is_durable(): bool {
		return 'memory' !== (string) Plugin::instance()->settings()->get( 'storage.backend', 'file' );
	}
}
