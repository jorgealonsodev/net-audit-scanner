# Delta for oui-fingerprint

## MODIFIED Requirements

### Requirement: OUI Database Initialization (was: Embedded OUI Database)

The system MUST initialize the OUI database at first access via `LazyLock`, attempting to load a cached manuf file from `~/.cache/netascan/manuf` first. If the cache is absent or unreadable, the system MUST fall back to the compile-time embedded database. The embedded DB SHALL remain as a permanent failsafe.

(Previously: compile-time-only via `include_dir`.)

#### Scenario: Cache hit initialization

- GIVEN manuf in cache dir → WHEN `OuiDb` initializes → THEN loaded from cache

#### Scenario: Cache miss fallback

- GIVEN no cached manuf file → WHEN `OuiDb` initializes → THEN embedded DB loaded, no error

#### Scenario: Corrupted cache fallback

- GIVEN invalid cached manuf → WHEN `OuiDb` initializes → THEN warning logged, embedded DB loaded

#### Scenario: Malformed lines skipped

- GIVEN invalid manuf lines → WHEN parsed → THEN warnings logged, valid lines indexed

#### Scenario: Unicode preserved

- GIVEN Unicode vendor name → WHEN returned → THEN original chars preserved