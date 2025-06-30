//! Database-backed persistent storage for ZVM
//! Provides SQLite and RocksDB integration for contract state persistence
const std = @import("std");
const contract = @import("contract.zig");

/// Database backend types
pub const DatabaseType = enum {
    sqlite,
    rocksdb,
    memory, // For testing
};

/// Database configuration
pub const DatabaseConfig = struct {
    type: DatabaseType,
    path: []const u8,
    max_connections: u32 = 10,
    cache_size: usize = 1024 * 1024 * 64, // 64MB default
    sync_mode: SyncMode = .normal,
    
    pub const SyncMode = enum {
        off,     // No fsync
        normal,  // fsync on important commits
        full,    // fsync on every commit
    };
};

/// Database errors
pub const DatabaseError = error{
    ConnectionFailed,
    QueryFailed,
    TransactionFailed,
    KeyNotFound,
    SerializationError,
    MigrationFailed,
};

/// Contract storage entry
pub const StorageEntry = struct {
    contract_address: contract.Address,
    storage_key: [32]u8,
    storage_value: [32]u8,
    block_number: u64,
    transaction_hash: [32]u8,
    timestamp: i64,
};

/// Contract metadata entry
pub const ContractEntry = struct {
    address: contract.Address,
    bytecode: []const u8,
    bytecode_format: []const u8, // "ZVM", "EVM", "WASM"
    deployer: contract.Address,
    deployment_tx: [32]u8,
    block_number: u64,
    timestamp: i64,
    abi: ?[]const u8,
};

/// Transaction entry
pub const TransactionEntry = struct {
    hash: [32]u8,
    from_address: contract.Address,
    to_address: ?contract.Address,
    value: u64,
    gas_limit: u64,
    gas_used: u64,
    gas_price: u64,
    data: []const u8,
    nonce: u64,
    block_number: u64,
    transaction_index: u32,
    timestamp: i64,
    status: u8, // 0 = failed, 1 = success
};

/// Database interface for different backends
pub const Database = struct {
    allocator: std.mem.Allocator,
    config: DatabaseConfig,
    backend: Backend,

    const Backend = union(DatabaseType) {
        sqlite: SqliteBackend,
        rocksdb: RocksDbBackend,
        memory: MemoryBackend,
    };

    pub fn init(allocator: std.mem.Allocator, config: DatabaseConfig) !Database {
        const backend = switch (config.type) {
            .sqlite => Backend{ .sqlite = try SqliteBackend.init(allocator, config) },
            .rocksdb => Backend{ .rocksdb = try RocksDbBackend.init(allocator, config) },
            .memory => Backend{ .memory = MemoryBackend.init(allocator) },
        };

        return Database{
            .allocator = allocator,
            .config = config,
            .backend = backend,
        };
    }

    pub fn deinit(self: *Database) void {
        switch (self.backend) {
            .sqlite => |*sqlite| sqlite.deinit(),
            .rocksdb => |*rocksdb| rocksdb.deinit(),
            .memory => |*memory| memory.deinit(),
        }
    }

    /// Initialize database schema
    pub fn migrate(self: *Database) !void {
        switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.migrate(),
            .rocksdb => |*rocksdb| try rocksdb.migrate(),
            .memory => |*memory| try memory.migrate(),
        }
    }

    /// Store contract storage value
    pub fn storeContractStorage(self: *Database, entry: StorageEntry) !void {
        switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.storeContractStorage(entry),
            .rocksdb => |*rocksdb| try rocksdb.storeContractStorage(entry),
            .memory => |*memory| try memory.storeContractStorage(entry),
        }
    }

    /// Load contract storage value
    pub fn loadContractStorage(self: *Database, contract_address: contract.Address, storage_key: [32]u8) !?[32]u8 {
        return switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.loadContractStorage(contract_address, storage_key),
            .rocksdb => |*rocksdb| try rocksdb.loadContractStorage(contract_address, storage_key),
            .memory => |*memory| try memory.loadContractStorage(contract_address, storage_key),
        };
    }

    /// Store contract metadata
    pub fn storeContract(self: *Database, entry: ContractEntry) !void {
        switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.storeContract(entry),
            .rocksdb => |*rocksdb| try rocksdb.storeContract(entry),
            .memory => |*memory| try memory.storeContract(entry),
        }
    }

    /// Get contract metadata
    pub fn getContract(self: *Database, address: contract.Address) !?ContractEntry {
        return switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.getContract(address),
            .rocksdb => |*rocksdb| try rocksdb.getContract(address),
            .memory => |*memory| try memory.getContract(address),
        };
    }

    /// Store transaction
    pub fn storeTransaction(self: *Database, entry: TransactionEntry) !void {
        switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.storeTransaction(entry),
            .rocksdb => |*rocksdb| try rocksdb.storeTransaction(entry),
            .memory => |*memory| try memory.storeTransaction(entry),
        }
    }

    /// Get transaction by hash
    pub fn getTransaction(self: *Database, hash: [32]u8) !?TransactionEntry {
        return switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.getTransaction(hash),
            .rocksdb => |*rocksdb| try rocksdb.getTransaction(hash),
            .memory => |*memory| try memory.getTransaction(hash),
        };
    }

    /// Begin transaction
    pub fn beginTransaction(self: *Database) !void {
        switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.beginTransaction(),
            .rocksdb => |*rocksdb| try rocksdb.beginTransaction(),
            .memory => |*memory| try memory.beginTransaction(),
        }
    }

    /// Commit transaction
    pub fn commitTransaction(self: *Database) !void {
        switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.commitTransaction(),
            .rocksdb => |*rocksdb| try rocksdb.commitTransaction(),
            .memory => |*memory| try memory.commitTransaction(),
        }
    }

    /// Rollback transaction
    pub fn rollbackTransaction(self: *Database) !void {
        switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.rollbackTransaction(),
            .rocksdb => |*rocksdb| try rocksdb.rollbackTransaction(),
            .memory => |*memory| try memory.rollbackTransaction(),
        }
    }

    /// Get database statistics
    pub fn getStatistics(self: *Database) !DatabaseStatistics {
        return switch (self.backend) {
            .sqlite => |*sqlite| try sqlite.getStatistics(),
            .rocksdb => |*rocksdb| try rocksdb.getStatistics(),
            .memory => |*memory| try memory.getStatistics(),
        };
    }
};

pub const DatabaseStatistics = struct {
    total_contracts: u64,
    total_storage_entries: u64,
    total_transactions: u64,
    database_size_bytes: u64,
    cache_hit_rate: f64,
};

/// SQLite backend implementation
const SqliteBackend = struct {
    allocator: std.mem.Allocator,
    config: DatabaseConfig,
    db_path: []const u8,
    in_transaction: bool,

    pub fn init(allocator: std.mem.Allocator, config: DatabaseConfig) !SqliteBackend {
        // In a real implementation, we would initialize SQLite here
        // For now, we'll use a mock implementation
        
        const db_path = try allocator.dupe(u8, config.path);
        
        std.log.info("Initializing SQLite database at: {s}", .{db_path});
        
        return SqliteBackend{
            .allocator = allocator,
            .config = config,
            .db_path = db_path,
            .in_transaction = false,
        };
    }

    pub fn deinit(self: *SqliteBackend) void {
        self.allocator.free(self.db_path);
    }

    pub fn migrate(self: *SqliteBackend) !void {
        std.log.info("Running SQLite migrations for {s}", .{self.db_path});
        
        // Mock SQL migrations
        const migrations = [_][]const u8{
            \\CREATE TABLE IF NOT EXISTS contracts (
            \\    address BLOB PRIMARY KEY,
            \\    bytecode BLOB NOT NULL,
            \\    bytecode_format TEXT NOT NULL,
            \\    deployer BLOB NOT NULL,
            \\    deployment_tx BLOB NOT NULL,
            \\    block_number INTEGER NOT NULL,
            \\    timestamp INTEGER NOT NULL,
            \\    abi TEXT
            \\);
            ,
            \\CREATE TABLE IF NOT EXISTS contract_storage (
            \\    contract_address BLOB NOT NULL,
            \\    storage_key BLOB NOT NULL,
            \\    storage_value BLOB NOT NULL,
            \\    block_number INTEGER NOT NULL,
            \\    transaction_hash BLOB NOT NULL,
            \\    timestamp INTEGER NOT NULL,
            \\    PRIMARY KEY (contract_address, storage_key)
            \\);
            ,
            \\CREATE TABLE IF NOT EXISTS transactions (
            \\    hash BLOB PRIMARY KEY,
            \\    from_address BLOB NOT NULL,
            \\    to_address BLOB,
            \\    value INTEGER NOT NULL,
            \\    gas_limit INTEGER NOT NULL,
            \\    gas_used INTEGER NOT NULL,
            \\    gas_price INTEGER NOT NULL,
            \\    data BLOB,
            \\    nonce INTEGER NOT NULL,
            \\    block_number INTEGER NOT NULL,
            \\    transaction_index INTEGER NOT NULL,
            \\    timestamp INTEGER NOT NULL,
            \\    status INTEGER NOT NULL
            \\);
            ,
            \\CREATE INDEX IF NOT EXISTS idx_contracts_block ON contracts(block_number);
            \\CREATE INDEX IF NOT EXISTS idx_storage_block ON contract_storage(block_number);
            \\CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_number);
            \\CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_address);
            \\CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_address);
        };

        for (migrations) |migration| {
            std.log.debug("Executing: {s}", .{migration[0..@min(50, migration.len)]});
            // In real implementation: sqlite3_exec(db, migration, null, null, null);
        }
    }

    pub fn storeContractStorage(self: *SqliteBackend, entry: StorageEntry) !void {
        _ = self;
        std.log.debug("SQLite: Storing contract storage for {x}", .{std.fmt.fmtSliceHexLower(&entry.contract_address)});
        
        // Mock SQL: INSERT OR REPLACE INTO contract_storage VALUES (?, ?, ?, ?, ?, ?)
        // In real implementation: prepare statement, bind parameters, execute
    }

    pub fn loadContractStorage(self: *SqliteBackend, contract_address: contract.Address, storage_key: [32]u8) !?[32]u8 {
        _ = self;
        _ = contract_address;
        _ = storage_key;
        
        // Mock SQL: SELECT storage_value FROM contract_storage WHERE contract_address = ? AND storage_key = ?
        // In real implementation: prepare statement, bind parameters, execute, fetch result
        
        return null; // Not found
    }

    pub fn storeContract(self: *SqliteBackend, entry: ContractEntry) !void {
        _ = self;
        std.log.debug("SQLite: Storing contract {x}", .{std.fmt.fmtSliceHexLower(&entry.address)});
    }

    pub fn getContract(self: *SqliteBackend, address: contract.Address) !?ContractEntry {
        _ = self;
        _ = address;
        return null;
    }

    pub fn storeTransaction(self: *SqliteBackend, entry: TransactionEntry) !void {
        _ = self;
        std.log.debug("SQLite: Storing transaction {x}", .{std.fmt.fmtSliceHexLower(&entry.hash)});
    }

    pub fn getTransaction(self: *SqliteBackend, hash: [32]u8) !?TransactionEntry {
        _ = self;
        _ = hash;
        return null;
    }

    pub fn beginTransaction(self: *SqliteBackend) !void {
        if (self.in_transaction) return DatabaseError.TransactionFailed;
        self.in_transaction = true;
        std.log.debug("SQLite: BEGIN TRANSACTION");
    }

    pub fn commitTransaction(self: *SqliteBackend) !void {
        if (!self.in_transaction) return DatabaseError.TransactionFailed;
        self.in_transaction = false;
        std.log.debug("SQLite: COMMIT");
    }

    pub fn rollbackTransaction(self: *SqliteBackend) !void {
        if (!self.in_transaction) return DatabaseError.TransactionFailed;
        self.in_transaction = false;
        std.log.debug("SQLite: ROLLBACK");
    }

    pub fn getStatistics(self: *SqliteBackend) !DatabaseStatistics {
        _ = self;
        return DatabaseStatistics{
            .total_contracts = 0,
            .total_storage_entries = 0,
            .total_transactions = 0,
            .database_size_bytes = 0,
            .cache_hit_rate = 0.0,
        };
    }
};

/// RocksDB backend implementation (mock)
const RocksDbBackend = struct {
    allocator: std.mem.Allocator,
    config: DatabaseConfig,
    db_path: []const u8,

    pub fn init(allocator: std.mem.Allocator, config: DatabaseConfig) !RocksDbBackend {
        const db_path = try allocator.dupe(u8, config.path);
        std.log.info("Initializing RocksDB at: {s}", .{db_path});
        
        return RocksDbBackend{
            .allocator = allocator,
            .config = config,
            .db_path = db_path,
        };
    }

    pub fn deinit(self: *RocksDbBackend) void {
        self.allocator.free(self.db_path);
    }

    pub fn migrate(self: *RocksDbBackend) !void {
        _ = self;
        std.log.info("RocksDB: No migrations needed (key-value store)");
    }

    pub fn storeContractStorage(self: *RocksDbBackend, entry: StorageEntry) !void {
        _ = self;
        _ = entry;
        // RocksDB implementation would use column families
        // CF: contract_storage, Key: contract_address + storage_key, Value: storage_value + metadata
    }

    pub fn loadContractStorage(self: *RocksDbBackend, contract_address: contract.Address, storage_key: [32]u8) !?[32]u8 {
        _ = self;
        _ = contract_address;
        _ = storage_key;
        return null;
    }

    pub fn storeContract(self: *RocksDbBackend, entry: ContractEntry) !void {
        _ = self;
        _ = entry;
    }

    pub fn getContract(self: *RocksDbBackend, address: contract.Address) !?ContractEntry {
        _ = self;
        _ = address;
        return null;
    }

    pub fn storeTransaction(self: *RocksDbBackend, entry: TransactionEntry) !void {
        _ = self;
        _ = entry;
    }

    pub fn getTransaction(self: *RocksDbBackend, hash: [32]u8) !?TransactionEntry {
        _ = self;
        _ = hash;
        return null;
    }

    pub fn beginTransaction(self: *RocksDbBackend) !void {
        _ = self;
        // RocksDB transactions are different from SQL transactions
    }

    pub fn commitTransaction(self: *RocksDbBackend) !void {
        _ = self;
    }

    pub fn rollbackTransaction(self: *RocksDbBackend) !void {
        _ = self;
    }

    pub fn getStatistics(self: *RocksDbBackend) !DatabaseStatistics {
        _ = self;
        return DatabaseStatistics{
            .total_contracts = 0,
            .total_storage_entries = 0,
            .total_transactions = 0,
            .database_size_bytes = 0,
            .cache_hit_rate = 0.0,
        };
    }
};

/// In-memory backend for testing
const MemoryBackend = struct {
    allocator: std.mem.Allocator,
    contracts: std.HashMap(contract.Address, ContractEntry, contract.AddressHashContext, std.hash_map.default_max_load_percentage),
    storage: std.HashMap(StorageKey, [32]u8, StorageKeyContext, std.hash_map.default_max_load_percentage),
    transactions: std.HashMap([32]u8, TransactionEntry, HashContext, std.hash_map.default_max_load_percentage),
    in_transaction: bool,

    const StorageKey = struct {
        contract_address: contract.Address,
        storage_key: [32]u8,
    };

    const StorageKeyContext = struct {
        pub fn hash(self: @This(), s: StorageKey) u32 {
            _ = self;
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(&s.contract_address);
            hasher.update(&s.storage_key);
            return @truncate(hasher.final());
        }

        pub fn eql(self: @This(), a: StorageKey, b: StorageKey, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return std.mem.eql(u8, &a.contract_address, &b.contract_address) and
                   std.mem.eql(u8, &a.storage_key, &b.storage_key);
        }
    };

    const HashContext = struct {
        pub fn hash(self: @This(), s: [32]u8) u32 {
            _ = self;
            return @truncate(std.hash_map.hashString(&s));
        }

        pub fn eql(self: @This(), a: [32]u8, b: [32]u8, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return std.mem.eql(u8, &a, &b);
        }
    };

    pub fn init(allocator: std.mem.Allocator) MemoryBackend {
        return MemoryBackend{
            .allocator = allocator,
            .contracts = std.HashMap(contract.Address, ContractEntry, contract.AddressHashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .storage = std.HashMap(StorageKey, [32]u8, StorageKeyContext, std.hash_map.default_max_load_percentage).init(allocator),
            .transactions = std.HashMap([32]u8, TransactionEntry, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .in_transaction = false,
        };
    }

    pub fn deinit(self: *MemoryBackend) void {
        self.contracts.deinit();
        self.storage.deinit();
        self.transactions.deinit();
    }

    pub fn migrate(self: *MemoryBackend) !void {
        _ = self;
        // No migration needed for memory backend
    }

    pub fn storeContractStorage(self: *MemoryBackend, entry: StorageEntry) !void {
        const key = StorageKey{
            .contract_address = entry.contract_address,
            .storage_key = entry.storage_key,
        };
        try self.storage.put(key, entry.storage_value);
    }

    pub fn loadContractStorage(self: *MemoryBackend, contract_address: contract.Address, storage_key: [32]u8) !?[32]u8 {
        const key = StorageKey{
            .contract_address = contract_address,
            .storage_key = storage_key,
        };
        return self.storage.get(key);
    }

    pub fn storeContract(self: *MemoryBackend, entry: ContractEntry) !void {
        try self.contracts.put(entry.address, entry);
    }

    pub fn getContract(self: *MemoryBackend, address: contract.Address) !?ContractEntry {
        return self.contracts.get(address);
    }

    pub fn storeTransaction(self: *MemoryBackend, entry: TransactionEntry) !void {
        try self.transactions.put(entry.hash, entry);
    }

    pub fn getTransaction(self: *MemoryBackend, hash: [32]u8) !?TransactionEntry {
        return self.transactions.get(hash);
    }

    pub fn beginTransaction(self: *MemoryBackend) !void {
        self.in_transaction = true;
    }

    pub fn commitTransaction(self: *MemoryBackend) !void {
        self.in_transaction = false;
    }

    pub fn rollbackTransaction(self: *MemoryBackend) !void {
        self.in_transaction = false;
        // In a real implementation, we would rollback changes
    }

    pub fn getStatistics(self: *MemoryBackend) !DatabaseStatistics {
        return DatabaseStatistics{
            .total_contracts = self.contracts.count(),
            .total_storage_entries = self.storage.count(),
            .total_transactions = self.transactions.count(),
            .database_size_bytes = 0, // Not applicable for memory
            .cache_hit_rate = 1.0, // Everything is in memory
        };
    }
};

/// Database-backed storage for ZVM runtime
pub const PersistentStorage = struct {
    allocator: std.mem.Allocator,
    database: Database,

    pub fn init(allocator: std.mem.Allocator, config: DatabaseConfig) !PersistentStorage {
        var database = try Database.init(allocator, config);
        try database.migrate();

        return PersistentStorage{
            .allocator = allocator,
            .database = database,
        };
    }

    pub fn deinit(self: *PersistentStorage) void {
        self.database.deinit();
    }

    /// Store contract with full metadata
    pub fn storeContractWithMetadata(self: *PersistentStorage, address: contract.Address, bytecode: []const u8, format: []const u8, deployer: contract.Address, deployment_tx: [32]u8, block_number: u64) !void {
        const entry = ContractEntry{
            .address = address,
            .bytecode = try self.allocator.dupe(u8, bytecode),
            .bytecode_format = try self.allocator.dupe(u8, format),
            .deployer = deployer,
            .deployment_tx = deployment_tx,
            .block_number = block_number,
            .timestamp = std.time.timestamp(),
            .abi = null,
        };

        try self.database.storeContract(entry);
    }

    /// Implementation of contract.Storage interface
    pub fn load(self: *PersistentStorage, contract_address: contract.Address, key: u256) !u256 {
        // Convert u256 key to [32]u8
        var key_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &key_bytes, key, .big);

        if (try self.database.loadContractStorage(contract_address, key_bytes)) |value_bytes| {
            return std.mem.readInt(u256, &value_bytes, .big);
        }

        return 0; // Default value for unset storage
    }

    pub fn store(self: *PersistentStorage, contract_address: contract.Address, key: u256, value: u256, block_number: u64, tx_hash: [32]u8) !void {
        var key_bytes: [32]u8 = undefined;
        var value_bytes: [32]u8 = undefined;
        
        std.mem.writeInt(u256, &key_bytes, key, .big);
        std.mem.writeInt(u256, &value_bytes, value, .big);

        const entry = StorageEntry{
            .contract_address = contract_address,
            .storage_key = key_bytes,
            .storage_value = value_bytes,
            .block_number = block_number,
            .transaction_hash = tx_hash,
            .timestamp = std.time.timestamp(),
        };

        try self.database.storeContractStorage(entry);
    }

    /// Batch operations for performance
    pub fn batchStore(self: *PersistentStorage, operations: []const struct {
        contract_address: contract.Address,
        key: u256,
        value: u256,
    }, block_number: u64, tx_hash: [32]u8) !void {
        try self.database.beginTransaction();
        errdefer self.database.rollbackTransaction() catch {};

        for (operations) |op| {
            try self.store(op.contract_address, op.key, op.value, block_number, tx_hash);
        }

        try self.database.commitTransaction();
    }

    /// Get database statistics
    pub fn getStatistics(self: *PersistentStorage) !DatabaseStatistics {
        return self.database.getStatistics();
    }
};

// Tests
test "Database configuration" {
    const config = DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };

    var db = try Database.init(std.testing.allocator, config);
    defer db.deinit();

    try db.migrate();
    
    const stats = try db.getStatistics();
    try std.testing.expect(stats.total_contracts == 0);
}

test "Persistent storage operations" {
    const config = DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };

    var storage = try PersistentStorage.init(std.testing.allocator, config);
    defer storage.deinit();

    const addr = contract.AddressUtils.random();
    const tx_hash = [_]u8{0} ** 32;

    // Store value
    try storage.store(addr, 123, 456, 1000, tx_hash);

    // Load value
    const loaded_value = try storage.load(addr, 123);
    try std.testing.expect(loaded_value == 456);

    // Load non-existent value
    const default_value = try storage.load(addr, 999);
    try std.testing.expect(default_value == 0);
}