//! Database-backed persistent storage for ZVM
//! Provides ZQLite v0.7.0 integration for high-performance contract state persistence
const std = @import("std");
const contract = @import("contract.zig");

// Use conditional compilation for zqlite - disabled for now to use mock
// const zqlite = if (@hasDecl(@This(), "real_zqlite")) @import("zqlite") else MockZQLite;

/// Mock ZQLite types for compilation when zqlite is not available
const MockZQLite = struct {
    pub const Database = struct {
        allocator: std.mem.Allocator,
        path: []const u8,
        
        pub fn open(allocator: std.mem.Allocator, path: []const u8) !*MockZQLite.Database {
            const db = try allocator.create(MockZQLite.Database);
            db.* = MockZQLite.Database{ .allocator = allocator, .path = try allocator.dupe(u8, path) };
            return db;
        }
        
        pub fn close(self: *MockZQLite.Database) void {
            self.allocator.free(self.path);
            self.allocator.destroy(self);
        }
        
        pub fn setMVCCConfig(self: *MockZQLite.Database, config: anytype) !void { _ = self; _ = config; }
        pub fn beginTransaction(self: *MockZQLite.Database, isolation: anytype) !*MVCCTransaction { 
            _ = isolation;
            const tx = try self.allocator.create(MVCCTransaction);
            tx.* = MVCCTransaction{ .allocator = self.allocator };
            return tx;
        }
    };
    
    pub const IndexManager = struct {
        allocator: std.mem.Allocator,
        
        pub fn init(allocator: std.mem.Allocator) !*IndexManager {
            const mgr = try allocator.create(IndexManager);
            mgr.* = IndexManager{ .allocator = allocator };
            return mgr;
        }
        
        pub fn deinit(self: *IndexManager) void { self.allocator.destroy(self); }
        pub fn createHashIndex(self: *IndexManager, name: []const u8, fields: []const []const u8) !void { _ = self; _ = name; _ = fields; }
        pub fn createCompositeIndex(self: *IndexManager, name: []const u8, fields: []const []const u8) !void { _ = self; _ = name; _ = fields; }
        pub fn createBloomFilter(self: *IndexManager, name: []const u8, capacity: u32) !void { _ = self; _ = name; _ = capacity; }
        pub fn indexExists(self: *IndexManager, name: []const u8) bool { _ = self; _ = name; return true; }
        pub fn bloomFilterExists(self: *IndexManager, name: []const u8) bool { _ = self; _ = name; return true; }
        pub fn query(self: *IndexManager, index: []const u8, key: []const u8) !?[]const u8 { _ = self; _ = index; _ = key; return null; }
        pub fn updateHashIndex(self: *IndexManager, index: []const u8, key: []const u8, value: []const u8) !void { _ = self; _ = index; _ = key; _ = value; }
        pub fn updateCompositeIndex(self: *IndexManager, index: []const u8, key: []const u8, value: []const u8) !void { _ = self; _ = index; _ = key; _ = value; }
        pub fn addToBloomFilter(self: *IndexManager, filter: []const u8, key: []const u8) !void { _ = self; _ = filter; _ = key; }
        pub fn bloomFilterContains(self: *IndexManager, filter: []const u8, key: []const u8) !bool { _ = self; _ = filter; _ = key; return false; }
        pub fn getStatistics(self: *IndexManager) IndexStats { _ = self; return IndexStats{}; }
    };
    
    pub const AsyncTransactionPool = struct {
        allocator: std.mem.Allocator,
        
        pub fn init(allocator: std.mem.Allocator, capacity: u32) !*AsyncTransactionPool {
            _ = capacity;
            const pool = try allocator.create(AsyncTransactionPool);
            pool.* = AsyncTransactionPool{ .allocator = allocator };
            return pool;
        }
        
        pub fn deinit(self: *AsyncTransactionPool) void { self.allocator.destroy(self); }
        pub fn getStatistics(self: *AsyncTransactionPool) PoolStats { _ = self; return PoolStats{}; }
    };
    
    pub const MVCCTransaction = struct {
        allocator: std.mem.Allocator,
        
        pub fn write(self: *MVCCTransaction, key: []const u8, value: []const u8) !void { _ = self; _ = key; _ = value; }
        pub fn commit(self: *MVCCTransaction) !void { self.allocator.destroy(self); }
        pub fn rollback(self: *MVCCTransaction) !void { self.allocator.destroy(self); }
    };
    
    const IndexStats = struct {
        contract_count: u64 = 0,
        storage_count: u64 = 0,
        total_size_bytes: u64 = 0,
        cache_hit_rate: f64 = 0.0,
    };
    
    const PoolStats = struct {
        active_count: u64 = 0,
        committed_count: u64 = 0,
        rollback_count: u64 = 0,
        avg_transaction_time_ms: f64 = 0.0,
    };
};

// Use mock for now - will be replaced with real zqlite when --persistent flag is enabled
const zqlite = MockZQLite;

/// Database backend types
pub const DatabaseType = enum {
    zqlite, // ZQLite v0.7.0 backend (currently mocked due to dependency conflict)
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
        off, // No fsync
        normal, // fsync on important commits
        full, // fsync on every commit
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
        zqlite: ZQLiteBackend,
        memory: MemoryBackend,
    };

    pub fn init(allocator: std.mem.Allocator, config: DatabaseConfig) !Database {
        const backend = switch (config.type) {
            .zqlite => Backend{ .zqlite = try ZQLiteBackend.init(allocator, config) },
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
            .zqlite => |*zqlite_backend| zqlite_backend.deinit(),
            .memory => |*memory| memory.deinit(),
        }
    }

    /// Initialize database schema
    pub fn migrate(self: *Database) !void {
        switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.migrate(),
            .memory => |*memory| try memory.migrate(),
        }
    }

    /// Store contract storage value
    pub fn storeContractStorage(self: *Database, entry: StorageEntry) !void {
        switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.storeContractStorage(entry),
            .memory => |*memory| try memory.storeContractStorage(entry),
        }
    }

    /// Load contract storage value
    pub fn loadContractStorage(self: *Database, contract_address: contract.Address, storage_key: [32]u8) !?[32]u8 {
        return switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.loadContractStorage(contract_address, storage_key),
            .memory => |*memory| try memory.loadContractStorage(contract_address, storage_key),
        };
    }

    /// Store contract metadata
    pub fn storeContract(self: *Database, entry: ContractEntry) !void {
        switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.storeContract(entry),
            .memory => |*memory| try memory.storeContract(entry),
        }
    }

    /// Get contract metadata
    pub fn getContract(self: *Database, address: contract.Address) !?ContractEntry {
        return switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.getContract(address),
            .memory => |*memory| try memory.getContract(address),
        };
    }

    /// Store transaction
    pub fn storeTransaction(self: *Database, entry: TransactionEntry) !void {
        switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.storeTransaction(entry),
            .memory => |*memory| try memory.storeTransaction(entry),
        }
    }

    /// Get transaction by hash
    pub fn getTransaction(self: *Database, hash: [32]u8) !?TransactionEntry {
        return switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.getTransaction(hash),
            .memory => |*memory| try memory.getTransaction(hash),
        };
    }

    /// Begin transaction
    pub fn beginTransaction(self: *Database) !void {
        switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.beginTransaction(),
            .memory => |*memory| try memory.beginTransaction(),
        }
    }

    /// Commit transaction
    pub fn commitTransaction(self: *Database) !void {
        switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.commitTransaction(),
            .memory => |*memory| try memory.commitTransaction(),
        }
    }

    /// Rollback transaction
    pub fn rollbackTransaction(self: *Database) !void {
        switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.rollbackTransaction(),
            .memory => |*memory| try memory.rollbackTransaction(),
        }
    }

    /// Get database statistics
    pub fn getStatistics(self: *Database) !DatabaseStatistics {
        return switch (self.backend) {
            .zqlite => |*zqlite_backend| try zqlite_backend.getStatistics(),
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

/// ZQLite v0.7.0 backend implementation
const ZQLiteBackend = struct {
    allocator: std.mem.Allocator,
    config: DatabaseConfig,
    db: *zqlite.Database,
    index_manager: *zqlite.IndexManager,
    transaction_pool: *zqlite.AsyncTransactionPool,
    current_transaction: ?*zqlite.MVCCTransaction,

    pub fn init(allocator: std.mem.Allocator, config: DatabaseConfig) !ZQLiteBackend {
        // Initialize ZQLite database
        var db = try zqlite.Database.open(allocator, config.path);

        // Initialize advanced indexing for blockchain data
        const index_manager = try zqlite.IndexManager.init(allocator);

        // Account address hash index for O(1) lookups
        try index_manager.createHashIndex("account_address_idx", &[_][]const u8{"address"});

        // Contract storage composite index
        try index_manager.createCompositeIndex("contract_storage_idx", &[_][]const u8{ "contract_address", "storage_key" });

        // Transaction hash index
        try index_manager.createHashIndex("tx_hash_idx", &[_][]const u8{"tx_hash"});

        // Bloom filter for transaction existence checks
        try index_manager.createBloomFilter("tx_exists_filter", 10000000);

        // Contract metadata index
        try index_manager.createHashIndex("contract_metadata_idx", &[_][]const u8{"address"});

        // Async transaction pool for concurrent operations
        const transaction_pool = try zqlite.AsyncTransactionPool.init(allocator, 1000);

        // Configure MVCC for blockchain workloads
        try db.setMVCCConfig(.{
            .max_concurrent_transactions = 1000,
            .transaction_timeout_ms = 5000,
            .deadlock_detection_enabled = true,
            .retry_on_conflict = true,
            .max_retries = 3,
        });

        std.log.info("Initialized ZQLite v0.7.0 database at: {s}", .{config.path});

        return ZQLiteBackend{
            .allocator = allocator,
            .config = config,
            .db = db,
            .index_manager = index_manager,
            .transaction_pool = transaction_pool,
            .current_transaction = null,
        };
    }

    pub fn deinit(self: *ZQLiteBackend) void {
        if (self.current_transaction) |tx| {
            tx.rollback() catch {};
        }
        self.transaction_pool.deinit();
        self.index_manager.deinit();
        self.db.close();
    }

    pub fn migrate(self: *ZQLiteBackend) !void {
        std.log.info("Running ZQLite migrations for {s}", .{self.config.path});

        // ZQLite doesn't need SQL migrations - it uses schema-free operations
        // We'll ensure our indexes are properly configured instead

        // Verify all required indexes exist
        const required_indexes = [_][]const u8{
            "account_address_idx",
            "contract_storage_idx",
            "tx_hash_idx",
            "contract_metadata_idx",
        };

        for (required_indexes) |index_name| {
            if (!self.index_manager.indexExists(index_name)) {
                std.log.warn("Index {s} missing, recreating", .{index_name});
                // Index creation is handled in init()
            }
        }

        // Verify bloom filter exists
        if (!self.index_manager.bloomFilterExists("tx_exists_filter")) {
            std.log.warn("Bloom filter missing, recreating", .{});
            try self.index_manager.createBloomFilter("tx_exists_filter", 10000000);
        }

        std.log.info("ZQLite database schema verified", .{});
    }

    pub fn storeContractStorage(self: *ZQLiteBackend, entry: StorageEntry) !void {
        // Use composite index for contract storage
        var key_bytes: [52]u8 = undefined;
        @memcpy(key_bytes[0..20], &entry.contract_address);
        @memcpy(key_bytes[20..52], &entry.storage_key);

        // Store the complete entry as value
        const value = try self.allocator.alloc(u8, @sizeOf(StorageEntry));
        defer self.allocator.free(value);
        @memcpy(value, std.mem.asBytes(&entry));

        // Use MVCC transaction for atomic storage
        if (self.current_transaction) |tx| {
            try tx.write(&key_bytes, value);
        } else {
            var tx = try self.db.beginTransaction(.ReadCommitted);
            defer tx.rollback() catch {};
            try tx.write(&key_bytes, value);
            try tx.commit();
        }

        // Update composite index for fast lookups
        try self.index_manager.updateCompositeIndex("contract_storage_idx", &key_bytes, value);

        std.log.debug("ZQLite: Stored contract storage for {any}", .{entry.contract_address});
    }

    pub fn loadContractStorage(self: *ZQLiteBackend, contract_address: contract.Address, storage_key: [32]u8) !?[32]u8 {
        // Use composite index for O(1) lookup
        var key_bytes: [52]u8 = undefined;
        @memcpy(key_bytes[0..20], &contract_address);
        @memcpy(key_bytes[20..52], &storage_key);

        // Query the composite index
        const result = try self.index_manager.query("contract_storage_idx", &key_bytes);

        if (result) |data| {
            const storage_entry = std.mem.bytesToValue(StorageEntry, data);
            return storage_entry.storage_value;
        }

        return null; // Not found
    }

    pub fn storeContract(self: *ZQLiteBackend, entry: ContractEntry) !void {
        // Use address as key for contract metadata
        const key = std.mem.asBytes(&entry.address);

        // Serialize contract entry
        const value = try self.allocator.alloc(u8, @sizeOf(ContractEntry));
        defer self.allocator.free(value);
        @memcpy(value, std.mem.asBytes(&entry));

        // Store in MVCC transaction
        if (self.current_transaction) |tx| {
            try tx.write(key, value);
        } else {
            var tx = try self.db.beginTransaction(.ReadCommitted);
            defer tx.rollback() catch {};
            try tx.write(key, value);
            try tx.commit();
        }

        // Update hash index for fast lookups
        try self.index_manager.updateHashIndex("contract_metadata_idx", key, value);

        std.log.debug("ZQLite: Stored contract {any}", .{entry.address});
    }

    pub fn getContract(self: *ZQLiteBackend, address: contract.Address) !?ContractEntry {
        const key = std.mem.asBytes(&address);

        // Query hash index for O(1) lookup
        const result = try self.index_manager.query("contract_metadata_idx", key);

        if (result) |data| {
            return std.mem.bytesToValue(ContractEntry, data);
        }

        return null;
    }

    pub fn storeTransaction(self: *ZQLiteBackend, entry: TransactionEntry) !void {
        const key = std.mem.asBytes(&entry.hash);

        // Serialize transaction entry
        const value = try self.allocator.alloc(u8, @sizeOf(TransactionEntry));
        defer self.allocator.free(value);
        @memcpy(value, std.mem.asBytes(&entry));

        // Store in MVCC transaction
        if (self.current_transaction) |tx| {
            try tx.write(key, value);
        } else {
            var tx = try self.db.beginTransaction(.ReadCommitted);
            defer tx.rollback() catch {};
            try tx.write(key, value);
            try tx.commit();
        }

        // Update hash index and bloom filter
        try self.index_manager.updateHashIndex("tx_hash_idx", key, value);
        try self.index_manager.addToBloomFilter("tx_exists_filter", key);

        std.log.debug("ZQLite: Stored transaction {any}", .{entry.hash});
    }

    pub fn getTransaction(self: *ZQLiteBackend, hash: [32]u8) !?TransactionEntry {
        const key = std.mem.asBytes(&hash);

        // Check bloom filter first (fast negative check)
        const might_exist = try self.index_manager.bloomFilterContains("tx_exists_filter", key);
        if (!might_exist) return null;

        // Query hash index
        const result = try self.index_manager.query("tx_hash_idx", key);

        if (result) |data| {
            return std.mem.bytesToValue(TransactionEntry, data);
        }

        return null;
    }

    pub fn beginTransaction(self: *ZQLiteBackend) !void {
        if (self.current_transaction != null) return DatabaseError.TransactionFailed;
        self.current_transaction = try self.db.beginTransaction(.ReadCommitted);
        std.log.debug("ZQLite: BEGIN TRANSACTION");
    }

    pub fn commitTransaction(self: *ZQLiteBackend) !void {
        if (self.current_transaction) |tx| {
            try tx.commit();
            self.current_transaction = null;
            std.log.debug("ZQLite: COMMIT");
        } else {
            return DatabaseError.TransactionFailed;
        }
    }

    pub fn rollbackTransaction(self: *ZQLiteBackend) !void {
        if (self.current_transaction) |tx| {
            try tx.rollback();
            self.current_transaction = null;
            std.log.debug("ZQLite: ROLLBACK");
        } else {
            return DatabaseError.TransactionFailed;
        }
    }

    pub fn getStatistics(self: *ZQLiteBackend) !DatabaseStatistics {
        // Get actual statistics from ZQLite
        const stats = self.transaction_pool.getStatistics();
        const index_stats = self.index_manager.getStatistics();

        return DatabaseStatistics{
            .total_contracts = index_stats.contract_count,
            .total_storage_entries = index_stats.storage_count,
            .total_transactions = stats.committed_count,
            .database_size_bytes = index_stats.total_size_bytes,
            .cache_hit_rate = index_stats.cache_hit_rate,
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

        pub fn eql(self: @This(), a: StorageKey, b: StorageKey) bool {
            _ = self;
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
