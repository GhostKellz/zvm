//! Example demonstrating persistent contract storage with ZQLite backend
const std = @import("std");
const contract = @import("../src/contract.zig");
const database = @import("../src/database.zig");

/// Example persistent contract that maintains state across restarts
pub const PersistentCounter = struct {
    storage: contract.Storage,
    owner: contract.Address,
    
    const COUNTER_KEY: u256 = 0;
    const LAST_UPDATE_KEY: u256 = 1;
    
    pub fn init(owner: contract.Address, persistent_storage: ?*database.PersistentStorage) PersistentCounter {
        const storage = if (persistent_storage) |ps|
            contract.Storage.initPersistent(std.heap.page_allocator, ps, owner)
        else
            contract.Storage.init(std.heap.page_allocator);
            
        return PersistentCounter{
            .storage = storage,
            .owner = owner,
        };
    }
    
    pub fn deinit(self: *PersistentCounter) void {
        self.storage.deinit();
    }
    
    /// Get current counter value
    pub fn getCounter(self: *PersistentCounter) u256 {
        return self.storage.load(COUNTER_KEY);
    }
    
    /// Increment counter
    pub fn increment(self: *PersistentCounter) !void {
        const current = self.getCounter();
        self.storage.store(COUNTER_KEY, current + 1);
        self.storage.store(LAST_UPDATE_KEY, @intCast(@as(u64, @truncate(@as(u128, std.time.timestamp())))));
        
        std.log.info("Counter incremented from {} to {}", .{ current, current + 1 });
    }
    
    /// Get last update timestamp
    pub fn getLastUpdate(self: *PersistentCounter) u256 {
        return self.storage.load(LAST_UPDATE_KEY);
    }
    
    /// Reset counter (only owner can do this)
    pub fn reset(self: *PersistentCounter, caller: contract.Address) !void {
        if (!std.mem.eql(u8, &caller, &self.owner)) {
            return error.Unauthorized;
        }
        
        self.storage.store(COUNTER_KEY, 0);
        self.storage.store(LAST_UPDATE_KEY, @intCast(@as(u64, @truncate(@as(u128, std.time.timestamp())))));
        
        std.log.info("Counter reset by owner", .{});
    }
};

test "Persistent counter with database backend" {
    // Create database configuration
    const db_config = database.DatabaseConfig{
        .type = .memory, // Use memory for testing, would be .zqlite for real persistence
        .path = ":memory:",
    };
    
    // Initialize persistent storage
    var persistent_storage = try database.PersistentStorage.init(std.testing.allocator, db_config);
    defer persistent_storage.deinit();
    
    // Create contract address and owner
    const contract_address = contract.AddressUtils.random();
    const owner_address = contract.AddressUtils.random();
    
    // Deploy contract with persistent storage
    var counter = PersistentCounter.init(contract_address, &persistent_storage);
    defer counter.deinit();
    
    // Test initial state
    try std.testing.expect(counter.getCounter() == 0);
    
    // Increment counter
    try counter.increment();
    try std.testing.expect(counter.getCounter() == 1);
    
    // Increment again
    try counter.increment();
    try std.testing.expect(counter.getCounter() == 2);
    
    // Test unauthorized reset
    const random_caller = contract.AddressUtils.random();
    try std.testing.expectError(error.Unauthorized, counter.reset(random_caller));
    
    // Test authorized reset
    try counter.reset(contract_address);
    try std.testing.expect(counter.getCounter() == 0);
    
    // Verify timestamp was updated
    const last_update = counter.getLastUpdate();
    try std.testing.expect(last_update > 0);
}

test "Persistent storage across sessions" {
    // This test demonstrates persistence across contract "sessions"
    const db_config = database.DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };
    
    var persistent_storage = try database.PersistentStorage.init(std.testing.allocator, db_config);
    defer persistent_storage.deinit();
    
    const contract_address = contract.AddressUtils.random();
    
    // First session: increment counter
    {
        var counter = PersistentCounter.init(contract_address, &persistent_storage);
        defer counter.deinit();
        
        try counter.increment();
        try counter.increment();
        try counter.increment();
        try std.testing.expect(counter.getCounter() == 3);
    }
    
    // Second session: verify state persisted
    {
        var counter = PersistentCounter.init(contract_address, &persistent_storage);
        defer counter.deinit();
        
        // Counter should still be 3
        try std.testing.expect(counter.getCounter() == 3);
        
        // Continue incrementing
        try counter.increment();
        try std.testing.expect(counter.getCounter() == 4);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Example: Using ZQLite for real persistence
    const db_config = database.DatabaseConfig{
        .type = .zqlite,
        .path = "contracts.db",
        .sync_mode = .full,
    };
    
    std.log.info("Initializing persistent contract storage...", .{});
    
    var persistent_storage = try database.PersistentStorage.init(allocator, db_config);
    defer persistent_storage.deinit();
    
    const contract_address = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
    
    // Create contract with persistent storage
    var counter = PersistentCounter.init(contract_address, &persistent_storage);
    defer counter.deinit();
    
    // Show current state
    const current_value = counter.getCounter();
    std.log.info("Current counter value: {}", .{current_value});
    
    // Increment
    try counter.increment();
    
    // Show new state
    std.log.info("New counter value: {}", .{counter.getCounter()});
    
    // Get statistics
    const stats = try persistent_storage.getStatistics();
    std.log.info("Database statistics:", .{});
    std.log.info("  Total contracts: {}", .{stats.total_contracts});
    std.log.info("  Total storage entries: {}", .{stats.total_storage_entries});
    std.log.info("  Database size: {} bytes", .{stats.database_size_bytes});
    std.log.info("  Cache hit rate: {d:.2}%", .{stats.cache_hit_rate * 100});
}