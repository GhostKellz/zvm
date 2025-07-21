//! Hybrid Smart Contract Example
//! Demonstrates stateless ZVM execution with optional persistent zqlite storage
//! This contract can run in both stateless mode (in-memory) and persistent mode (database)

const std = @import("std");
const contract = @import("../src/contract.zig");
const database = @import("../src/database.zig");

/// Hybrid contract that supports both stateless and persistent modes
pub const HybridContract = struct {
    /// Contract storage (automatically handles memory vs persistent)
    storage: contract.Storage,
    owner: contract.Address,
    address: contract.Address,
    
    const COUNTER_KEY: u256 = 0;
    const OWNER_KEY: u256 = 1;
    const LAST_CALLER_KEY: u256 = 2;
    
    /// Initialize contract in stateless mode (memory-only)
    pub fn init(allocator: std.mem.Allocator, owner: contract.Address) HybridContract {
        var storage = contract.Storage.init(allocator);
        
        // Store owner in contract storage
        const owner_as_u256 = std.mem.readInt(u256, std.mem.asBytes(&owner)[0..32], .big);
        storage.store(OWNER_KEY, owner_as_u256);
        
        return HybridContract{
            .storage = storage,
            .owner = owner,
            .address = contract.AddressUtils.random(), // Generate random address for this example
        };
    }
    
    /// Initialize contract in persistent mode (database-backed)
    pub fn initPersistent(allocator: std.mem.Allocator, owner: contract.Address, persistent_storage: *database.PersistentStorage) HybridContract {
        const address = contract.AddressUtils.random();
        var storage = contract.Storage.initPersistent(allocator, persistent_storage, address);
        
        // Store owner in contract storage
        const owner_as_u256 = std.mem.readInt(u256, std.mem.asBytes(&owner)[0..32], .big);
        storage.store(OWNER_KEY, owner_as_u256);
        
        return HybridContract{
            .storage = storage,
            .owner = owner,
            .address = address,
        };
    }
    
    pub fn deinit(self: *HybridContract) void {
        self.storage.deinit();
    }
    
    /// Get current counter value
    pub fn getCounter(self: *HybridContract) u256 {
        return self.storage.load(COUNTER_KEY);
    }
    
    /// Increment counter (callable by anyone)
    pub fn increment(self: *HybridContract, caller: contract.Address) !void {
        const current = self.getCounter();
        self.storage.store(COUNTER_KEY, current + 1);
        
        // Store the last caller
        const caller_as_u256 = std.mem.readInt(u256, std.mem.asBytes(&caller)[0..32], .big);
        self.storage.store(LAST_CALLER_KEY, caller_as_u256);
        
        std.log.info("Counter incremented from {} to {} by {x}", .{ current, current + 1, caller });
    }
    
    /// Reset counter (only owner can do this)
    pub fn reset(self: *HybridContract, caller: contract.Address) !void {
        const stored_owner_u256 = self.storage.load(OWNER_KEY);
        var stored_owner: contract.Address = undefined;
        std.mem.writeInt(u256, std.mem.asBytes(&stored_owner)[0..32], stored_owner_u256, .big);
        
        if (!std.mem.eql(u8, &caller, &stored_owner)) {
            return error.Unauthorized;
        }
        
        self.storage.store(COUNTER_KEY, 0);
        
        // Store the last caller
        const caller_as_u256 = std.mem.readInt(u256, std.mem.asBytes(&caller)[0..32], .big);
        self.storage.store(LAST_CALLER_KEY, caller_as_u256);
        
        std.log.info("Counter reset by owner {x}", .{caller});
    }
    
    /// Get last caller address
    pub fn getLastCaller(self: *HybridContract) contract.Address {
        const caller_u256 = self.storage.load(LAST_CALLER_KEY);
        var caller: contract.Address = undefined;
        std.mem.writeInt(u256, std.mem.asBytes(&caller)[0..32], caller_u256, .big);
        return caller;
    }
    
    /// Get contract owner
    pub fn getOwner(self: *HybridContract) contract.Address {
        const owner_u256 = self.storage.load(OWNER_KEY);
        var owner: contract.Address = undefined;
        std.mem.writeInt(u256, std.mem.asBytes(&owner)[0..32], owner_u256, .big);
        return owner;
    }
};

test "Hybrid contract in stateless mode" {
    const owner = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
    const caller = contract.AddressUtils.fromHex("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd") catch unreachable;
    
    var hybrid = HybridContract.init(std.testing.allocator, owner);
    defer hybrid.deinit();
    
    // Test initial state
    try std.testing.expect(hybrid.getCounter() == 0);
    try std.testing.expect(std.mem.eql(u8, &hybrid.getOwner(), &owner));
    
    // Test increment
    try hybrid.increment(caller);
    try std.testing.expect(hybrid.getCounter() == 1);
    try std.testing.expect(std.mem.eql(u8, &hybrid.getLastCaller(), &caller));
    
    // Test multiple increments
    try hybrid.increment(caller);
    try hybrid.increment(caller);
    try std.testing.expect(hybrid.getCounter() == 3);
    
    // Test unauthorized reset
    try std.testing.expectError(error.Unauthorized, hybrid.reset(caller));
    
    // Test authorized reset
    try hybrid.reset(owner);
    try std.testing.expect(hybrid.getCounter() == 0);
    try std.testing.expect(std.mem.eql(u8, &hybrid.getLastCaller(), &owner));
}

test "Hybrid contract in persistent mode" {
    const db_config = database.DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };
    
    var persistent_storage = try database.PersistentStorage.init(std.testing.allocator, db_config);
    defer persistent_storage.deinit();
    
    const owner = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
    const caller = contract.AddressUtils.fromHex("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd") catch unreachable;
    
    var hybrid = HybridContract.initPersistent(std.testing.allocator, owner, &persistent_storage);
    defer hybrid.deinit();
    
    // Test increment in persistent mode
    try hybrid.increment(caller);
    try hybrid.increment(caller);
    try std.testing.expect(hybrid.getCounter() == 2);
    
    // Test reset
    try hybrid.reset(owner);
    try std.testing.expect(hybrid.getCounter() == 0);
}

test "Persistent contract state across sessions" {
    const db_config = database.DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };
    
    var persistent_storage = try database.PersistentStorage.init(std.testing.allocator, db_config);
    defer persistent_storage.deinit();
    
    const owner = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
    const caller = contract.AddressUtils.fromHex("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd") catch unreachable;
    
    var contract_address: contract.Address = undefined;
    
    // First session: deploy and use contract
    {
        var hybrid = HybridContract.initPersistent(std.testing.allocator, owner, &persistent_storage);
        contract_address = hybrid.address;
        
        try hybrid.increment(caller);
        try hybrid.increment(caller);
        try hybrid.increment(caller);
        try std.testing.expect(hybrid.getCounter() == 3);
        
        hybrid.deinit();
    }
    
    // Second session: recreate contract with same address and verify state
    {
        var storage = contract.Storage.initPersistent(std.testing.allocator, &persistent_storage, contract_address);
        var hybrid = HybridContract{
            .storage = storage,
            .owner = owner,
            .address = contract_address,
        };
        defer hybrid.deinit();
        
        // State should be preserved
        try std.testing.expect(hybrid.getCounter() == 3);
        
        // Continue incrementing
        try hybrid.increment(caller);
        try std.testing.expect(hybrid.getCounter() == 4);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== Hybrid Contract Demo ===", .{});
    
    // Demo 1: Stateless mode
    std.log.info("\n1. Stateless Mode (Memory Only):", .{});
    {
        const owner = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
        const caller = contract.AddressUtils.fromHex("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd") catch unreachable;
        
        var hybrid = HybridContract.init(allocator, owner);
        defer hybrid.deinit();
        
        std.log.info("Initial counter: {}", .{hybrid.getCounter()});
        
        try hybrid.increment(caller);
        try hybrid.increment(caller);
        std.log.info("After 2 increments: {}", .{hybrid.getCounter()});
        
        try hybrid.reset(owner);
        std.log.info("After reset: {}", .{hybrid.getCounter()});
    }
    
    // Demo 2: Persistent mode
    std.log.info("\n2. Persistent Mode (Database):", .{});
    {
        const db_config = database.DatabaseConfig{
            .type = .zqlite,
            .path = "hybrid_demo.db",
            .sync_mode = .full,
        };
        
        var persistent_storage = try database.PersistentStorage.init(allocator, db_config);
        defer persistent_storage.deinit();
        
        const owner = contract.AddressUtils.fromHex("0x9876543210987654321098765432109876543210") catch unreachable;
        const caller = contract.AddressUtils.fromHex("0xfedcba9876543210fedcba9876543210fedcba98") catch unreachable;
        
        var hybrid = HybridContract.initPersistent(allocator, owner, &persistent_storage);
        defer hybrid.deinit();
        
        const initial = hybrid.getCounter();
        std.log.info("Initial counter (from DB): {}", .{initial});
        
        try hybrid.increment(caller);
        try hybrid.increment(caller);
        std.log.info("After 2 increments: {}", .{hybrid.getCounter()});
        
        // Show database statistics
        const stats = try persistent_storage.getStatistics();
        std.log.info("Database stats - Storage entries: {}, Size: {} bytes", .{ stats.total_storage_entries, stats.database_size_bytes });
    }
    
    std.log.info("\n=== Demo Complete ===", .{});
}