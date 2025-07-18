//! Hybrid Smart Contract Example
//! Demonstrates stateless ZVM execution with optional persistent zqlite storage
//! This contract can run in both stateless mode (in-memory) and persistent mode (database)

const std = @import("std");
const zvm = @import("zvm");

/// Hybrid contract that supports both stateless and persistent modes
pub const HybridContract = struct {
    /// Contract state (in-memory for stateless mode)
    counter: u64,
    owner: [20]u8,
    persistent_mode: bool,
    
    /// Database connection (only used in persistent mode)
    db_connection: ?u32,
    
    pub fn init(owner: [20]u8, persistent_mode: bool) HybridContract {
        return HybridContract{
            .counter = 0,
            .owner = owner,
            .persistent_mode = persistent_mode,
            .db_connection = null,
        };
    }
    
    /// Initialize persistent storage (only called in persistent mode)
    pub fn initPersistent(self: *HybridContract, db_path: []const u8) !void {
        if (!self.persistent_mode) return;
        
        // In real implementation, this would:
        // 1. Call db_connect host function
        // 2. Create tables if they don't exist
        // 3. Load existing state from database
        _ = db_path;
        self.db_connection = 1; // Mock connection ID
        
        // Load existing counter from database
        self.counter = try self.loadCounterFromDB();
    }
    
    /// Increment counter (works in both modes)
    pub fn increment(self: *HybridContract) !void {
        self.counter += 1;
        
        if (self.persistent_mode) {
            try self.saveCounterToDB();
        }
    }
    
    /// Get current counter value
    pub fn getCounter(self: *const HybridContract) u64 {
        return self.counter;
    }
    
    /// Set counter value (only owner can do this)
    pub fn setCounter(self: *HybridContract, new_value: u64, caller: [20]u8) !void {
        if (!std.mem.eql(u8, &self.owner, &caller)) {
            return error.Unauthorized;
        }
        
        self.counter = new_value;
        
        if (self.persistent_mode) {
            try self.saveCounterToDB();
        }
    }
    
    /// Load counter from database (persistent mode only)
    fn loadCounterFromDB(self: *const HybridContract) !u64 {
        if (!self.persistent_mode or self.db_connection == null) {
            return 0;
        }
        
        // In real implementation, this would:
        // 1. Call db_query host function with SELECT statement
        // 2. Parse the result
        // 3. Return the counter value
        
        // For now, return a mock value
        return 42;
    }
    
    /// Save counter to database (persistent mode only)
    fn saveCounterToDB(self: *const HybridContract) !void {
        if (!self.persistent_mode or self.db_connection == null) {
            return;
        }
        
        // In real implementation, this would:
        // 1. Call db_execute host function with INSERT/UPDATE statement
        // 2. Handle any errors
        
        // For now, this is a no-op
    }
    
    /// Close database connection (cleanup)
    pub fn deinit(self: *HybridContract) void {
        if (self.persistent_mode and self.db_connection != null) {
            // In real implementation, this would call db_close host function
            self.db_connection = null;
        }
    }
};

/// Example contract deployment and execution
pub fn runHybridContractExample() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== Hybrid Contract Example ===");
    
    // Example owner address
    const owner = [_]u8{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78};
    
    // Test 1: Stateless mode
    std.log.info("1. Testing stateless mode...");
    var stateless_contract = HybridContract.init(owner, false);
    
    try stateless_contract.increment();
    try stateless_contract.increment();
    try stateless_contract.increment();
    
    std.log.info("   Stateless counter: {d}", .{stateless_contract.getCounter()});
    
    // Test 2: Persistent mode
    std.log.info("2. Testing persistent mode...");
    var persistent_contract = HybridContract.init(owner, true);
    
    try persistent_contract.initPersistent("contract_storage.db");
    
    std.log.info("   Loaded counter from DB: {d}", .{persistent_contract.getCounter()});
    
    try persistent_contract.increment();
    try persistent_contract.increment();
    
    std.log.info("   Persistent counter: {d}", .{persistent_contract.getCounter()});
    
    // Test 3: Owner-only operations
    std.log.info("3. Testing owner-only operations...");
    try persistent_contract.setCounter(100, owner);
    std.log.info("   Counter set by owner: {d}", .{persistent_contract.getCounter()});
    
    // Test unauthorized access
    const unauthorized_caller = [_]u8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const result = persistent_contract.setCounter(200, unauthorized_caller);
    if (result) {
        std.log.warn("   Unauthorized access should have failed!");
    } else |err| {
        std.log.info("   Unauthorized access correctly blocked: {}", .{err});
    }
    
    // Cleanup
    persistent_contract.deinit();
    
    std.log.info("=== Hybrid Contract Example Complete ===");
    
    _ = allocator;
}

test "hybrid contract basic functionality" {
    const owner = [_]u8{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78};
    
    var contract = HybridContract.init(owner, false);
    try std.testing.expect(contract.getCounter() == 0);
    
    try contract.increment();
    try std.testing.expect(contract.getCounter() == 1);
    
    try contract.setCounter(42, owner);
    try std.testing.expect(contract.getCounter() == 42);
    
    const unauthorized = [_]u8{0} ** 20;
    try std.testing.expectError(error.Unauthorized, contract.setCounter(100, unauthorized));
}