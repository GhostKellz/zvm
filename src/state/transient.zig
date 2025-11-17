//! Transient storage implementation (EIP-1153)
//! Storage that is cleared after each transaction

const std = @import("std");
const types = @import("../primitives/types.zig");
const storage_mod = @import("storage.zig");

const U256 = types.U256;
const Address = types.Address;
const TransientStorage = storage_mod.TransientStorage;

/// Storage key for HashMap
const StorageKey = struct {
    addr: Address,
    key: U256,

    pub fn hash(self: StorageKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(&self.addr.bytes);
        const key_bytes = self.key.toBytes();
        h.update(&key_bytes);
        return h.final();
    }

    pub fn eql(self: StorageKey, other: StorageKey) bool {
        return self.addr.eql(other.addr) and self.key.eql(other.key);
    }
};

/// Transient storage implementation
pub const TransientStorageImpl = struct {
    /// Transient state (cleared after transaction)
    state: std.AutoHashMap(StorageKey, U256),
    /// Allocator
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TransientStorageImpl {
        return .{
            .state = std.AutoHashMap(StorageKey, U256).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TransientStorageImpl) void {
        self.state.deinit();
    }

    /// Load from transient storage
    fn loadImpl(ptr: *anyopaque, addr: Address, key: U256) U256 {
        const self: *TransientStorageImpl = @ptrCast(@alignCast(ptr));
        const storage_key = StorageKey{ .addr = addr, .key = key };
        return self.state.get(storage_key) orelse U256.zero();
    }

    /// Store to transient storage
    fn storeImpl(ptr: *anyopaque, addr: Address, key: U256, value: U256) void {
        const self: *TransientStorageImpl = @ptrCast(@alignCast(ptr));
        const storage_key = StorageKey{ .addr = addr, .key = key };

        if (value.isZero()) {
            _ = self.state.remove(storage_key);
        } else {
            self.state.put(storage_key, value) catch unreachable;
        }
    }

    /// Clear all transient storage
    fn clearImpl(ptr: *anyopaque) void {
        const self: *TransientStorageImpl = @ptrCast(@alignCast(ptr));
        self.state.clearRetainingCapacity();
    }

    /// Convert to TransientStorage interface
    pub fn asTransientStorage(self: *TransientStorageImpl) TransientStorage {
        const vtable = comptime &TransientStorage.VTable{
            .load = loadImpl,
            .store = storeImpl,
            .clear = clearImpl,
        };

        return TransientStorage{
            .ptr = self,
            .vtable = vtable,
        };
    }
};

// Tests
test "transient storage basic operations" {
    var tstorage = TransientStorageImpl.init(std.testing.allocator);
    defer tstorage.deinit();

    const storage = tstorage.asTransientStorage();
    const addr = Address.zero();
    const key = U256.fromU64(1);
    const value = U256.fromU64(42);

    // Store and load
    storage.store(addr, key, value);
    const loaded = storage.load(addr, key);
    try std.testing.expect(loaded.eql(value));
}

test "transient storage clear" {
    var tstorage = TransientStorageImpl.init(std.testing.allocator);
    defer tstorage.deinit();

    const storage = tstorage.asTransientStorage();
    const addr = Address.zero();
    const key = U256.fromU64(1);

    // Store value
    storage.store(addr, key, U256.fromU64(42));
    try std.testing.expectEqual(@as(u64, 42), storage.load(addr, key).toU64());

    // Clear
    storage.clear();

    // Should be zero after clear
    try std.testing.expect(storage.load(addr, key).isZero());
}

test "transient storage zero value deletion" {
    var tstorage = TransientStorageImpl.init(std.testing.allocator);
    defer tstorage.deinit();

    const storage = tstorage.asTransientStorage();
    const addr = Address.zero();
    const key = U256.fromU64(1);

    // Store non-zero
    storage.store(addr, key, U256.fromU64(42));
    try std.testing.expectEqual(@as(u64, 42), storage.load(addr, key).toU64());

    // Store zero (should delete)
    storage.store(addr, key, U256.zero());
    try std.testing.expect(storage.load(addr, key).isZero());
}
