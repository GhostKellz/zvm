//! Journaled state implementation with checkpoint/rollback support
//! Tracks all state changes for atomic execution and revert support

const std = @import("std");
const types = @import("../primitives/types.zig");
const storage_mod = @import("storage.zig");

const U256 = types.U256;
const Address = types.Address;
const Storage = storage_mod.Storage;
const StorageAccess = storage_mod.StorageAccess;

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

/// Journal entry types
const JournalEntry = union(enum) {
    /// Storage value changed
    storage_changed: struct {
        addr: Address,
        key: U256,
        old_value: U256,
    },
    /// Storage value created (was zero)
    storage_created: struct {
        addr: Address,
        key: U256,
    },
    /// Warm storage access recorded
    storage_warmed: struct {
        addr: Address,
        key: U256,
    },
};

/// Journaled state with checkpoint/rollback support
pub const JournaledState = struct {
    /// Current state
    state: std.AutoHashMap(StorageKey, U256),
    /// Journal of changes (stack of checkpoints)
    journal: std.ArrayListUnmanaged(std.ArrayListUnmanaged(JournalEntry)),
    /// Warm storage tracking (for gas)
    warm_storage: std.AutoHashMap(StorageKey, void),
    /// Allocator
    allocator: std.mem.Allocator,
    /// Current checkpoint depth
    depth: usize,

    pub fn init(allocator: std.mem.Allocator) JournaledState {
        return .{
            .state = std.AutoHashMap(StorageKey, U256).init(allocator),
            .journal = .{},
            .warm_storage = std.AutoHashMap(StorageKey, void).init(allocator),
            .allocator = allocator,
            .depth = 0,
        };
    }

    pub fn deinit(self: *JournaledState) void {
        self.state.deinit();
        self.warm_storage.deinit();
        for (self.journal.items) |*checkpoint| {
            checkpoint.deinit(self.allocator);
        }
        self.journal.deinit(self.allocator);
    }

    /// Load value from storage
    fn loadImpl(ptr: *anyopaque, addr: Address, key: U256) U256 {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        const storage_key = StorageKey{ .addr = addr, .key = key };

        // Mark as warm if not already
        if (!self.warm_storage.contains(storage_key)) {
            self.warm_storage.put(storage_key, {}) catch unreachable;

            // Record warming in journal
            if (self.depth > 0) {
                const entry = JournalEntry{ .storage_warmed = .{ .addr = addr, .key = key } };
                self.journal.items[self.depth - 1].append(self.allocator, entry) catch unreachable;
            }
        }

        return self.state.get(storage_key) orelse U256.zero();
    }

    /// Store value to storage
    fn storeImpl(ptr: *anyopaque, addr: Address, key: U256, value: U256) void {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        const storage_key = StorageKey{ .addr = addr, .key = key };

        const old_value = self.state.get(storage_key);

        // Record change in journal if in a checkpoint
        if (self.depth > 0) {
            const entry = if (old_value) |old|
                JournalEntry{ .storage_changed = .{ .addr = addr, .key = key, .old_value = old } }
            else
                JournalEntry{ .storage_created = .{ .addr = addr, .key = key } };

            self.journal.items[self.depth - 1].append(self.allocator, entry) catch unreachable;
        }

        // Update state
        if (value.isZero()) {
            _ = self.state.remove(storage_key);
        } else {
            self.state.put(storage_key, value) catch unreachable;
        }

        // Mark as warm
        self.warm_storage.put(storage_key, {}) catch unreachable;
    }

    /// Check if storage slot exists (non-zero)
    fn existsImpl(ptr: *anyopaque, addr: Address, key: U256) bool {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        const storage_key = StorageKey{ .addr = addr, .key = key };
        return self.state.contains(storage_key);
    }

    /// Get storage access pattern (for gas calculation)
    fn accessPatternImpl(ptr: *anyopaque, addr: Address, key: U256) StorageAccess {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        const storage_key = StorageKey{ .addr = addr, .key = key };

        return if (self.warm_storage.contains(storage_key))
            StorageAccess.warm
        else
            StorageAccess.cold;
    }

    /// Create checkpoint for nested call
    fn checkpointImpl(ptr: *anyopaque) void {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        self.journal.append(self.allocator, .{}) catch unreachable;
        self.depth += 1;
    }

    /// Commit changes from current checkpoint
    fn commitImpl(ptr: *anyopaque) void {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        if (self.depth == 0) return;

        // Pop and discard journal entries (changes are already applied)
        if (self.journal.pop()) |checkpoint| {
            var cp = checkpoint;
            cp.deinit(self.allocator);
        }
        self.depth -= 1;
    }

    /// Rollback changes to last checkpoint
    fn rollbackImpl(ptr: *anyopaque) void {
        const self: *JournaledState = @ptrCast(@alignCast(ptr));
        if (self.depth == 0) return;

        // Pop journal and revert changes
        if (self.journal.pop()) |checkpoint| {
            var cp = checkpoint;
            defer cp.deinit(self.allocator);
            self.depth -= 1;

            // Replay journal entries in reverse
            var i = cp.items.len;
            while (i > 0) {
                i -= 1;
                const entry = cp.items[i];

                switch (entry) {
                    .storage_changed => |change| {
                        const storage_key = StorageKey{ .addr = change.addr, .key = change.key };
                        self.state.put(storage_key, change.old_value) catch unreachable;
                    },
                    .storage_created => |create| {
                        const storage_key = StorageKey{ .addr = create.addr, .key = create.key };
                        _ = self.state.remove(storage_key);
                    },
                    .storage_warmed => |warm| {
                        const storage_key = StorageKey{ .addr = warm.addr, .key = warm.key };
                        _ = self.warm_storage.remove(storage_key);
                    },
                }
            }
        } else {
            self.depth -= 1;
        }
    }

    /// Convert to Storage interface
    pub fn asStorage(self: *JournaledState) Storage {
        const vtable = comptime &Storage.VTable{
            .load = loadImpl,
            .store = storeImpl,
            .exists = existsImpl,
            .accessPattern = accessPatternImpl,
            .checkpoint = checkpointImpl,
            .commit = commitImpl,
            .rollback = rollbackImpl,
        };

        return Storage{
            .ptr = self,
            .vtable = vtable,
        };
    }
};

// Tests
test "journaled state basic operations" {
    var state = JournaledState.init(std.testing.allocator);
    defer state.deinit();

    const storage = state.asStorage();
    const addr = Address.zero();
    const key = U256.fromU64(1);
    const value = U256.fromU64(42);

    // Store and load
    storage.store(addr, key, value);
    const loaded = storage.load(addr, key);
    try std.testing.expect(loaded.eql(value));
}

test "journaled state checkpoint and commit" {
    var state = JournaledState.init(std.testing.allocator);
    defer state.deinit();

    const storage = state.asStorage();
    const addr = Address.zero();
    const key = U256.fromU64(1);

    // Initial state
    storage.store(addr, key, U256.fromU64(10));

    // Create checkpoint
    storage.checkpoint();

    // Modify in checkpoint
    storage.store(addr, key, U256.fromU64(20));
    try std.testing.expectEqual(@as(u64, 20), storage.load(addr, key).toU64());

    // Commit
    storage.commit();

    // Change should persist
    try std.testing.expectEqual(@as(u64, 20), storage.load(addr, key).toU64());
}

test "journaled state checkpoint and rollback" {
    var state = JournaledState.init(std.testing.allocator);
    defer state.deinit();

    const storage = state.asStorage();
    const addr = Address.zero();
    const key = U256.fromU64(1);

    // Initial state
    storage.store(addr, key, U256.fromU64(10));

    // Create checkpoint
    storage.checkpoint();

    // Modify in checkpoint
    storage.store(addr, key, U256.fromU64(20));
    try std.testing.expectEqual(@as(u64, 20), storage.load(addr, key).toU64());

    // Rollback
    storage.rollback();

    // Should revert to old value
    try std.testing.expectEqual(@as(u64, 10), storage.load(addr, key).toU64());
}

test "journaled state nested checkpoints" {
    var state = JournaledState.init(std.testing.allocator);
    defer state.deinit();

    const storage = state.asStorage();
    const addr = Address.zero();
    const key = U256.fromU64(1);

    // Level 0
    storage.store(addr, key, U256.fromU64(10));

    // Level 1
    storage.checkpoint();
    storage.store(addr, key, U256.fromU64(20));

    // Level 2
    storage.checkpoint();
    storage.store(addr, key, U256.fromU64(30));
    try std.testing.expectEqual(@as(u64, 30), storage.load(addr, key).toU64());

    // Rollback level 2
    storage.rollback();
    try std.testing.expectEqual(@as(u64, 20), storage.load(addr, key).toU64());

    // Commit level 1
    storage.commit();
    try std.testing.expectEqual(@as(u64, 20), storage.load(addr, key).toU64());
}

test "journaled state access patterns" {
    var state = JournaledState.init(std.testing.allocator);
    defer state.deinit();

    const storage = state.asStorage();
    const addr = Address.zero();
    const key = U256.fromU64(1);

    // First access is cold
    try std.testing.expectEqual(StorageAccess.cold, storage.accessPattern(addr, key));

    // Load warms it up
    _ = storage.load(addr, key);

    // Second access is warm
    try std.testing.expectEqual(StorageAccess.warm, storage.accessPattern(addr, key));
}
