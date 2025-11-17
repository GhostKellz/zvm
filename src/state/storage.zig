//! Storage interface and implementations for ZVM
//! Provides trait-like storage abstraction for different backends

const std = @import("std");
const types = @import("../primitives/types.zig");
const U256 = types.U256;
const Address = types.Address;

/// Storage key-value pair
pub const StorageSlot = struct {
    key: U256,
    value: U256,

    pub fn init(key: U256, value: U256) StorageSlot {
        return .{ .key = key, .value = value };
    }
};

/// Storage access pattern (for gas accounting)
pub const StorageAccess = enum {
    cold, // First access - expensive
    warm, // Subsequent access - cheaper
};

/// Storage interface (trait-like)
pub const Storage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Load value from storage
        load: *const fn (ptr: *anyopaque, addr: Address, key: U256) U256,
        /// Store value to storage
        store: *const fn (ptr: *anyopaque, addr: Address, key: U256, value: U256) void,
        /// Check if slot exists (non-zero)
        exists: *const fn (ptr: *anyopaque, addr: Address, key: U256) bool,
        /// Get storage access pattern (for gas)
        accessPattern: *const fn (ptr: *anyopaque, addr: Address, key: U256) StorageAccess,
        /// Create checkpoint for nested calls
        checkpoint: *const fn (ptr: *anyopaque) void,
        /// Commit changes from current checkpoint
        commit: *const fn (ptr: *anyopaque) void,
        /// Rollback changes to last checkpoint
        rollback: *const fn (ptr: *anyopaque) void,
    };

    pub fn load(self: Storage, addr: Address, key: U256) U256 {
        return self.vtable.load(self.ptr, addr, key);
    }

    pub fn store(self: Storage, addr: Address, key: U256, value: U256) void {
        self.vtable.store(self.ptr, addr, key, value);
    }

    pub fn exists(self: Storage, addr: Address, key: U256) bool {
        return self.vtable.exists(self.ptr, addr, key);
    }

    pub fn accessPattern(self: Storage, addr: Address, key: U256) StorageAccess {
        return self.vtable.accessPattern(self.ptr, addr, key);
    }

    pub fn checkpoint(self: Storage) void {
        self.vtable.checkpoint(self.ptr);
    }

    pub fn commit(self: Storage) void {
        self.vtable.commit(self.ptr);
    }

    pub fn rollback(self: Storage) void {
        self.vtable.rollback(self.ptr);
    }
};

/// Transient storage (EIP-1153) - cleared after transaction
pub const TransientStorage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        load: *const fn (ptr: *anyopaque, addr: Address, key: U256) U256,
        store: *const fn (ptr: *anyopaque, addr: Address, key: U256, value: U256) void,
        clear: *const fn (ptr: *anyopaque) void,
    };

    pub fn load(self: TransientStorage, addr: Address, key: U256) U256 {
        return self.vtable.load(self.ptr, addr, key);
    }

    pub fn store(self: TransientStorage, addr: Address, key: U256, value: U256) void {
        self.vtable.store(self.ptr, addr, key, value);
    }

    pub fn clear(self: TransientStorage) void {
        self.vtable.clear(self.ptr);
    }
};
