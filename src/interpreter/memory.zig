//! Memory implementation for ZVM
//! Dynamic memory with quadratic expansion cost (EVM-compatible)

const std = @import("std");
const types = @import("../primitives/types.zig");
const U256 = types.U256;

pub const MemoryError = error{
    OutOfMemory,
    InvalidOffset,
};

/// Dynamic memory with gas-metered expansion
pub const Memory = struct {
    data: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Memory {
        return .{
            .data = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Memory) void {
        self.data.deinit(self.allocator);
    }

    /// Load 32 bytes from memory at offset
    pub fn load(self: *Memory, offset: usize) !U256 {
        try self.expand(offset + 32);

        var bytes: [32]u8 = undefined;
        @memcpy(&bytes, self.data.items[offset .. offset + 32]);

        return U256.fromBytes(bytes);
    }

    /// Store 32 bytes to memory at offset
    pub fn store(self: *Memory, offset: usize, value: U256) !void {
        try self.expand(offset + 32);

        const bytes = value.toBytes();
        @memcpy(self.data.items[offset .. offset + 32], &bytes);
    }

    /// Store single byte to memory
    pub fn store8(self: *Memory, offset: usize, value: u8) !void {
        try self.expand(offset + 1);
        self.data.items[offset] = value;
    }

    /// Copy data from source to memory
    pub fn copy(self: *Memory, dest_offset: usize, src: []const u8) !void {
        if (src.len == 0) return;

        try self.expand(dest_offset + src.len);
        @memcpy(self.data.items[dest_offset .. dest_offset + src.len], src);
    }

    /// Get slice of memory (read-only)
    pub fn slice(self: *Memory, offset: usize, length: usize) ![]const u8 {
        if (length == 0) return &[_]u8{};

        try self.expand(offset + length);
        return self.data.items[offset .. offset + length];
    }

    /// Get current memory size in bytes
    pub fn size(self: *const Memory) usize {
        return self.data.items.len;
    }

    /// Get memory size in 32-byte words
    pub fn sizeWords(self: *const Memory) usize {
        return (self.size() + 31) / 32;
    }

    /// Calculate gas cost for expanding memory to new_size
    /// Uses quadratic formula: cost = 3*words + words²/512
    pub fn expansionCost(current_size: usize, new_size: usize) u64 {
        if (new_size <= current_size) return 0;

        const current_words = (current_size + 31) / 32;
        const new_words = (new_size + 31) / 32;

        const current_cost = memoryCost(current_words);
        const new_cost = memoryCost(new_words);

        return new_cost - current_cost;
    }

    fn memoryCost(words: usize) u64 {
        const w: u64 = @intCast(words);
        return 3 * w + (w * w) / 512;
    }

    /// Expand memory to at least new_size bytes
    /// Pads with zeros
    fn expand(self: *Memory, new_size: usize) !void {
        const current_size = self.data.items.len;
        if (new_size <= current_size) return;

        // Resize and zero-fill new memory
        try self.data.resize(self.allocator, new_size);
        @memset(self.data.items[current_size..], 0);
    }

    /// Clear all memory (for testing)
    pub fn clear(self: *Memory) void {
        self.data.clearRetainingCapacity();
    }
};

// Tests
test "memory load and store" {
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();

    const value = U256.fromU64(0x123456789ABCDEF0);
    try memory.store(0, value);

    const loaded = try memory.load(0);
    try std.testing.expect(value.eql(loaded));
}

test "memory store8" {
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();

    try memory.store8(0, 0xAB);
    try memory.store8(1, 0xCD);

    const loaded = try memory.load(0);
    const bytes = loaded.toBytes();

    try std.testing.expectEqual(@as(u8, 0xAB), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0xCD), bytes[1]);
}

test "memory copy" {
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();

    const data = [_]u8{ 1, 2, 3, 4, 5 };
    try memory.copy(10, &data);

    const copied = try memory.slice(10, 5);
    try std.testing.expectEqualSlices(u8, &data, copied);
}

test "memory expansion" {
    var memory = Memory.init(std.testing.allocator);
    defer memory.deinit();

    try std.testing.expectEqual(@as(usize, 0), memory.size());

    // Store at offset 64 should expand to at least 96 bytes
    try memory.store(64, U256.fromU64(42));
    try std.testing.expect(memory.size() >= 96);

    // Memory should be zero-filled
    const slice1 = try memory.slice(0, 64);
    for (slice1) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "memory expansion cost" {
    // First 32 bytes: 3 words * 3 = 9 gas + 3²/512 ≈ 9 gas
    const cost1 = Memory.expansionCost(0, 32);
    try std.testing.expectEqual(@as(u64, 3), cost1);

    // Expanding from 32 to 64 bytes
    const cost2 = Memory.expansionCost(32, 64);
    try std.testing.expect(cost2 > 0);

    // No expansion needed
    const cost3 = Memory.expansionCost(64, 32);
    try std.testing.expectEqual(@as(u64, 0), cost3);

    // Large expansion should be expensive (quadratic)
    const cost_small = Memory.expansionCost(0, 1024);
    const cost_large = Memory.expansionCost(0, 4096);
    try std.testing.expect(cost_large > cost_small * 4); // Should be more than linear
}
