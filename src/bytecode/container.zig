//! Bytecode Container Format
//! Wraps raw bytecode with metadata, ABI, and versioning information

const std = @import("std");
const primitives = @import("../primitives/types.zig");
const Hash = primitives.Hash;

/// Bytecode container with metadata
pub const BytecodeContainer = struct {
    /// Magic number: "ZVMC" (ZVM Container)
    magic: [4]u8 = "ZVMC".*,

    /// Container format version
    version: u8 = 1,

    /// Target execution environment
    target: Target,

    /// Reserved flags for future use
    flags: u8 = 0,

    /// Size of code section
    code_size: u32,

    /// Size of ABI section
    abi_size: u32,

    /// Actual bytecode
    code: []const u8,

    /// ABI metadata (JSON format, optional)
    abi: []const u8,

    pub const Target = enum(u8) {
        /// Native ZVM bytecode (KALIX-compiled)
        zvm_native = 0,

        /// EVM-compatible bytecode
        evm_compat = 1,

        /// WASM bridge (e.g., Soroban)
        wasm_bridge = 2,
    };

    /// Create container from code and optional ABI
    pub fn create(allocator: std.mem.Allocator, code: []const u8, abi: []const u8, target: Target) !BytecodeContainer {
        const code_copy = try allocator.dupe(u8, code);
        const abi_copy = if (abi.len > 0) try allocator.dupe(u8, abi) else &[_]u8{};

        return BytecodeContainer{
            .target = target,
            .code_size = @intCast(code.len),
            .abi_size = @intCast(abi.len),
            .code = code_copy,
            .abi = abi_copy,
        };
    }

    /// Serialize container to bytes
    pub fn serialize(self: *const BytecodeContainer, allocator: std.mem.Allocator) ![]u8 {
        var buffer: std.ArrayList(u8) = .{};
        errdefer buffer.deinit(allocator);

        // Write header (16 bytes total)
        try buffer.appendSlice(allocator, &self.magic); // 4 bytes
        try buffer.append(allocator, self.version); // 1 byte
        try buffer.append(allocator, @intFromEnum(self.target)); // 1 byte
        try buffer.append(allocator, self.flags); // 1 byte

        // Padding to align (1 byte)
        try buffer.append(allocator, 0);

        // Write sizes (8 bytes)
        try writeU32(&buffer, allocator, self.code_size);
        try writeU32(&buffer, allocator, self.abi_size);

        // Write code section
        try buffer.appendSlice(allocator, self.code);

        // Write ABI section (if present)
        if (self.abi.len > 0) {
            try buffer.appendSlice(allocator, self.abi);
        }

        return buffer.toOwnedSlice(allocator);
    }

    /// Deserialize container from bytes
    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !BytecodeContainer {
        if (data.len < 16) return error.InvalidContainer;

        // Check magic number
        var magic: [4]u8 = undefined;
        @memcpy(&magic, data[0..4]);
        if (!std.mem.eql(u8, &magic, "ZVMC")) return error.InvalidMagic;

        // Parse header
        const version = data[4];
        const target = @as(Target, @enumFromInt(data[5]));
        const flags = data[6];
        // data[7] is padding

        const code_size = std.mem.readInt(u32, data[8..12][0..4], .little);
        const abi_size = std.mem.readInt(u32, data[12..16][0..4], .little);

        // Validate total size
        if (data.len < 16 + code_size + abi_size) return error.TruncatedContainer;

        // Extract sections
        const code_start = 16;
        const code_end = code_start + code_size;
        const abi_start = code_end;
        const abi_end = abi_start + abi_size;

        const code = try allocator.dupe(u8, data[code_start..code_end]);
        const abi = if (abi_size > 0)
            try allocator.dupe(u8, data[abi_start..abi_end])
        else
            &[_]u8{};

        return BytecodeContainer{
            .magic = magic,
            .version = version,
            .target = target,
            .flags = flags,
            .code_size = code_size,
            .abi_size = abi_size,
            .code = code,
            .abi = abi,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: *BytecodeContainer, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        if (self.abi.len > 0) {
            allocator.free(self.abi);
        }
    }

    /// Get code hash
    pub fn getCodeHash(self: *const BytecodeContainer) Hash {
        var hash_bytes: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(self.code, &hash_bytes, .{});
        return Hash.fromBytes(hash_bytes);
    }
};

// Helper functions for writing integers (since .writer() is removed)

fn writeU32(buffer: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try buffer.appendSlice(allocator, &bytes);
}

// =============================================================================
// Tests
// =============================================================================

test "BytecodeContainer creation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const code = [_]u8{ 0x60, 0x80, 0x60, 0x40, 0x52 };
    const abi = [_]u8{};

    var container = try BytecodeContainer.create(allocator, &code, &abi, .zvm_native);
    defer container.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 5), container.code_size);
    try std.testing.expectEqual(@as(u32, 0), container.abi_size);
    try std.testing.expectEqualSlices(u8, &code, container.code);
}

test "BytecodeContainer serialize and deserialize" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const code = [_]u8{ 0x60, 0x80, 0x60, 0x40, 0x52 };
    const abi = "{}";

    var original = try BytecodeContainer.create(allocator, &code, abi, .evm_compat);
    defer original.deinit(allocator);

    // Serialize
    const serialized = try original.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expect(serialized.len >= 16);

    // Deserialize
    var deserialized = try BytecodeContainer.deserialize(serialized, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(original.version, deserialized.version);
    try std.testing.expectEqual(original.target, deserialized.target);
    try std.testing.expectEqual(original.code_size, deserialized.code_size);
    try std.testing.expectEqual(original.abi_size, deserialized.abi_size);
    try std.testing.expectEqualSlices(u8, original.code, deserialized.code);
    try std.testing.expectEqualSlices(u8, original.abi, deserialized.abi);
}

test "BytecodeContainer invalid magic" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const bad_data = [_]u8{ 'B', 'A', 'D', '!', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    const result = BytecodeContainer.deserialize(&bad_data, allocator);
    try std.testing.expectError(error.InvalidMagic, result);
}

test "BytecodeContainer truncated data" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const truncated = [_]u8{ 'Z', 'V', 'M', 'C', 1, 0, 0, 0 }; // Only 8 bytes

    const result = BytecodeContainer.deserialize(&truncated, allocator);
    try std.testing.expectError(error.InvalidContainer, result);
}

test "BytecodeContainer code hash" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const code = [_]u8{ 0x60, 0x80, 0x60, 0x40, 0x52 };

    var container = try BytecodeContainer.create(allocator, &code, &[_]u8{}, .zvm_native);
    defer container.deinit(allocator);

    const hash = container.getCodeHash();
    try std.testing.expect(!hash.eql(Hash.zero()));
}
