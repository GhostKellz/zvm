//! Core primitive types for ZVM
//! Zero external dependencies - pure Zig implementation

const std = @import("std");

/// 20-byte address (compatible with Ethereum and Hedera)
pub const Address = struct {
    bytes: [20]u8,

    pub fn zero() Address {
        return .{ .bytes = [_]u8{0} ** 20 };
    }

    pub fn fromBytes(bytes: [20]u8) Address {
        return .{ .bytes = bytes };
    }

    pub fn eql(self: Address, other: Address) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn format(
        self: Address,
        comptime _: []const u8,
        _: anytype,
        writer: anytype,
    ) !void {
        try writer.writeAll("0x");
        for (self.bytes) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }
    }
};

/// 32-byte hash
pub const Hash = struct {
    bytes: [32]u8,

    pub fn zero() Hash {
        return .{ .bytes = [_]u8{0} ** 32 };
    }

    pub fn fromBytes(bytes: [32]u8) Hash {
        return .{ .bytes = bytes };
    }

    pub fn eql(self: Hash, other: Hash) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    pub fn format(
        self: Hash,
        comptime _: []const u8,
        _: anytype,
        writer: anytype,
    ) !void {
        try writer.writeAll("0x");
        for (self.bytes) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }
    }
};

/// 256-bit unsigned integer
/// Uses two u128 values for efficient operations
pub const U256 = struct {
    /// High 128 bits
    high: u128,
    /// Low 128 bits
    low: u128,

    pub fn zero() U256 {
        return .{ .high = 0, .low = 0 };
    }

    pub fn one() U256 {
        return .{ .high = 0, .low = 1 };
    }

    pub fn fromU64(value: u64) U256 {
        return .{ .high = 0, .low = value };
    }

    pub fn fromU128(value: u128) U256 {
        return .{ .high = 0, .low = value };
    }

    pub fn fromBytes(bytes: [32]u8) U256 {
        var high: u128 = 0;
        var low: u128 = 0;

        // Big-endian: bytes[0] is most significant
        for (bytes[0..16], 0..) |byte, i| {
            high |= @as(u128, byte) << @intCast((15 - i) * 8);
        }
        for (bytes[16..32], 0..) |byte, i| {
            low |= @as(u128, byte) << @intCast((15 - i) * 8);
        }

        return .{ .high = high, .low = low };
    }

    pub fn toBytes(self: U256) [32]u8 {
        var bytes: [32]u8 = undefined;

        // Big-endian
        for (0..16) |i| {
            bytes[i] = @intCast((self.high >> @intCast((15 - i) * 8)) & 0xFF);
        }
        for (0..16) |i| {
            bytes[16 + i] = @intCast((self.low >> @intCast((15 - i) * 8)) & 0xFF);
        }

        return bytes;
    }

    pub fn toU64(self: U256) u64 {
        return @intCast(self.low & 0xFFFFFFFFFFFFFFFF);
    }

    pub fn toUsize(self: U256) usize {
        return @intCast(self.low & std.math.maxInt(usize));
    }

    pub fn isZero(self: U256) bool {
        return self.high == 0 and self.low == 0;
    }

    pub fn eql(self: U256, other: U256) bool {
        return self.high == other.high and self.low == other.low;
    }

    /// Addition with overflow wrapping (EVM semantics)
    pub fn add(self: U256, other: U256) U256 {
        const low_result = @addWithOverflow(self.low, other.low);
        const high_result = @addWithOverflow(self.high, other.high);
        const carry = @addWithOverflow(high_result[0], low_result[1]);

        return .{
            .high = carry[0],
            .low = low_result[0],
        };
    }

    /// Subtraction with underflow wrapping (EVM semantics)
    pub fn sub(self: U256, other: U256) U256 {
        const low_result = @subWithOverflow(self.low, other.low);
        const high_result = @subWithOverflow(self.high, other.high);
        const borrow = @subWithOverflow(high_result[0], low_result[1]);

        return .{
            .high = borrow[0],
            .low = low_result[0],
        };
    }

    /// Multiplication (lower 256 bits only, overflow wraps)
    pub fn mul(self: U256, other: U256) U256 {
        // For simplicity, we handle the case where both values fit in u128
        // Full 256x256->512 multiplication is complex but can be added later
        if (self.high == 0 and other.high == 0) {
            const result = @as(u256, self.low) *% @as(u256, other.low);
            return .{
                .high = @intCast(result >> 128),
                .low = @intCast(result & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
            };
        }

        // Simplified for now - full implementation needed for production
        return .{ .high = 0, .low = 0 };
    }

    /// Division (panics on divide by zero in EVM)
    pub fn div(self: U256, other: U256) U256 {
        if (other.isZero()) {
            return U256.zero(); // EVM returns 0 on division by zero
        }

        // Simplified: only handle cases where divisor and result fit in u128
        if (other.high == 0 and self.high == 0) {
            return .{
                .high = 0,
                .low = self.low / other.low,
            };
        }

        // Full 256-bit division needed for production
        return U256.zero();
    }

    /// Modulo
    pub fn mod(self: U256, other: U256) U256 {
        if (other.isZero()) {
            return U256.zero(); // EVM returns 0 on modulo by zero
        }

        if (other.high == 0 and self.high == 0) {
            return .{
                .high = 0,
                .low = self.low % other.low,
            };
        }

        return U256.zero();
    }

    /// Bitwise AND
    pub fn bitAnd(self: U256, other: U256) U256 {
        return .{
            .high = self.high & other.high,
            .low = self.low & other.low,
        };
    }

    /// Bitwise OR
    pub fn bitOr(self: U256, other: U256) U256 {
        return .{
            .high = self.high | other.high,
            .low = self.low | other.low,
        };
    }

    /// Bitwise XOR
    pub fn bitXor(self: U256, other: U256) U256 {
        return .{
            .high = self.high ^ other.high,
            .low = self.low ^ other.low,
        };
    }

    /// Bitwise NOT
    pub fn bitNot(self: U256) U256 {
        return .{
            .high = ~self.high,
            .low = ~self.low,
        };
    }

    /// Shift left
    pub fn shl(self: U256, shift: U256) U256 {
        const shift_amount = shift.toU64();
        if (shift_amount >= 256) return U256.zero();

        if (shift_amount >= 128) {
            return .{
                .high = self.low << @intCast(shift_amount - 128),
                .low = 0,
            };
        } else if (shift_amount == 0) {
            return self;
        } else {
            return .{
                .high = (self.high << @intCast(shift_amount)) | (self.low >> @intCast(128 - shift_amount)),
                .low = self.low << @intCast(shift_amount),
            };
        }
    }

    /// Shift right (logical)
    pub fn shr(self: U256, shift: U256) U256 {
        const shift_amount = shift.toU64();
        if (shift_amount >= 256) return U256.zero();

        if (shift_amount >= 128) {
            return .{
                .high = 0,
                .low = self.high >> @intCast(shift_amount - 128),
            };
        } else if (shift_amount == 0) {
            return self;
        } else {
            return .{
                .high = self.high >> @intCast(shift_amount),
                .low = (self.low >> @intCast(shift_amount)) | (self.high << @intCast(128 - shift_amount)),
            };
        }
    }

    /// Less than comparison
    pub fn lt(self: U256, other: U256) bool {
        if (self.high != other.high) {
            return self.high < other.high;
        }
        return self.low < other.low;
    }

    /// Greater than comparison
    pub fn gt(self: U256, other: U256) bool {
        if (self.high != other.high) {
            return self.high > other.high;
        }
        return self.low > other.low;
    }

    pub fn format(
        self: U256,
        comptime _: []const u8,
        _: anytype,
        writer: anytype,
    ) !void {
        if (self.high == 0) {
            try writer.print("{d}", .{self.low});
        } else {
            try writer.print("0x{x:0>32}{x:0>32}", .{ self.high, self.low });
        }
    }
};

/// Dynamic byte array
pub const Bytes = struct {
    data: []const u8,

    pub fn fromSlice(slice: []const u8) Bytes {
        return .{ .data = slice };
    }

    pub fn len(self: Bytes) usize {
        return self.data.len;
    }

    pub fn eql(self: Bytes, other: Bytes) bool {
        return std.mem.eql(u8, self.data, other.data);
    }
};

// Tests
test "Address creation and formatting" {
    const addr = Address.zero();
    try std.testing.expect(addr.eql(Address.zero()));
}

test "U256 basic operations" {
    const a = U256.fromU64(42);
    const b = U256.fromU64(8);

    const sum = a.add(b);
    try std.testing.expectEqual(@as(u64, 50), sum.toU64());

    const diff = a.sub(b);
    try std.testing.expectEqual(@as(u64, 34), diff.toU64());

    const product = a.mul(b);
    try std.testing.expectEqual(@as(u64, 336), product.toU64());

    const quotient = a.div(b);
    try std.testing.expectEqual(@as(u64, 5), quotient.toU64());
}

test "U256 comparisons" {
    const a = U256.fromU64(100);
    const b = U256.fromU64(50);
    const c = U256.fromU64(100);

    try std.testing.expect(a.gt(b));
    try std.testing.expect(b.lt(a));
    try std.testing.expect(a.eql(c));
}

test "U256 bitwise operations" {
    const a = U256.fromU64(0b1010);
    const b = U256.fromU64(0b1100);

    const and_result = a.bitAnd(b);
    try std.testing.expectEqual(@as(u64, 0b1000), and_result.toU64());

    const or_result = a.bitOr(b);
    try std.testing.expectEqual(@as(u64, 0b1110), or_result.toU64());

    const xor_result = a.bitXor(b);
    try std.testing.expectEqual(@as(u64, 0b0110), xor_result.toU64());
}

test "U256 shifts" {
    const a = U256.fromU64(0b1010);
    const shift = U256.fromU64(2);

    const shl_result = a.shl(shift);
    try std.testing.expectEqual(@as(u64, 0b101000), shl_result.toU64());

    const shr_result = a.shr(shift);
    try std.testing.expectEqual(@as(u64, 0b10), shr_result.toU64());
}
