//! Gas metering for ZVM
//! Tracks gas consumption and enforces limits

const std = @import("std");

pub const GasError = error{
    OutOfGas,
};

/// Gas meter with limit tracking
pub const Gas = struct {
    limit: u64,
    used: u64,
    refunded: i64,

    pub fn init(limit: u64) Gas {
        return .{
            .limit = limit,
            .used = 0,
            .refunded = 0,
        };
    }

    /// Charge gas for operation
    pub fn charge(self: *Gas, amount: u64) GasError!void {
        const new_used = self.used + amount;
        if (new_used > self.limit) {
            return error.OutOfGas;
        }
        self.used = new_used;
    }

    /// Record gas refund (for SSTORE and SELFDESTRUCT)
    pub fn refund(self: *Gas, amount: i64) void {
        self.refunded += amount;
    }

    /// Get remaining gas
    pub fn remaining(self: *const Gas) u64 {
        return self.limit - self.used;
    }

    /// Get final gas used (after refunds)
    /// Refunds are capped at used_gas / 5 (EIP-3529)
    pub fn finalUsed(self: *const Gas) u64 {
        if (self.refunded <= 0) {
            return self.used;
        }

        const max_refund: i64 = @intCast(self.used / 5);
        const actual_refund = @min(self.refunded, max_refund);

        return self.used - @as(u64, @intCast(actual_refund));
    }

    /// Check if we have enough gas without consuming it
    pub fn checkAvailable(self: *const Gas, amount: u64) bool {
        return self.used + amount <= self.limit;
    }

    /// Get gas usage percentage (for monitoring)
    pub fn usagePercent(self: *const Gas) f64 {
        if (self.limit == 0) return 0.0;
        return @as(f64, @floatFromInt(self.used)) / @as(f64, @floatFromInt(self.limit)) * 100.0;
    }
};

// Tests
test "gas charge and remaining" {
    var gas = Gas.init(100);

    try gas.charge(30);
    try std.testing.expectEqual(@as(u64, 70), gas.remaining());
    try std.testing.expectEqual(@as(u64, 30), gas.used);

    try gas.charge(50);
    try std.testing.expectEqual(@as(u64, 20), gas.remaining());
    try std.testing.expectEqual(@as(u64, 80), gas.used);
}

test "gas out of gas error" {
    var gas = Gas.init(100);

    try gas.charge(90);
    try std.testing.expectError(error.OutOfGas, gas.charge(20));
}

test "gas refund" {
    var gas = Gas.init(1000);
    try gas.charge(500);

    gas.refund(100);
    try std.testing.expectEqual(@as(i64, 100), gas.refunded);

    const final = gas.finalUsed();
    try std.testing.expectEqual(@as(u64, 400), final); // 500 - 100
}

test "gas refund cap" {
    var gas = Gas.init(1000);
    try gas.charge(500);

    // Refund more than allowed (max is used/5 = 100)
    gas.refund(200);

    const final = gas.finalUsed();
    try std.testing.expectEqual(@as(u64, 400), final); // 500 - 100 (capped)
}

test "gas check available" {
    var gas = Gas.init(100);
    try gas.charge(60);

    try std.testing.expect(gas.checkAvailable(30));
    try std.testing.expect(!gas.checkAvailable(50));
}

test "gas usage percent" {
    var gas = Gas.init(1000);
    try gas.charge(250);

    const pct = gas.usagePercent();
    try std.testing.expectApproxEqAbs(25.0, pct, 0.01);
}
