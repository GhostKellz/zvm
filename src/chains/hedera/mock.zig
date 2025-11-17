//! Mock Hedera syscall implementation for testing
//! In production, this would connect to actual Hedera network via ZELIX

const std = @import("std");
const types = @import("../../primitives/types.zig");
const syscalls = @import("syscalls.zig");

const U256 = types.U256;
const Address = types.Address;
const HederaSyscalls = syscalls.HederaSyscalls;
const HTSOperation = syscalls.HTSOperation;
const HCSOperation = syscalls.HCSOperation;
const SyscallResult = syscalls.SyscallResult;
const TokenInfo = syscalls.TokenInfo;

/// Mock Hedera implementation for testing
pub const MockHedera = struct {
    /// Token balances: token_id -> account -> balance
    token_balances: std.AutoHashMap(TokenKey, U256),
    /// Token metadata
    tokens: std.AutoHashMap(Address, TokenInfo),
    /// HCS messages: topic_id -> messages
    hcs_messages: std.AutoHashMap(Address, std.ArrayListUnmanaged([]const u8)),
    /// Allocator
    allocator: std.mem.Allocator,

    const TokenKey = struct {
        token_id: Address,
        account: Address,

        pub fn hash(self: TokenKey) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(&self.token_id.bytes);
            h.update(&self.account.bytes);
            return h.final();
        }

        pub fn eql(self: TokenKey, other: TokenKey) bool {
            return self.token_id.eql(other.token_id) and self.account.eql(other.account);
        }
    };

    pub fn init(allocator: std.mem.Allocator) MockHedera {
        return .{
            .token_balances = std.AutoHashMap(TokenKey, U256).init(allocator),
            .tokens = std.AutoHashMap(Address, TokenInfo).init(allocator),
            .hcs_messages = std.AutoHashMap(Address, std.ArrayListUnmanaged([]const u8)).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MockHedera) void {
        self.token_balances.deinit();

        // Clean up token info
        var token_iter = self.tokens.valueIterator();
        while (token_iter.next()) |info| {
            self.allocator.free(info.name);
            self.allocator.free(info.symbol);
        }
        self.tokens.deinit();

        // Clean up HCS messages
        var msg_iter = self.hcs_messages.valueIterator();
        while (msg_iter.next()) |messages| {
            for (messages.items) |msg| {
                self.allocator.free(msg);
            }
            messages.deinit(self.allocator);
        }
        self.hcs_messages.deinit();
    }

    /// HTS call implementation
    fn htsCallImpl(ptr: *anyopaque, op: HTSOperation, data: []const u8) SyscallResult {
        const self: *MockHedera = @ptrCast(@alignCast(ptr));
        _ = data;

        return switch (op) {
            .TRANSFER => self.htsTransfer(),
            .MINT => self.htsMint(),
            .BURN => self.htsBurn(),
            .BALANCE_OF => self.htsBalanceOf(),
            .TOKEN_INFO => self.htsTokenInfo(),
            .CREATE_TOKEN => self.htsCreateToken(),
            else => SyscallResult{ .error_code = 1 }, // Not implemented
        };
    }

    fn htsTransfer(self: *MockHedera) SyscallResult {
        // Mock transfer - would parse data in real implementation
        _ = self;
        return SyscallResult{ .success = U256.one() };
    }

    fn htsMint(self: *MockHedera) SyscallResult {
        _ = self;
        return SyscallResult{ .success = U256.one() };
    }

    fn htsBurn(self: *MockHedera) SyscallResult {
        _ = self;
        return SyscallResult{ .success = U256.one() };
    }

    fn htsBalanceOf(self: *MockHedera) SyscallResult {
        _ = self;
        return SyscallResult{ .success = U256.fromU64(1000) };
    }

    fn htsTokenInfo(self: *MockHedera) SyscallResult {
        _ = self;
        return SyscallResult{ .success = U256.one() };
    }

    fn htsCreateToken(self: *MockHedera) SyscallResult {
        _ = self;
        // Return mock token address
        return SyscallResult{ .address = Address.zero() };
    }

    /// HCS call implementation
    fn hcsCallImpl(ptr: *anyopaque, op: HCSOperation, data: []const u8) SyscallResult {
        const self: *MockHedera = @ptrCast(@alignCast(ptr));

        return switch (op) {
            .SUBMIT_MESSAGE => self.hcsSubmitMessage(data),
            .CREATE_TOPIC => self.hcsCreateTopic(),
            .TOPIC_INFO => self.hcsTopicInfo(),
            else => SyscallResult{ .error_code = 1 },
        };
    }

    fn hcsSubmitMessage(self: *MockHedera, data: []const u8) SyscallResult {
        // Store message in mock topic
        const topic_id = Address.zero(); // Mock topic

        const msg = self.allocator.dupe(u8, data) catch return SyscallResult{ .error_code = 2 };

        const result = self.hcs_messages.getOrPut(topic_id) catch return SyscallResult{ .error_code = 2 };
        if (!result.found_existing) {
            result.value_ptr.* = .{};
        }
        result.value_ptr.append(self.allocator, msg) catch return SyscallResult{ .error_code = 2 };

        return SyscallResult{ .success = U256.one() };
    }

    fn hcsCreateTopic(self: *MockHedera) SyscallResult {
        _ = self;
        // Return mock topic address
        return SyscallResult{ .address = Address.zero() };
    }

    fn hcsTopicInfo(self: *MockHedera) SyscallResult {
        _ = self;
        return SyscallResult{ .success = U256.one() };
    }

    /// Get balance implementation
    fn getBalanceImpl(ptr: *anyopaque, account: Address) U256 {
        const self: *MockHedera = @ptrCast(@alignCast(ptr));
        const key = TokenKey{
            .token_id = Address.zero(), // Default token
            .account = account,
        };
        return self.token_balances.get(key) orelse U256.zero();
    }

    /// Get token info implementation
    fn getTokenInfoImpl(ptr: *anyopaque, token_id: Address) ?TokenInfo {
        const self: *MockHedera = @ptrCast(@alignCast(ptr));
        return self.tokens.get(token_id);
    }

    /// Convert to HederaSyscalls interface
    pub fn asHederaSyscalls(self: *MockHedera) HederaSyscalls {
        const vtable = comptime &HederaSyscalls.VTable{
            .hts_call = htsCallImpl,
            .hcs_call = hcsCallImpl,
            .get_balance = getBalanceImpl,
            .get_token_info = getTokenInfoImpl,
        };

        return HederaSyscalls{
            .ptr = self,
            .vtable = vtable,
        };
    }

    /// Helper: Set token balance
    pub fn setTokenBalance(self: *MockHedera, token_id: Address, account: Address, balance: U256) !void {
        const key = TokenKey{ .token_id = token_id, .account = account };
        try self.token_balances.put(key, balance);
    }

    /// Helper: Create mock token
    pub fn createMockToken(self: *MockHedera, token_id: Address, name: []const u8, symbol: []const u8, decimals: u8, supply: U256) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const symbol_copy = try self.allocator.dupe(u8, symbol);

        const info = TokenInfo.init(token_id, name_copy, symbol_copy, decimals, supply, Address.zero());
        try self.tokens.put(token_id, info);
    }
};

// Tests
test "mock HTS transfer" {
    var mock = MockHedera.init(std.testing.allocator);
    defer mock.deinit();

    const hedera = mock.asHederaSyscalls();
    const result = hedera.htsCall(.TRANSFER, &[_]u8{});

    try std.testing.expect(result.isSuccess());
}

test "mock HCS submit message" {
    var mock = MockHedera.init(std.testing.allocator);
    defer mock.deinit();

    const hedera = mock.asHederaSyscalls();
    const message = "Hello Hedera!";
    const result = hedera.hcsCall(.SUBMIT_MESSAGE, message);

    try std.testing.expect(result.isSuccess());

    // Verify message was stored
    const topic_id = Address.zero();
    const messages = mock.hcs_messages.get(topic_id).?;
    try std.testing.expectEqual(@as(usize, 1), messages.items.len);
    try std.testing.expectEqualStrings(message, messages.items[0]);
}

test "mock token balance" {
    var mock = MockHedera.init(std.testing.allocator);
    defer mock.deinit();

    const token_id = Address.zero();
    const account = Address.zero();

    try mock.setTokenBalance(token_id, account, U256.fromU64(1000));

    const hedera = mock.asHederaSyscalls();
    const balance = hedera.getBalance(account);

    try std.testing.expectEqual(@as(u64, 1000), balance.toU64());
}

test "mock token creation" {
    var mock = MockHedera.init(std.testing.allocator);
    defer mock.deinit();

    const token_id = Address.zero();
    try mock.createMockToken(token_id, "TestToken", "TEST", 8, U256.fromU64(1_000_000));

    const hedera = mock.asHederaSyscalls();
    const info = hedera.getTokenInfo(token_id).?;

    try std.testing.expectEqualStrings("TestToken", info.name);
    try std.testing.expectEqualStrings("TEST", info.symbol);
    try std.testing.expectEqual(@as(u8, 8), info.decimals);
    try std.testing.expectEqual(@as(u64, 1_000_000), info.total_supply.toU64());
}
