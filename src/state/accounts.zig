//! Account State Management
//! Tracks account balances, bytecode, nonces, and contract vs EOA distinction

const std = @import("std");
const primitives = @import("../primitives/types.zig");
const Address = primitives.Address;
const Hash = primitives.Hash;
const U256 = primitives.U256;

/// Represents a single account (contract or EOA)
pub const Account = struct {
    address: Address,
    balance: U256,
    nonce: u64,
    code: []const u8,
    code_hash: Hash,
    is_contract: bool,

    pub fn init(address: Address) Account {
        return .{
            .address = address,
            .balance = U256.zero(),
            .nonce = 0,
            .code = &[_]u8{},
            .code_hash = Hash.zero(),
            .is_contract = false,
        };
    }

    /// Deploy contract bytecode to this account
    pub fn deployContract(self: *Account, allocator: std.mem.Allocator, bytecode: []const u8) !void {
        // Free existing code if any
        if (self.code.len > 0) {
            allocator.free(self.code);
        }

        // Store new bytecode
        self.code = try allocator.dupe(u8, bytecode);
        self.code_hash = keccak256(bytecode);
        self.is_contract = true;
    }

    /// Free owned memory
    pub fn deinit(self: *Account, allocator: std.mem.Allocator) void {
        if (self.code.len > 0) {
            allocator.free(self.code);
        }
    }
};

/// Manages all accounts in the system
pub const AccountState = struct {
    accounts: std.AutoHashMap(Address, Account),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AccountState {
        return .{
            .accounts = std.AutoHashMap(Address, Account).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AccountState) void {
        // Free all contract bytecode
        var iter = self.accounts.valueIterator();
        while (iter.next()) |account| {
            if (account.code.len > 0) {
                self.allocator.free(account.code);
            }
        }
        self.accounts.deinit();
    }

    /// Get mutable reference to account
    pub fn getAccount(self: *AccountState, addr: Address) ?*Account {
        return self.accounts.getPtr(addr);
    }

    /// Get immutable reference to account
    pub fn getAccountConst(self: *const AccountState, addr: Address) ?Account {
        return self.accounts.get(addr);
    }

    /// Create new account (fails if already exists)
    pub fn createAccount(self: *AccountState, addr: Address) !*Account {
        const account = Account.init(addr);
        try self.accounts.put(addr, account);
        return self.accounts.getPtr(addr).?;
    }

    /// Get or create account
    pub fn getOrCreateAccount(self: *AccountState, addr: Address) !*Account {
        if (self.accounts.getPtr(addr)) |existing| {
            return existing;
        }
        return self.createAccount(addr);
    }

    /// Check if account exists
    pub fn exists(self: *const AccountState, addr: Address) bool {
        return self.accounts.contains(addr);
    }

    /// Get account balance
    pub fn getBalance(self: *const AccountState, addr: Address) U256 {
        if (self.accounts.get(addr)) |account| {
            return account.balance;
        }
        return U256.zero();
    }

    /// Set account balance
    pub fn setBalance(self: *AccountState, addr: Address, balance: U256) !void {
        const account = try self.getOrCreateAccount(addr);
        account.balance = balance;
    }

    /// Transfer value between accounts
    pub fn transfer(self: *AccountState, from: Address, to: Address, value: U256) !void {
        if (value.isZero()) return; // No-op for zero transfers

        const from_account = self.accounts.getPtr(from) orelse return error.AccountNotFound;
        if (from_account.balance.lt(value)) return error.InsufficientBalance;

        // Deduct from sender
        from_account.balance = from_account.balance.sub(value);

        // Add to recipient (create if needed)
        const to_account = try self.getOrCreateAccount(to);
        to_account.balance = to_account.balance.add(value);
    }

    /// Increment account nonce
    pub fn incrementNonce(self: *AccountState, addr: Address) !void {
        const account = try self.getOrCreateAccount(addr);
        account.nonce += 1;
    }

    /// Get account nonce
    pub fn getNonce(self: *const AccountState, addr: Address) u64 {
        if (self.accounts.get(addr)) |account| {
            return account.nonce;
        }
        return 0;
    }

    /// Get account code
    pub fn getCode(self: *const AccountState, addr: Address) []const u8 {
        if (self.accounts.get(addr)) |account| {
            return account.code;
        }
        return &[_]u8{};
    }

    /// Get code hash
    pub fn getCodeHash(self: *const AccountState, addr: Address) Hash {
        if (self.accounts.get(addr)) |account| {
            return account.code_hash;
        }
        return Hash.zero();
    }

    /// Check if address is a contract
    pub fn isContract(self: *const AccountState, addr: Address) bool {
        if (self.accounts.get(addr)) |account| {
            return account.is_contract;
        }
        return false;
    }

    /// Deploy contract to address
    pub fn deployContract(self: *AccountState, addr: Address, bytecode: []const u8) !void {
        const account = try self.getOrCreateAccount(addr);
        try account.deployContract(self.allocator, bytecode);
    }

    /// Destroy account (SELFDESTRUCT)
    pub fn destroyAccount(self: *AccountState, addr: Address) void {
        if (self.accounts.getPtr(addr)) |account| {
            account.deinit(self.allocator);
            _ = self.accounts.remove(addr);
        }
    }

    /// Get total number of accounts
    pub fn count(self: *const AccountState) usize {
        return self.accounts.count();
    }
};

/// Simplified keccak256 hash (using Zig's built-in Keccak)
fn keccak256(data: []const u8) Hash {
    var hash_bytes: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(data, &hash_bytes, .{});
    return Hash.fromBytes(hash_bytes);
}

// =============================================================================
// Tests
// =============================================================================

test "Account init" {
    const addr = Address.zero();
    const account = Account.init(addr);

    try std.testing.expect(account.address.eql(addr));
    try std.testing.expect(account.balance.isZero());
    try std.testing.expectEqual(@as(u64, 0), account.nonce);
    try std.testing.expectEqual(@as(usize, 0), account.code.len);
    try std.testing.expect(!account.is_contract);
}

test "Account deploy contract" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const addr = Address.zero();
    var account = Account.init(addr);
    defer account.deinit(allocator);

    const bytecode = [_]u8{ 0x60, 0x80, 0x60, 0x40, 0x52 }; // Sample bytecode
    try account.deployContract(allocator, &bytecode);

    try std.testing.expect(account.is_contract);
    try std.testing.expectEqual(@as(usize, 5), account.code.len);
    try std.testing.expectEqualSlices(u8, &bytecode, account.code);
}

test "AccountState creation and retrieval" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = AccountState.init(allocator);
    defer state.deinit();

    const addr1 = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);

    // Create account
    const account = try state.createAccount(addr1);
    try std.testing.expect(account.address.eql(addr1));
    try std.testing.expectEqual(@as(usize, 1), state.count());

    // Retrieve account
    const retrieved = state.getAccount(addr1);
    try std.testing.expect(retrieved != null);
    try std.testing.expect(retrieved.?.address.eql(addr1));
}

test "AccountState balance operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = AccountState.init(allocator);
    defer state.deinit();

    const addr = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);

    // Set balance
    try state.setBalance(addr, U256.fromU64(1000));

    const balance = state.getBalance(addr);
    try std.testing.expectEqual(@as(u64, 1000), balance.toU64());
}

test "AccountState transfer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = AccountState.init(allocator);
    defer state.deinit();

    const addr1 = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    const addr2 = Address.fromBytes([_]u8{2} ++ [_]u8{0} ** 19);

    // Setup: addr1 has 1000, addr2 has 0
    try state.setBalance(addr1, U256.fromU64(1000));

    // Transfer 300 from addr1 to addr2
    try state.transfer(addr1, addr2, U256.fromU64(300));

    const balance1 = state.getBalance(addr1);
    const balance2 = state.getBalance(addr2);

    try std.testing.expectEqual(@as(u64, 700), balance1.toU64());
    try std.testing.expectEqual(@as(u64, 300), balance2.toU64());
}

test "AccountState transfer insufficient balance" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = AccountState.init(allocator);
    defer state.deinit();

    const addr1 = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    const addr2 = Address.fromBytes([_]u8{2} ++ [_]u8{0} ** 19);

    try state.setBalance(addr1, U256.fromU64(100));

    // Try to transfer more than balance
    const result = state.transfer(addr1, addr2, U256.fromU64(200));
    try std.testing.expectError(error.InsufficientBalance, result);
}

test "AccountState nonce operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = AccountState.init(allocator);
    defer state.deinit();

    const addr = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);

    try std.testing.expectEqual(@as(u64, 0), state.getNonce(addr));

    try state.incrementNonce(addr);
    try std.testing.expectEqual(@as(u64, 1), state.getNonce(addr));

    try state.incrementNonce(addr);
    try std.testing.expectEqual(@as(u64, 2), state.getNonce(addr));
}

test "AccountState contract deployment" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = AccountState.init(allocator);
    defer state.deinit();

    const addr = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);
    const bytecode = [_]u8{ 0x60, 0x80, 0x60, 0x40, 0x52 };

    try state.deployContract(addr, &bytecode);

    try std.testing.expect(state.isContract(addr));
    const code = state.getCode(addr);
    try std.testing.expectEqual(@as(usize, 5), code.len);
    try std.testing.expectEqualSlices(u8, &bytecode, code);

    const code_hash = state.getCodeHash(addr);
    try std.testing.expect(!code_hash.eql(Hash.zero()));
}

test "AccountState destroy account" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = AccountState.init(allocator);
    defer state.deinit();

    const addr = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);

    try state.setBalance(addr, U256.fromU64(1000));
    try std.testing.expect(state.exists(addr));

    state.destroyAccount(addr);
    try std.testing.expect(!state.exists(addr));
    try std.testing.expect(state.getBalance(addr).isZero());
}
