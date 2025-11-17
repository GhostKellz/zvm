//! Hedera-specific syscalls for HTS (Token Service) and HCS (Consensus Service)
//! These opcodes enable native interaction with Hedera network features

const std = @import("std");
const types = @import("../../primitives/types.zig");

const U256 = types.U256;
const Address = types.Address;

/// Hedera Token Service (HTS) operations
pub const HTSOperation = enum(u8) {
    /// Transfer tokens from one account to another
    TRANSFER = 0x01,
    /// Mint new tokens (requires treasury key)
    MINT = 0x02,
    /// Burn tokens (requires supply key)
    BURN = 0x03,
    /// Associate token with account
    ASSOCIATE = 0x04,
    /// Dissociate token from account
    DISSOCIATE = 0x05,
    /// Approve token allowance
    APPROVE = 0x06,
    /// Get token balance
    BALANCE_OF = 0x07,
    /// Get token info
    TOKEN_INFO = 0x08,
    /// Create new token
    CREATE_TOKEN = 0x09,
    /// Update token properties
    UPDATE_TOKEN = 0x0A,
    /// Delete token
    DELETE_TOKEN = 0x0B,
    /// Pause token
    PAUSE = 0x0C,
    /// Unpause token
    UNPAUSE = 0x0D,
};

/// Hedera Consensus Service (HCS) operations
pub const HCSOperation = enum(u8) {
    /// Submit message to topic
    SUBMIT_MESSAGE = 0x01,
    /// Create new topic
    CREATE_TOPIC = 0x02,
    /// Update topic
    UPDATE_TOPIC = 0x03,
    /// Delete topic
    DELETE_TOPIC = 0x04,
    /// Get topic info
    TOPIC_INFO = 0x05,
};

/// Token transfer parameters
pub const TokenTransfer = struct {
    token_id: Address,
    from: Address,
    to: Address,
    amount: U256,

    pub fn init(token_id: Address, from: Address, to: Address, amount: U256) TokenTransfer {
        return .{
            .token_id = token_id,
            .from = from,
            .to = to,
            .amount = amount,
        };
    }
};

/// Token creation parameters
pub const TokenCreateParams = struct {
    name: []const u8,
    symbol: []const u8,
    decimals: u8,
    initial_supply: U256,
    treasury: Address,

    pub fn init(name: []const u8, symbol: []const u8, decimals: u8, initial_supply: U256, treasury: Address) TokenCreateParams {
        return .{
            .name = name,
            .symbol = symbol,
            .decimals = decimals,
            .initial_supply = initial_supply,
            .treasury = treasury,
        };
    }
};

/// HCS message submission parameters
pub const HCSMessage = struct {
    topic_id: Address,
    message: []const u8,

    pub fn init(topic_id: Address, message: []const u8) HCSMessage {
        return .{
            .topic_id = topic_id,
            .message = message,
        };
    }
};

/// Hedera syscall result
pub const SyscallResult = union(enum) {
    success: U256,
    error_code: u64,
    address: Address,
    data: []const u8,

    pub fn isSuccess(self: SyscallResult) bool {
        return switch (self) {
            .success => true,
            .address => true,
            .data => true,
            .error_code => false,
        };
    }
};

/// Hedera syscall handler interface
pub const HederaSyscalls = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Execute HTS operation
        hts_call: *const fn (ptr: *anyopaque, op: HTSOperation, data: []const u8) SyscallResult,
        /// Execute HCS operation
        hcs_call: *const fn (ptr: *anyopaque, op: HCSOperation, data: []const u8) SyscallResult,
        /// Get account balance
        get_balance: *const fn (ptr: *anyopaque, account: Address) U256,
        /// Get token info
        get_token_info: *const fn (ptr: *anyopaque, token_id: Address) ?TokenInfo,
    };

    pub fn htsCall(self: HederaSyscalls, op: HTSOperation, data: []const u8) SyscallResult {
        return self.vtable.hts_call(self.ptr, op, data);
    }

    pub fn hcsCall(self: HederaSyscalls, op: HCSOperation, data: []const u8) SyscallResult {
        return self.vtable.hcs_call(self.ptr, op, data);
    }

    pub fn getBalance(self: HederaSyscalls, account: Address) U256 {
        return self.vtable.get_balance(self.ptr, account);
    }

    pub fn getTokenInfo(self: HederaSyscalls, token_id: Address) ?TokenInfo {
        return self.vtable.get_token_info(self.ptr, token_id);
    }
};

/// Token information structure
pub const TokenInfo = struct {
    token_id: Address,
    name: []const u8,
    symbol: []const u8,
    decimals: u8,
    total_supply: U256,
    treasury: Address,
    paused: bool,

    pub fn init(token_id: Address, name: []const u8, symbol: []const u8, decimals: u8, total_supply: U256, treasury: Address) TokenInfo {
        return .{
            .token_id = token_id,
            .name = name,
            .symbol = symbol,
            .decimals = decimals,
            .total_supply = total_supply,
            .treasury = treasury,
            .paused = false,
        };
    }
};

/// Gas costs for Hedera operations
pub const HederaGas = struct {
    /// HTS transfer base cost
    pub const HTS_TRANSFER: u64 = 10_000;
    /// HTS mint base cost
    pub const HTS_MINT: u64 = 50_000;
    /// HTS burn base cost
    pub const HTS_BURN: u64 = 50_000;
    /// HTS associate
    pub const HTS_ASSOCIATE: u64 = 20_000;
    /// HTS approve
    pub const HTS_APPROVE: u64 = 5_000;
    /// HTS create token
    pub const HTS_CREATE: u64 = 100_000;
    /// HTS token info query
    pub const HTS_INFO: u64 = 1_000;

    /// HCS submit message base cost
    pub const HCS_SUBMIT: u64 = 5_000;
    /// HCS submit message per byte
    pub const HCS_SUBMIT_PER_BYTE: u64 = 100;
    /// HCS create topic
    pub const HCS_CREATE_TOPIC: u64 = 50_000;
    /// HCS topic info query
    pub const HCS_INFO: u64 = 1_000;

    pub fn htsGasCost(op: HTSOperation) u64 {
        return switch (op) {
            .TRANSFER => HTS_TRANSFER,
            .MINT => HTS_MINT,
            .BURN => HTS_BURN,
            .ASSOCIATE => HTS_ASSOCIATE,
            .DISSOCIATE => HTS_ASSOCIATE,
            .APPROVE => HTS_APPROVE,
            .BALANCE_OF => HTS_INFO,
            .TOKEN_INFO => HTS_INFO,
            .CREATE_TOKEN => HTS_CREATE,
            .UPDATE_TOKEN => HTS_CREATE / 2,
            .DELETE_TOKEN => HTS_BURN,
            .PAUSE, .UNPAUSE => HTS_APPROVE,
        };
    }

    pub fn hcsGasCost(op: HCSOperation, message_size: usize) u64 {
        return switch (op) {
            .SUBMIT_MESSAGE => HCS_SUBMIT + (@as(u64, @intCast(message_size)) * HCS_SUBMIT_PER_BYTE),
            .CREATE_TOPIC => HCS_CREATE_TOPIC,
            .UPDATE_TOPIC => HCS_CREATE_TOPIC / 2,
            .DELETE_TOPIC => HCS_CREATE_TOPIC / 4,
            .TOPIC_INFO => HCS_INFO,
        };
    }
};
