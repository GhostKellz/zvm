//! KALIX Bytecode Loader and Executor
//! Loads KALIX-compiled contracts and executes them on ZVM

const std = @import("std");
const VM = @import("../interpreter/vm.zig").VM;
const ExecutionResult = @import("../interpreter/vm.zig").ExecutionResult;
const BytecodeContainer = @import("../bytecode/container.zig").BytecodeContainer;
const AccountState = @import("../state/accounts.zig").AccountState;
const Address = @import("../primitives/types.zig").Address;
const U256 = @import("../primitives/types.zig").U256;
const Storage = @import("../state/storage.zig").Storage;
const TransientStorage = @import("../state/storage.zig").TransientStorage;

pub const KalixLoaderError = error{
    InvalidContainer,
    InvalidTarget,
    InvalidBytecode,
    ContractNotFound,
    FunctionNotFound,
} || std.mem.Allocator.Error;

/// Function selector (first 4 bytes of keccak256(function_signature))
pub const FunctionSelector = [4]u8;

/// KALIX contract loader and executor
pub const KalixLoader = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) KalixLoader {
        return .{ .allocator = allocator };
    }

    /// Load KALIX bytecode container from raw bytes
    pub fn loadContract(
        self: *KalixLoader,
        bytecode: []const u8,
    ) !BytecodeContainer {
        // Deserialize ZVMC container
        var container = BytecodeContainer.deserialize(bytecode, self.allocator) catch {
            return error.InvalidContainer;
        };

        // Validate it's KALIX-compiled (ZVM native target)
        if (container.target != .zvm_native) {
            container.deinit(self.allocator);
            return error.InvalidTarget;
        }

        // Validate bytecode is not empty
        if (container.code.len == 0) {
            container.deinit(self.allocator);
            return error.InvalidBytecode;
        }

        return container;
    }

    /// Execute KALIX contract with function selector
    pub fn executeFunction(
        self: *KalixLoader,
        container: *const BytecodeContainer,
        selector: FunctionSelector,
        calldata: []const u8,
        gas_limit: u64,
        storage: Storage,
        transient_storage: TransientStorage,
        accounts: ?*AccountState,
    ) !ExecutionResult {
        // Create VM instance
        var vm = VM.init(
            self.allocator,
            gas_limit,
            storage,
            transient_storage,
            null, // No Hedera syscalls by default
        );
        vm.account_state = accounts;
        defer vm.deinit();

        // Load contract bytecode
        vm.loadBytecode(container.code);

        // Prepare calldata: selector + args
        var full_calldata = std.ArrayList(u8).init(self.allocator);
        defer full_calldata.deinit();

        try full_calldata.appendSlice(&selector);
        try full_calldata.appendSlice(calldata);

        vm.context.calldata = full_calldata.items;

        // Execute
        return try vm.execute();
    }

    /// Execute KALIX contract without function selector (direct execution)
    pub fn executeDirect(
        self: *KalixLoader,
        container: *const BytecodeContainer,
        calldata: []const u8,
        gas_limit: u64,
        storage: Storage,
        transient_storage: TransientStorage,
        accounts: ?*AccountState,
    ) !ExecutionResult {
        var vm = VM.init(
            self.allocator,
            gas_limit,
            storage,
            transient_storage,
            null,
        );
        vm.account_state = accounts;
        defer vm.deinit();

        vm.loadBytecode(container.code);
        vm.context.calldata = calldata;

        return try vm.execute();
    }

    /// Deploy KALIX contract to an address
    pub fn deployContract(
        _: *KalixLoader,
        container: *const BytecodeContainer,
        target_address: Address,
        accounts: *AccountState,
    ) !void {
        // Deploy bytecode to account
        try accounts.deployContract(target_address, container.code);
    }

    /// Parse function selector from function signature
    /// Example: "deposit(u64)" -> first 4 bytes of keccak256
    pub fn computeSelector(signature: []const u8) FunctionSelector {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(signature, &hash, .{});

        var selector: FunctionSelector = undefined;
        @memcpy(&selector, hash[0..4]);
        return selector;
    }

    /// Get contract metadata (if available in ABI)
    pub fn getMetadata(container: *const BytecodeContainer) ?[]const u8 {
        if (container.abi.len > 0) {
            return container.abi;
        }
        return null;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "KalixLoader init" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const loader = KalixLoader.init(allocator);
    _ = loader;
}

test "KalixLoader compute selector" {
    const testing = std.testing;

    // Test function selector generation
    const selector1 = KalixLoader.computeSelector("deposit(u64)");
    const selector2 = KalixLoader.computeSelector("deposit(u64)");

    // Same input should produce same selector
    try testing.expectEqualSlices(u8, &selector1, &selector2);

    // Different inputs should produce different selectors
    const selector3 = KalixLoader.computeSelector("withdraw(u64)");
    const different = !std.mem.eql(u8, &selector1, &selector3);
    try testing.expect(different);
}

test "KalixLoader load invalid container" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var loader = KalixLoader.init(allocator);

    // Try to load invalid bytecode
    const invalid_bytecode = [_]u8{ 0x00, 0x01, 0x02, 0x03 };

    const result = loader.loadContract(&invalid_bytecode);
    try testing.expectError(error.InvalidContainer, result);
}

test "KalixLoader load valid container" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var loader = KalixLoader.init(allocator);

    // Create a valid ZVMC container
    const code = [_]u8{ 0x00 }; // HALT
    var container = try BytecodeContainer.create(allocator, &code, &[_]u8{}, .zvm_native);
    defer container.deinit(allocator);

    // Serialize it
    const serialized = try container.serialize(allocator);
    defer allocator.free(serialized);

    // Load it
    var loaded = try loader.loadContract(serialized);
    defer loaded.deinit(allocator);

    try testing.expectEqual(BytecodeContainer.Target.zvm_native, loaded.target);
    try testing.expectEqual(@as(usize, 1), loaded.code.len);
}

test "KalixLoader execute direct" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const journaled = @import("../state/journaled.zig");
    const transient = @import("../state/transient.zig");

    var loader = KalixLoader.init(allocator);

    // Create simple contract: HALT
    const code = [_]u8{0x00}; // HALT
    var container = try BytecodeContainer.create(allocator, &code, &[_]u8{}, .zvm_native);
    defer container.deinit(allocator);

    // Setup storage
    var state = journaled.JournaledState.init(allocator);
    defer state.deinit();
    var tstorage = transient.TransientStorageImpl.init(allocator);
    defer tstorage.deinit();

    // Execute
    const result = try loader.executeDirect(
        &container,
        &[_]u8{},
        100000,
        state.asStorage(),
        tstorage.asTransientStorage(),
        null,
    );

    try testing.expect(result.success);
}

test "KalixLoader deploy contract" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var loader = KalixLoader.init(allocator);

    // Create contract
    const code = [_]u8{ 0x00, 0x01, 0x02 };
    var container = try BytecodeContainer.create(allocator, &code, &[_]u8{}, .zvm_native);
    defer container.deinit(allocator);

    // Setup account state
    var accounts = @import("../state/accounts.zig").AccountState.init(allocator);
    defer accounts.deinit();

    const target = Address.fromBytes([_]u8{1} ++ [_]u8{0} ** 19);

    // Deploy
    try loader.deployContract(&container, target, &accounts);

    // Verify deployment
    try testing.expect(accounts.isContract(target));
    const deployed_code = accounts.getCode(target);
    try testing.expectEqualSlices(u8, &code, deployed_code);
}
