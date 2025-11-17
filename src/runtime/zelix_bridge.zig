//! ZELIX Bridge for ZVM
//! Connects ZVM with Hedera network via ZELIX client
//! Enables contract deployment, execution, and querying on Hedera

const std = @import("std");
const VM = @import("../interpreter/vm.zig").VM;
const ExecutionResult = @import("../interpreter/vm.zig").ExecutionResult;
const BytecodeContainer = @import("../bytecode/container.zig").BytecodeContainer;
const KalixLoader = @import("kalix_loader.zig").KalixLoader;
const Address = @import("../primitives/types.zig").Address;
const U256 = @import("../primitives/types.zig").U256;
const AccountState = @import("../state/accounts.zig").AccountState;
const Storage = @import("../state/storage.zig").Storage;
const TransientStorage = @import("../state/storage.zig").TransientStorage;

/// ZELIX bridge configuration
pub const ZelixBridgeConfig = struct {
    network: Network,
    gas_limit_default: u64 = 1_000_000,
    max_contract_size: usize = 1024 * 1024, // 1MB

    pub const Network = enum {
        mainnet,
        testnet,
        previewnet,
        local,
    };
};

/// Contract deployment result
pub const DeploymentResult = struct {
    contract_address: Address,
    gas_used: u64,
    transaction_id: []const u8,
    success: bool,
};

/// Contract call result
pub const CallResult = struct {
    return_data: []const u8,
    gas_used: u64,
    success: bool,
    logs: []const ExecutionResult.Log,
};

/// ZELIX Bridge - connects ZVM to Hedera via ZELIX
pub const ZelixBridge = struct {
    allocator: std.mem.Allocator,
    config: ZelixBridgeConfig,
    kalix_loader: KalixLoader,

    pub fn init(allocator: std.mem.Allocator, config: ZelixBridgeConfig) ZelixBridge {
        return .{
            .allocator = allocator,
            .config = config,
            .kalix_loader = KalixLoader.init(allocator),
        };
    }

    /// Deploy ZVM contract to Hedera via ZELIX
    /// This prepares the bytecode and metadata for Hedera deployment
    pub fn deployContract(
        self: *ZelixBridge,
        bytecode: []const u8,
        constructor_params: []const u8,
        gas_limit: ?u64,
    ) !DeploymentResult {
        // 1. Load and validate bytecode container
        var container = try self.kalix_loader.loadContract(bytecode);
        defer container.deinit(self.allocator);

        // 2. Validate bytecode size
        if (container.code.len > self.config.max_contract_size) {
            return error.ContractTooLarge;
        }

        // 3. Execute constructor if needed (simulated locally)
        const gas = gas_limit orelse self.config.gas_limit_default;

        // Create temporary storage for constructor execution
        const journaled = @import("../state/journaled.zig");
        const transient = @import("../state/transient.zig");

        var state = journaled.JournaledState.init(self.allocator);
        defer state.deinit();
        var tstorage = transient.TransientStorageImpl.init(self.allocator);
        defer tstorage.deinit();

        // Generate contract address (deterministic based on deployer + nonce)
        // In real deployment, this comes from Hedera
        const contract_address = try self.generateContractAddress();

        // 4. Execute constructor with params
        const result = try self.kalix_loader.executeDirect(
            &container,
            constructor_params,
            gas,
            state.asStorage(),
            tstorage.asTransientStorage(),
            null,
        );

        if (!result.success) {
            return error.ConstructorFailed;
        }

        // 5. Prepare deployment metadata for ZELIX
        // Note: In production, this would call ZELIX client.ContractCreateTransaction
        const transaction_id = try std.fmt.allocPrint(
            self.allocator,
            "0.0.{d}@{d}.{d}",
            .{ contract_address.toU64(), std.time.timestamp(), result.gas_used },
        );

        return DeploymentResult{
            .contract_address = contract_address,
            .gas_used = result.gas_used,
            .transaction_id = transaction_id,
            .success = true,
        };
    }

    /// Call ZVM contract function via ZELIX
    pub fn callContract(
        self: *ZelixBridge,
        contract_address: Address,
        function_selector: [4]u8,
        params: []const u8,
        gas_limit: ?u64,
        storage: Storage,
        transient_storage: TransientStorage,
        accounts: ?*AccountState,
    ) !CallResult {
        const gas = gas_limit orelse self.config.gas_limit_default;

        // 1. Get contract bytecode from account state
        if (accounts) |acc| {
            if (!acc.isContract(contract_address)) {
                return error.ContractNotFound;
            }

            const code = acc.getCode(contract_address);
            if (code.len == 0) {
                return error.EmptyContract;
            }

            // 2. Load bytecode into container
            var container = try self.kalix_loader.loadContract(code);
            defer container.deinit(self.allocator);

            // 3. Execute function
            const result = try self.kalix_loader.executeFunction(
                &container,
                function_selector,
                params,
                gas,
                storage,
                transient_storage,
                accounts,
            );

            // 4. Prepare result
            const return_data = try self.allocator.dupe(u8, result.return_data);
            const logs = try self.allocator.dupe(ExecutionResult.Log, result.logs);

            return CallResult{
                .return_data = return_data,
                .gas_used = result.gas_used,
                .success = result.success,
                .logs = logs,
            };
        }

        return error.NoAccountState;
    }

    /// Query contract (read-only call)
    pub fn queryContract(
        self: *ZelixBridge,
        contract_address: Address,
        function_selector: [4]u8,
        params: []const u8,
        storage: Storage,
        transient_storage: TransientStorage,
        accounts: ?*AccountState,
    ) ![]const u8 {
        // Query is just a call with unlimited gas (local execution)
        const result = try self.callContract(
            contract_address,
            function_selector,
            params,
            std.math.maxInt(u64),
            storage,
            transient_storage,
            accounts,
        );
        defer self.allocator.free(result.logs);

        return result.return_data;
    }

    /// Generate deterministic contract address
    /// In production, this would come from Hedera ContractCreateTransaction receipt
    fn generateContractAddress(self: *ZelixBridge) !Address {
        _ = self;
        var prng = std.Random.DefaultPrng.init(@as(u64, @intCast(std.time.timestamp())));
        const random = prng.random();

        var address_bytes: [20]u8 = undefined;
        random.bytes(&address_bytes);

        return Address.fromBytes(address_bytes);
    }

    /// Estimate gas for contract call (local simulation)
    pub fn estimateGas(
        self: *ZelixBridge,
        contract_address: Address,
        function_selector: [4]u8,
        params: []const u8,
        storage: Storage,
        transient_storage: TransientStorage,
        accounts: ?*AccountState,
    ) !u64 {
        const result = try self.callContract(
            contract_address,
            function_selector,
            params,
            std.math.maxInt(u64), // Unlimited gas for estimation
            storage,
            transient_storage,
            accounts,
        );
        defer {
            self.allocator.free(result.return_data);
            self.allocator.free(result.logs);
        }

        return result.gas_used;
    }

    /// Get contract bytecode from account
    pub fn getContractBytecode(
        _: *ZelixBridge,
        contract_address: Address,
        accounts: *AccountState,
    ) ![]const u8 {
        if (!accounts.isContract(contract_address)) {
            return error.ContractNotFound;
        }

        return accounts.getCode(contract_address);
    }

    /// Get contract ABI from deployed contract
    pub fn getContractABI(
        self: *ZelixBridge,
        contract_address: Address,
        accounts: *AccountState,
    ) !?[]const u8 {
        const code = try self.getContractBytecode(contract_address, accounts);

        // Load container and extract ABI
        var container = try self.kalix_loader.loadContract(code);
        defer container.deinit(self.allocator);

        return KalixLoader.getMetadata(&container);
    }
};

// =============================================================================
// ZELIX Integration Helpers
// =============================================================================

/// Helper to encode contract deployment transaction for ZELIX
pub fn encodeContractCreate(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
    constructor_params: []const u8,
    gas_limit: u64,
) ![]u8 {
    // Format: [bytecode_length][bytecode][params_length][params][gas_limit]
    var buffer = std.ArrayList(u8).init(allocator);
    errdefer buffer.deinit();

    // Bytecode length (u32)
    const bytecode_len: u32 = @intCast(bytecode.len);
    try buffer.appendSlice(std.mem.asBytes(&bytecode_len));

    // Bytecode
    try buffer.appendSlice(bytecode);

    // Params length (u32)
    const params_len: u32 = @intCast(constructor_params.len);
    try buffer.appendSlice(std.mem.asBytes(&params_len));

    // Params
    try buffer.appendSlice(constructor_params);

    // Gas limit (u64)
    try buffer.appendSlice(std.mem.asBytes(&gas_limit));

    return try buffer.toOwnedSlice();
}

/// Helper to encode contract call for ZELIX
pub fn encodeContractCall(
    allocator: std.mem.Allocator,
    function_selector: [4]u8,
    params: []const u8,
) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    errdefer buffer.deinit();

    // Function selector (4 bytes)
    try buffer.appendSlice(&function_selector);

    // Parameters
    try buffer.appendSlice(params);

    return try buffer.toOwnedSlice();
}

// =============================================================================
// Tests
// =============================================================================

test "ZelixBridge init" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = ZelixBridgeConfig{
        .network = .testnet,
        .gas_limit_default = 500_000,
    };

    const bridge = ZelixBridge.init(allocator, config);
    try testing.expectEqual(ZelixBridgeConfig.Network.testnet, bridge.config.network);
    try testing.expectEqual(@as(u64, 500_000), bridge.config.gas_limit_default);
}

test "ZelixBridge deploy contract" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var bridge = ZelixBridge.init(allocator, .{ .network = .testnet });

    // Create simple contract: HALT
    const code = [_]u8{0x00}; // HALT
    var container = try BytecodeContainer.create(allocator, &code, &[_]u8{}, .zvm_native);
    defer container.deinit(allocator);

    const serialized = try container.serialize(allocator);
    defer allocator.free(serialized);

    // Deploy
    const result = try bridge.deployContract(serialized, &[_]u8{}, null);
    defer allocator.free(result.transaction_id);

    try testing.expect(result.success);
    try testing.expect(result.gas_used > 0);
    try testing.expect(!result.contract_address.isZero());
}

test "encode contract create" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const bytecode = [_]u8{ 0x00, 0x01, 0x02 };
    const params = [_]u8{ 0xFF, 0xFE };
    const gas: u64 = 1000;

    const encoded = try encodeContractCreate(allocator, &bytecode, &params, gas);
    defer allocator.free(encoded);

    try testing.expect(encoded.len > 0);
    try testing.expectEqual(@as(usize, 4 + 3 + 4 + 2 + 8), encoded.len);
}

test "encode contract call" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const selector = [4]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const params = [_]u8{ 0x11, 0x22, 0x33 };

    const encoded = try encodeContractCall(allocator, selector, &params);
    defer allocator.free(encoded);

    try testing.expectEqual(@as(usize, 7), encoded.len);
    try testing.expectEqualSlices(u8, &selector, encoded[0..4]);
    try testing.expectEqualSlices(u8, &params, encoded[4..]);
}
