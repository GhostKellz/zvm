//! Enhanced Contract Demo - End-to-end contract deployment and execution
//! Demonstrates the complete ZVM runtime with persistent storage, host functions, and crypto
const std = @import("std");
const zvm_root = @import("zvm");

const contract = zvm_root.contract;
const database = zvm_root.database;
const runtime = zvm_root.runtime;
const zvm = zvm_root.zvm;

/// Complete contract execution environment
pub const ContractEnvironment = struct {
    allocator: std.mem.Allocator,
    persistent_storage: database.PersistentStorage,
    contracts: std.HashMap(contract.Address, ContractDeployment, contract.AddressHashContext, std.hash_map.default_max_load_percentage),
    
    pub const ContractDeployment = struct {
        bytecode: []const u8,
        storage: contract.Storage,
        deployed_block: u64,
        deployer: contract.Address,
    };
    
    pub fn init(allocator: std.mem.Allocator, db_config: database.DatabaseConfig) !ContractEnvironment {
        return ContractEnvironment{
            .allocator = allocator,
            .persistent_storage = try database.PersistentStorage.init(allocator, db_config),
            .contracts = std.HashMap(contract.Address, ContractDeployment, contract.AddressHashContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *ContractEnvironment) void {
        // Free contract bytecode and storage
        var iterator = self.contracts.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.bytecode);
            entry.value_ptr.storage.deinit();
        }
        self.contracts.deinit();
        self.persistent_storage.deinit();
    }
    
    /// Deploy a new contract
    pub fn deployContract(self: *ContractEnvironment, bytecode: []const u8, deployer: contract.Address, block_number: u64) !contract.Address {
        // Generate contract address (simplified)
        const contract_address = contract.AddressUtils.random();
        
        // Clone bytecode
        const contract_bytecode = try self.allocator.dupe(u8, bytecode);
        
        // Create persistent storage for contract
        const contract_storage = contract.Storage.initPersistent(self.allocator, &self.persistent_storage, contract_address);
        
        // Store contract metadata in database
        try self.persistent_storage.storeContractWithMetadata(
            contract_address,
            bytecode,
            "ZVM",
            deployer,
            [_]u8{0} ** 32, // deployment tx hash
            block_number
        );
        
        const deployment = ContractDeployment{
            .bytecode = contract_bytecode,
            .storage = contract_storage,
            .deployed_block = block_number,
            .deployer = deployer,
        };
        
        try self.contracts.put(contract_address, deployment);
        
        std.log.info("Contract deployed at {x} by {x}", .{
            contract_address,
            (&deployer)
        });
        
        return contract_address;
    }
    
    /// Execute a contract call
    pub fn callContract(
        self: *ContractEnvironment,
        contract_address: contract.Address,
        caller: contract.Address,
        value: u256,
        input_data: []const u8,
        gas_limit: u64,
        block_number: u64,
        block_timestamp: u64
    ) !ContractExecutionResult {
        const deployment = self.contracts.getPtr(contract_address) orelse return error.ContractNotFound;
        
        // Create execution context
        const context = contract.ContractContext.init(
            contract_address,
            caller,
            value,
            input_data,
            gas_limit,
            block_number,
            block_timestamp,
            &deployment.storage
        );
        
        // Create enhanced runtime VM
        var vm = runtime.EnhancedRuntimeVM.init(
            self.allocator,
            context,
            &deployment.storage,
            &self.persistent_storage
        );
        defer vm.deinit();
        
        // Execute contract
        const result = try vm.execute(deployment.bytecode);
        
        // Get emitted events
        const events = vm.get_events();
        
        return ContractExecutionResult{
            .execution_result = result,
            .events = try self.allocator.dupe(runtime.EnhancedRuntimeHooks.ContractEvent, events),
            .storage_changes = try self.getStorageChanges(contract_address),
        };
    }
    
    /// Get storage changes for a contract (simplified)
    fn getStorageChanges(self: *ContractEnvironment, contract_addr: contract.Address) ![]StorageChange {
        _ = self;
        _ = contract_addr;
        // For now, return empty - in real implementation would track changes
        return &[_]StorageChange{};
    }
    
    pub const ContractExecutionResult = struct {
        execution_result: contract.ExecutionResult,
        events: []runtime.EnhancedRuntimeHooks.ContractEvent,
        storage_changes: []StorageChange,
    };
    
    pub const StorageChange = struct {
        key: u256,
        old_value: u256,
        new_value: u256,
    };
};

/// Example: Simple counter contract bytecode
/// This would normally be compiled from Zig or other language to ZVM bytecode
fn createCounterContractBytecode(allocator: std.mem.Allocator) ![]u8 {
    var bytecode = std.ArrayList(u8).init(allocator);
    
    // Simplified counter contract bytecode:
    // 1. Load counter from storage (key 0)
    // 2. Increment by 1
    // 3. Store back to storage
    // 4. Emit event
    // 5. Return new value
    
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push storage key (0)
    try bytecode.append(0);
    try bytecode.append(@intFromEnum(zvm.Opcode.SLOAD)); // Load from storage
    
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push 1
    try bytecode.append(1);
    try bytecode.append(@intFromEnum(zvm.Opcode.ADD)); // Increment
    
    try bytecode.append(@intFromEnum(zvm.Opcode.DUP)); // Duplicate new value
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push storage key (0)
    try bytecode.append(0);
    try bytecode.append(@intFromEnum(zvm.Opcode.SWAP)); // Swap key and value
    try bytecode.append(@intFromEnum(zvm.Opcode.SSTORE)); // Store to storage
    
    try bytecode.append(@intFromEnum(zvm.Opcode.RETURN)); // Return (simplified)
    
    return bytecode.toOwnedSlice();
}

/// Example: Math contract with crypto operations
fn createMathContractBytecode(allocator: std.mem.Allocator) ![]u8 {
    var bytecode = std.ArrayList(u8).init(allocator);
    
    // Math contract that:
    // 1. Takes two inputs from calldata
    // 2. Adds them
    // 3. Hashes the result with keccak256
    // 4. Stores hash in storage
    // 5. Returns the hash
    
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push calldata offset (0)
    try bytecode.append(0);
    try bytecode.append(@intFromEnum(zvm.Opcode.CALLDATALOAD)); // Load first input
    
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push calldata offset (32)
    try bytecode.append(32);
    try bytecode.append(@intFromEnum(zvm.Opcode.CALLDATALOAD)); // Load second input
    
    try bytecode.append(@intFromEnum(zvm.Opcode.ADD)); // Add inputs
    
    // Prepare for keccak256 (simplified - normally would put data in memory)
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push data offset
    try bytecode.append(0);
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push data length
    try bytecode.append(32);
    try bytecode.append(@intFromEnum(zvm.Opcode.KECCAK256)); // Hash the sum
    
    try bytecode.append(@intFromEnum(zvm.Opcode.DUP)); // Duplicate hash
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push storage key (1)
    try bytecode.append(1);
    try bytecode.append(@intFromEnum(zvm.Opcode.SWAP)); // Swap key and hash
    try bytecode.append(@intFromEnum(zvm.Opcode.SSTORE)); // Store hash
    
    try bytecode.append(@intFromEnum(zvm.Opcode.RETURN)); // Return hash
    
    return bytecode.toOwnedSlice();
}

/// Example: Post-quantum crypto contract
fn createPostQuantumContractBytecode(allocator: std.mem.Allocator) ![]u8 {
    var bytecode = std.ArrayList(u8).init(allocator);
    
    // Post-quantum contract that:
    // 1. Takes input data from calldata
    // 2. Computes BLAKE3 hash (modern, fast)
    // 3. Stores hash using BLAKE3 instead of Keccak256
    // 4. Demonstrates next-gen crypto in ZVM
    
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push calldata offset (0)
    try bytecode.append(0);
    try bytecode.append(@intFromEnum(zvm.Opcode.CALLDATASIZE)); // Get all calldata
    
    // Use BLAKE3 instead of Keccak256
    try bytecode.append(@intFromEnum(zvm.Opcode.BLAKE3)); // Hash with BLAKE3
    
    try bytecode.append(@intFromEnum(zvm.Opcode.DUP)); // Duplicate hash
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push storage key (5)
    try bytecode.append(5);
    try bytecode.append(@intFromEnum(zvm.Opcode.SWAP)); // Swap key and hash
    try bytecode.append(@intFromEnum(zvm.Opcode.SSTORE)); // Store BLAKE3 hash
    
    // Also compute and store SHA256 for comparison
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push calldata offset again
    try bytecode.append(0);
    try bytecode.append(@intFromEnum(zvm.Opcode.CALLDATASIZE));
    try bytecode.append(@intFromEnum(zvm.Opcode.SHA256)); // Hash with SHA256
    
    try bytecode.append(@intFromEnum(zvm.Opcode.PUSH1)); // Push storage key (6)
    try bytecode.append(6);
    try bytecode.append(@intFromEnum(zvm.Opcode.SWAP));
    try bytecode.append(@intFromEnum(zvm.Opcode.SSTORE)); // Store SHA256 hash
    
    try bytecode.append(@intFromEnum(zvm.Opcode.RETURN));
    
    return bytecode.toOwnedSlice();
}

test "Complete contract deployment and execution flow" {
    const allocator = std.testing.allocator;
    
    // Create contract environment with persistent storage
    const db_config = database.DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };
    
    var env = try ContractEnvironment.init(allocator, db_config);
    defer env.deinit();
    
    // Create deployer and caller addresses
    const deployer = contract.AddressUtils.fromHex("0x1234567890123456789012345678901234567890") catch unreachable;
    const caller = contract.AddressUtils.fromHex("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd") catch unreachable;
    
    // Deploy counter contract
    const counter_bytecode = try createCounterContractBytecode(allocator);
    defer allocator.free(counter_bytecode);
    
    const counter_address = try env.deployContract(counter_bytecode, deployer, 1000);
    
    // Call counter contract multiple times
    for (0..3) |i| {
        const call_result = try env.callContract(
            counter_address,
            caller,
            0, // no value sent
            &[_]u8{}, // no input data
            100000, // gas limit
            1000 + i + 1, // block number
            1700000000 + i, // timestamp
        );
        
        try std.testing.expect(call_result.execution_result.success);
        std.log.info("Counter call {}: gas_used={}", .{ i + 1, call_result.execution_result.gas_used });
        
        // Free event data
        allocator.free(call_result.events);
        allocator.free(call_result.storage_changes);
    }
    
    // Deploy and test math contract
    const math_bytecode = try createMathContractBytecode(allocator);
    defer allocator.free(math_bytecode);
    
    const math_address = try env.deployContract(math_bytecode, deployer, 1005);
    
    // Prepare input data (two 32-byte numbers)
    var input_data: [64]u8 = undefined;
    std.mem.writeInt(u256, input_data[0..32], 42, .big);
    std.mem.writeInt(u256, input_data[32..64], 58, .big);
    
    const math_result = try env.callContract(
        math_address,
        caller,
        0,
        &input_data,
        100000,
        1006,
        1700000006,
    );
    
    try std.testing.expect(math_result.execution_result.success);
    std.log.info("Math call: gas_used={}", .{math_result.execution_result.gas_used});
    
    // Free resources
    allocator.free(math_result.events);
    allocator.free(math_result.storage_changes);
}

test "Storage persistence across contract sessions" {
    const allocator = std.testing.allocator;
    
    const db_config = database.DatabaseConfig{
        .type = .memory,
        .path = ":memory:",
    };
    
    var env = try ContractEnvironment.init(allocator, db_config);
    defer env.deinit();
    
    const deployer = contract.AddressUtils.fromHex("0x1111111111111111111111111111111111111111") catch unreachable;
    const caller = contract.AddressUtils.fromHex("0x2222222222222222222222222222222222222222") catch unreachable;
    
    // Deploy contract
    const counter_bytecode = try createCounterContractBytecode(allocator);
    defer allocator.free(counter_bytecode);
    
    const contract_address = try env.deployContract(counter_bytecode, deployer, 2000);
    
    // Call contract to increment counter
    const call_result = try env.callContract(contract_address, caller, 0, &[_]u8{}, 100000, 2001, 1700000000);
    try std.testing.expect(call_result.execution_result.success);
    allocator.free(call_result.events);
    allocator.free(call_result.storage_changes);
    
    // Verify storage persistence by checking database statistics
    const stats = try env.persistent_storage.getStatistics();
    try std.testing.expect(stats.total_storage_entries > 0);
    
    std.log.info("Database stats: {} storage entries, {} contracts", .{ stats.total_storage_entries, stats.total_contracts });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== Enhanced Contract Runtime Demo ===", .{});
    
    // Create production database config
    const db_config = database.DatabaseConfig{
        .type = .zqlite,
        .path = "enhanced_contracts.db",
        .sync_mode = .full,
    };
    
    var env = try ContractEnvironment.init(allocator, db_config);
    defer env.deinit();
    
    const deployer = contract.AddressUtils.fromHex("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") catch unreachable;
    const user1 = contract.AddressUtils.fromHex("0x1111111111111111111111111111111111111111") catch unreachable;
    const user2 = contract.AddressUtils.fromHex("0x2222222222222222222222222222222222222222") catch unreachable;
    
    std.log.info("\n1. Deploying Contracts:", .{});
    
    // Deploy counter contract
    const counter_bytecode = try createCounterContractBytecode(allocator);
    defer allocator.free(counter_bytecode);
    
    const counter_addr = try env.deployContract(counter_bytecode, deployer, 1000);
    std.log.info("Counter contract: {x}", .{(&counter_addr)});
    
    // Deploy math contract
    const math_bytecode = try createMathContractBytecode(allocator);
    defer allocator.free(math_bytecode);
    
    const math_addr = try env.deployContract(math_bytecode, deployer, 1001);
    std.log.info("Math contract: {x}", .{(&math_addr)});
    
    std.log.info("\n2. Executing Contract Calls:", .{});
    
    // Multiple users interact with counter
    for ([_]contract.Address{ user1, user2, user1 }, 0..) |user, i| {
        const result = try env.callContract(counter_addr, user, 0, &[_]u8{}, 100000, 1002 + i, 1700000000 + i);
        std.log.info("User {x} called counter, gas: {}", .{ (&user), result.execution_result.gas_used });
        
        allocator.free(result.events);
        allocator.free(result.storage_changes);
    }
    
    // Test math contract with crypto
    var math_input: [64]u8 = undefined;
    std.mem.writeInt(u256, math_input[0..32], 123, .big);
    std.mem.writeInt(u256, math_input[32..64], 456, .big);
    
    const math_result = try env.callContract(math_addr, user1, 1000, &math_input, 100000, 1005, 1700000005);
    std.log.info("Math contract (123 + 456 hash), gas: {}", .{math_result.execution_result.gas_used});
    
    allocator.free(math_result.events);
    allocator.free(math_result.storage_changes);
    
    std.log.info("\n3. Database Statistics:", .{});
    const stats = try env.persistent_storage.getStatistics();
    std.log.info("Contracts: {}", .{stats.total_contracts});
    std.log.info("Storage entries: {}", .{stats.total_storage_entries});
    std.log.info("Database size: {} bytes", .{stats.database_size_bytes});
    std.log.info("Cache hit rate: {d:.1}%", .{stats.cache_hit_rate * 100});
    
    std.log.info("\n=== Demo Complete ===", .{});
}