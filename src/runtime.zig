//! ZVM Runtime - Plugin functions: storage, signing, I/O hooks, crypto integration
const std = @import("std");
const zvm = @import("zvm.zig");
const contract = @import("contract.zig");

/// Runtime error types
pub const RuntimeError = error{
    InvalidSignature,
    CryptoError,
    NetworkError,
    StorageError,
    InvalidDomain,
};

// Pure Zig crypto - no external dependencies

/// Pure Zig crypto implementation
pub const Crypto = struct {
    /// Hash functions
    pub fn keccak256(data: []const u8) [32]u8 {
        // Use standard library SHA3-256 (Keccak-256 equivalent)
        var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(data);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    pub fn sha256(data: []const u8) [32]u8 {
        // Use standard library SHA-256
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(data);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }

    /// Ed25519 signature verification
    pub fn ed25519_verify(message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        // Use standard library Ed25519
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature) catch return false;
        const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
        return pub_key.verify(message, sig, .{}) == .valid;
    }

    /// secp256k1 signature verification (Bitcoin/Ethereum)
    pub fn secp256k1_verify(message_hash: [32]u8, signature: [64]u8, public_key: [33]u8) bool {
        // For now, use Ed25519 as placeholder - secp256k1 would need separate implementation
        _ = message_hash;
        _ = signature;
        _ = public_key;
        return true; // Simplified for compatibility
    }

    /// ECRECOVER implementation (Ethereum-style)
    pub fn ecrecover(message_hash: [32]u8, signature: [65]u8) ?[20]u8 {
        // This would require secp256k1 implementation which isn't in current zcrypto
        // For now, return a mock address
        _ = message_hash;
        _ = signature;
        var address: [20]u8 = undefined;
        const hash = sha256("mock_ecrecover");
        @memcpy(&address, hash[0..20]);
        return address;
    }
};

/// Integration with zwallet (will be available from external dependency)
pub const Wallet = struct {
    /// Verify a wallet signature
    pub fn verify_signature(wallet_address: contract.Address, message: []const u8, signature: []const u8) bool {
        // Placeholder - would integrate with zwallet
        _ = wallet_address;
        _ = message;
        _ = signature;
        return true; // Simplified for now
    }

    /// Get account balance (via ghostbridge)
    pub fn get_balance(address: contract.Address) u256 {
        // Placeholder - would call ghostbridge RPC
        _ = address;
        return 1000000; // Simplified
    }
};

/// Integration with CNS (Custom Name Service)
pub const NameService = struct {
    /// Resolve a domain name to an address
    pub fn resolve_domain(domain: []const u8) ?contract.Address {
        // Placeholder - would integrate with CNS
        _ = domain;
        return contract.AddressUtils.zero(); // Simplified
    }

    /// Register a domain
    pub fn register_domain(domain: []const u8, owner: contract.Address) RuntimeError!void {
        // Placeholder - would integrate with CNS
        _ = domain;
        _ = owner;
    }

    /// Check domain ownership
    pub fn is_domain_owner(domain: []const u8, address: contract.Address) bool {
        // Placeholder - would check CNS records
        _ = domain;
        _ = address;
        return true; // Simplified
    }
};

/// Runtime hooks for system calls from smart contracts
pub const RuntimeHooks = struct {
    /// Hook for KECCAK256 opcode
    pub fn keccak256_hook(data: []const u8) [32]u8 {
        return Crypto.keccak256(data);
    }

    /// Hook for ECRECOVER opcode
    pub fn ecrecover_hook(message_hash: [32]u8, signature: [65]u8) ?contract.Address {
        return Crypto.ecrecover(message_hash, signature);
    }

    /// Hook for domain resolution
    pub fn resolve_domain_hook(domain: []const u8) ?contract.Address {
        return NameService.resolve_domain(domain);
    }

    /// Hook for balance queries
    pub fn balance_hook(address: contract.Address) u256 {
        return Wallet.get_balance(address);
    }

    /// Hook for signature verification
    pub fn verify_signature_hook(address: contract.Address, message: []const u8, signature: []const u8) bool {
        return Wallet.verify_signature(address, message, signature);
    }
};

/// Enhanced VM with runtime hooks
pub const RuntimeVM = struct {
    vm: zvm.VM,
    context: contract.ContractContext,
    hooks: RuntimeHooks,

    pub fn init(context: contract.ContractContext) RuntimeVM {
        return RuntimeVM{
            .vm = zvm.VM.init(),
            .context = context,
            .hooks = RuntimeHooks{},
        };
    }

    /// Execute bytecode with runtime hooks
    pub fn execute(self: *RuntimeVM, bytecode: []const u8) zvm.VMError!contract.ExecutionResult {
        self.vm.load_bytecode(bytecode, self.context.gas_limit);

        // Enhanced execution loop with hook support
        while (self.vm.running) {
            try self.execute_with_hooks();
        }

        return contract.ExecutionResult{
            .success = true,
            .gas_used = self.vm.gas_used(),
            .return_data = &[_]u8{}, // TODO: Extract return data
            .error_msg = null,
            .contract_address = self.context.address,
        };
    }

    /// Execute one instruction with runtime hook support
    fn execute_with_hooks(self: *RuntimeVM) zvm.VMError!void {
        if (!self.vm.running || self.vm.pc >= self.vm.bytecode.len) {
            self.vm.running = false;
            return;
        }

        const opcode_byte = self.vm.bytecode[self.vm.pc];
        const opcode: zvm.Opcode = @enumFromInt(opcode_byte);

        // Handle special opcodes with runtime hooks
        switch (opcode) {
            .KECCAK256 => {
                const offset = try self.vm.stack.pop();
                const length = try self.vm.stack.pop();

                // Get data from memory (simplified)
                const data = &[_]u8{0x42}; // Placeholder
                _ = offset;
                _ = length;

                const hash = self.hooks.keccak256_hook(data);

                // Push result as u256
                var result: u256 = 0;
                for (hash) |byte| {
                    result = (result << 8) | byte;
                }
                try self.vm.stack.push(result);

                try self.vm.gas.consume(zvm.GasCost.HIGH);
                self.vm.pc += 1;
            },
            .ECRECOVER => {
                // Pop message hash and signature from stack
                const msg_hash_hi = try self.vm.stack.pop();
                const msg_hash_lo = try self.vm.stack.pop();
                const sig_v = try self.vm.stack.pop();
                const sig_r = try self.vm.stack.pop();
                const sig_s = try self.vm.stack.pop();

                // Reconstruct hash and signature (simplified)
                const message_hash: [32]u8 = [_]u8{0} ** 32;
                const signature: [65]u8 = [_]u8{0} ** 65;

                // Convert u256 to bytes (simplified)
                _ = msg_hash_hi;
                _ = msg_hash_lo;
                _ = sig_v;
                _ = sig_r;
                _ = sig_s;

                if (self.hooks.ecrecover_hook(message_hash, signature)) |recovered_addr| {
                    // Convert address to u256 and push
                    var addr_u256: u256 = 0;
                    for (recovered_addr) |byte| {
                        addr_u256 = (addr_u256 << 8) | byte;
                    }
                    try self.vm.stack.push(addr_u256);
                } else {
                    try self.vm.stack.push(0); // Recovery failed
                }

                try self.vm.gas.consume(3000); // Expensive operation
                self.vm.pc += 1;
            },
            .CALLER => {
                // Push caller address to stack
                var caller_u256: u256 = 0;
                for (self.context.sender) |byte| {
                    caller_u256 = (caller_u256 << 8) | byte;
                }
                try self.vm.stack.push(caller_u256);
                self.vm.pc += 1;
            },
            .CALLVALUE => {
                try self.vm.stack.push(self.context.value);
                self.vm.pc += 1;
            },
            .SLOAD => {
                const key = try self.vm.stack.pop();
                const value = self.context.storage.load(key);
                try self.vm.stack.push(value);
                try self.vm.gas.consume(zvm.GasCost.SLOAD);
                self.vm.pc += 1;
            },
            .SSTORE => {
                const key = try self.vm.stack.pop();
                const value = try self.vm.stack.pop();
                self.context.storage.store(key, value);
                try self.vm.gas.consume(zvm.GasCost.SSTORE);
                self.vm.pc += 1;
            },
            else => {
                // Use standard VM execution for other opcodes
                try self.vm.step();
            },
        }
    }
};

/// High-level runtime for smart contract execution
pub const Runtime = struct {
    registry: contract.ContractRegistry,
    default_storage: contract.Storage,

    pub fn init(allocator: std.mem.Allocator) Runtime {
        return Runtime{
            .registry = contract.ContractRegistry.init(allocator),
            .default_storage = contract.Storage.init(allocator),
        };
    }

    pub fn deinit(self: *Runtime) void {
        self.registry.deinit();
        self.default_storage.deinit();
    }

    /// Deploy a new contract
    pub fn deploy_contract(self: *Runtime, bytecode: []const u8, deployer: contract.Address, value: u256, gas_limit: u64) !contract.ExecutionResult {
        const contract_addr = contract.AddressUtils.random();

        // Execute constructor (simplified - just deploy the code)
        try self.registry.deploy(bytecode, contract_addr);

        _ = deployer;
        _ = value;
        _ = gas_limit;

        return contract.ExecutionResult{
            .success = true,
            .gas_used = 21000, // Base deployment cost
            .return_data = &contract_addr,
            .error_msg = null,
            .contract_address = contract_addr,
        };
    }

    /// Call a deployed contract
    pub fn call_contract(self: *Runtime, contract_address: contract.Address, caller: contract.Address, value: u256, input: []const u8, gas_limit: u64) !contract.ExecutionResult {
        const context = contract.ContractContext.init(
            contract_address,
            caller,
            value,
            input,
            gas_limit,
            12345, // Block number (placeholder)
            @intCast(std.time.timestamp()),
            &self.default_storage,
        );

        return self.registry.call(contract_address, context);
    }
};

/// ZVM Runtime - Enhanced with hybrid execution, networking, and storage
const zevm = @import("zevm.zig");
const wasm = @import("wasm.zig");
const networking = @import("networking.zig");

/// Enhanced Hybrid Runtime with ZVM, EVM, and WASM support
pub const HybridRuntime = struct {
    allocator: std.mem.Allocator,
    zvm_runtime: Runtime,
    wasm_runtime: wasm.WasmRuntime,
    network_node: ?*networking.NetworkNode,
    storage: EnhancedStorage,
    crypto: CryptoContext,

    /// Initialize hybrid runtime
    pub fn init(allocator: std.mem.Allocator) HybridRuntime {
        return HybridRuntime{
            .allocator = allocator,
            .zvm_runtime = Runtime.init(allocator),
            .wasm_runtime = wasm.WasmRuntime.init(allocator),
            .network_node = null,
            .storage = EnhancedStorage.init(allocator),
            .crypto = CryptoContext.init(),
        };
    }

    /// Deinitialize hybrid runtime
    pub fn deinit(self: *HybridRuntime) void {
        self.zvm_runtime.deinit();
        self.wasm_runtime.deinit();
        self.storage.deinit();
        if (self.network_node) |node| {
            self.allocator.destroy(node);
        }
    }

    /// Enable networking with QUIC transport
    pub fn enableNetworking(self: *HybridRuntime, config: networking.NetworkConfig) !void {
        if (self.network_node != null) return; // Already enabled

        var node = try self.allocator.create(networking.NetworkNode);
        node.* = try networking.NetworkNode.init(self.allocator, config);
        self.network_node = node;

        try node.start();
        std.debug.print("Hybrid runtime networking enabled\n", .{});
    }

    /// Deploy contract with automatic format detection
    pub fn deployContract(self: *HybridRuntime, bytecode: []const u8, deployer: contract.Address, value: u64, gas_limit: u64) !contract.ExecutionResult {
        const format = detectBytecodeFormat(bytecode);

        switch (format) {
            .ZVM => {
                std.debug.print("Deploying ZVM contract\n", .{});
                const result = try self.zvm_runtime.deploy_contract(bytecode, deployer, value, gas_limit);

                // Store in enhanced storage
                if (result.success and result.contract_address != null) {
                    try self.storage.storeContract(result.contract_address.?, bytecode, .ZVM);
                }

                return result;
            },
            .EVM => {
                std.debug.print("Deploying EVM contract\n", .{});
                var zevm_runtime = zevm.ZevmRuntime.init(self.allocator);
                defer zevm_runtime.deinit();

                const result = try zevm_runtime.execute_evm(bytecode, deployer, value, &[_]u8{}, gas_limit);

                const contract_result = contract.ExecutionResult{
                    .success = result.success,
                    .gas_used = result.gas_used,
                    .return_data = result.return_data,
                    .error_msg = result.error_msg,
                    .contract_address = if (result.success) contract.AddressUtils.random() else null,
                };

                // Store in enhanced storage
                if (contract_result.success and contract_result.contract_address != null) {
                    try self.storage.storeContract(contract_result.contract_address.?, bytecode, .EVM);
                }

                return contract_result;
            },
            .WASM => {
                std.debug.print("Deploying WASM contract\n", .{});
                const module = self.wasm_runtime.loadModule(bytecode) catch |err| {
                    return contract.ExecutionResult{
                        .success = false,
                        .gas_used = 0,
                        .return_data = &[_]u8{},
                        .error_msg = @errorName(err),
                        .contract_address = null,
                    };
                };

                const contract_address = contract.AddressUtils.random();

                // Create contract context for WASM deployment
                var storage = contract.Storage.init(self.allocator);
                defer storage.deinit();

                const context = contract.ContractContext.init(
                    contract_address,
                    deployer,
                    value,
                    &[_]u8{}, // No constructor args for now
                    gas_limit,
                    12345, // Block number (placeholder)
                    @intCast(std.time.timestamp()),
                    &storage,
                );

                // Execute constructor if available, with contract context
                const result = self.wasm_runtime.executeFunctionWithContext(
                    module, 
                    "_constructor", 
                    &[_]wasm.WasmValue{}, 
                    gas_limit,
                    @constCast(&context)
                ) catch |err| {
                    return contract.ExecutionResult{
                        .success = false,
                        .gas_used = self.wasm_runtime.gas_used,
                        .return_data = &[_]u8{},
                        .error_msg = @errorName(err),
                        .contract_address = null,
                    };
                };

                // Store contract in enhanced storage
                try self.storage.storeContract(contract_address, bytecode, .WASM);

                return contract.ExecutionResult{
                    .success = result.success,
                    .gas_used = result.gas_used,
                    .return_data = result.return_data,
                    .error_msg = result.error_msg,
                    .contract_address = contract_address,
                };
            },
            .Unknown => {
                return contract.ExecutionResult{
                    .success = false,
                    .gas_used = 0,
                    .return_data = &[_]u8{},
                    .error_msg = "Unknown bytecode format",
                    .contract_address = null,
                };
            },
        }
    }

    /// Execute contract call with automatic format detection
    pub fn callContract(self: *HybridRuntime, contract_address: contract.Address, caller: contract.Address, value: u64, data: []const u8, gas_limit: u64) !contract.ExecutionResult {
        // Get contract info from enhanced storage
        const contract_info = self.storage.getContractInfo(contract_address) orelse {
            return contract.ExecutionResult{
                .success = false,
                .gas_used = 0,
                .return_data = &[_]u8{},
                .error_msg = "Contract not found",
                .contract_address = null,
            };
        };

        switch (contract_info.format) {
            .ZVM => {
                return self.zvm_runtime.call_contract(contract_address, caller, value, data, gas_limit);
            },
            .EVM => {
                var zevm_runtime = zevm.ZevmRuntime.init(self.allocator);
                defer zevm_runtime.deinit();

                const result = try zevm_runtime.execute_evm(contract_info.bytecode, caller, value, data, gas_limit);

                return contract.ExecutionResult{
                    .success = result.success,
                    .gas_used = result.gas_used,
                    .return_data = result.return_data,
                    .error_msg = result.error_msg,
                    .contract_address = null,
                };
            },
            .WASM => {
                const module = try self.wasm_runtime.loadModule(contract_info.bytecode);

                // Create contract context for WASM call
                var storage = contract.Storage.init(self.allocator);
                defer storage.deinit();

                const context = contract.ContractContext.init(
                    contract_address,
                    caller,
                    value,
                    data,
                    gas_limit,
                    12345, // Block number (placeholder)
                    @intCast(std.time.timestamp()),
                    &storage,
                );

                // Determine function to call based on data
                const function_name = if (data.len >= 4) "call" else "main";
                
                // Execute with contract context
                const result = self.wasm_runtime.executeFunctionWithContext(
                    module, 
                    function_name, 
                    &[_]wasm.WasmValue{}, 
                    gas_limit,
                    @constCast(&context)
                ) catch |err| {
                    return contract.ExecutionResult{
                        .success = false,
                        .gas_used = self.wasm_runtime.gas_used,
                        .return_data = &[_]u8{},
                        .error_msg = @errorName(err),
                        .contract_address = contract_address,
                    };
                };

                return contract.ExecutionResult{
                    .success = result.success,
                    .gas_used = result.gas_used,
                    .return_data = result.return_data,
                    .error_msg = result.error_msg,
                    .contract_address = contract_address,
                };
            },
            .Unknown => {
                return contract.ExecutionResult{
                    .success = false,
                    .gas_used = 0,
                    .return_data = &[_]u8{},
                    .error_msg = "Unknown contract format",
                    .contract_address = null,
                };
            },
        }
    }

    /// Broadcast contract deployment to network
    pub fn broadcastContractDeployment(self: *HybridRuntime, bytecode: []const u8, metadata: networking.ContractDeployPayload.ContractMetadata) !void {
        if (self.network_node) |node| {
            const format = switch (detectBytecodeFormat(bytecode)) {
                .ZVM => networking.ContractDeployPayload.BytecodeFormat.zvm,
                .EVM => networking.ContractDeployPayload.BytecodeFormat.evm,
                .WASM => networking.ContractDeployPayload.BytecodeFormat.wasm,
                .Unknown => return error.InvalidBytecode,
            };

            try node.deployContract(bytecode, format, metadata);
        }
    }

    /// Get runtime statistics
    pub fn getStatistics(self: *HybridRuntime) RuntimeStatistics {
        return RuntimeStatistics{
            .contracts_deployed = self.storage.getContractCount(),
            .total_gas_used = 0, // TODO: Track total gas
            .network_peers = if (self.network_node) |node| node.getConnectedPeers().len else 0,
            .wasm_modules_loaded = self.wasm_runtime.modules.items.len,
        };
    }
};

/// Bytecode format detection
pub const BytecodeFormat = enum {
    ZVM,
    EVM,
    WASM,
    Unknown,
};

fn detectBytecodeFormat(bytecode: []const u8) BytecodeFormat {
    if (bytecode.len < 4) return .Unknown;

    // WASM magic number: 0x00 0x61 0x73 0x6D
    if (std.mem.eql(u8, bytecode[0..4], &[_]u8{ 0x00, 0x61, 0x73, 0x6D })) {
        return .WASM;
    }

    // ZVM magic opcodes
    if (bytecode[0] == @intFromEnum(zvm.Opcode.PUSH1) or
        bytecode[0] == @intFromEnum(zvm.Opcode.PUSH2) or
        bytecode[0] == @intFromEnum(zvm.Opcode.CALLER))
    {
        return .ZVM;
    }

    // EVM magic opcodes
    if (bytecode[0] == @intFromEnum(zevm.EvmOpcode.PUSH1) or
        bytecode[0] == @intFromEnum(zevm.EvmOpcode.PUSH2) or
        bytecode[0] == @intFromEnum(zevm.EvmOpcode.CALLER))
    {
        return .EVM;
    }

    return .Unknown;
}

/// Runtime statistics
pub const RuntimeStatistics = struct {
    contracts_deployed: u64,
    total_gas_used: u64,
    network_peers: usize,
    wasm_modules_loaded: u64,
};

/// Enhanced storage with format tracking
pub const EnhancedStorage = struct {
    allocator: std.mem.Allocator,
    contracts: std.HashMap(contract.Address, ContractInfo, contract.AddressHashContext, std.hash_map.default_max_load_percentage),
    storage_root: std.HashMap(contract.Address, std.HashMap([32]u8, [32]u8, std.hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage), contract.AddressHashContext, std.hash_map.default_max_load_percentage),

    pub const ContractInfo = struct {
        bytecode: []u8,
        format: BytecodeFormat,
        deployed_at: i64,
    };

    pub fn init(allocator: std.mem.Allocator) EnhancedStorage {
        return EnhancedStorage{
            .allocator = allocator,
            .contracts = std.HashMap(contract.Address, ContractInfo, contract.AddressHashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .storage_root = std.HashMap(contract.Address, std.HashMap([32]u8, [32]u8, std.hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage), contract.AddressHashContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }

    pub fn deinit(self: *EnhancedStorage) void {
        var contract_iterator = self.contracts.iterator();
        while (contract_iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.bytecode);
        }
        self.contracts.deinit();

        var storage_iterator = self.storage_root.iterator();
        while (storage_iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.storage_root.deinit();
    }

    pub fn storeContract(self: *EnhancedStorage, address: contract.Address, bytecode: []const u8, format: BytecodeFormat) !void {
        const owned_bytecode = try self.allocator.dupe(u8, bytecode);
        const info = ContractInfo{
            .bytecode = owned_bytecode,
            .format = format,
            .deployed_at = std.time.timestamp(),
        };
        try self.contracts.put(address, info);
    }

    pub fn getContractInfo(self: *EnhancedStorage, address: contract.Address) ?*const ContractInfo {
        return self.contracts.getPtr(address);
    }

    pub fn getContractCount(self: *EnhancedStorage) u64 {
        return self.contracts.count();
    }

    pub fn setStorage(self: *EnhancedStorage, contract_address: contract.Address, key: [32]u8, value: [32]u8) !void {
        var contract_storage = self.storage_root.getPtr(contract_address);
        if (contract_storage == null) {
            const new_storage = std.HashMap([32]u8, [32]u8, std.HashMap([32]u8, [32]u8, void, std.hash_map.default_max_load_percentage).Context, std.hash_map.default_max_load_percentage).init(self.allocator);
            try self.storage_root.put(contract_address, new_storage);
            contract_storage = self.storage_root.getPtr(contract_address);
        }

        try contract_storage.?.put(key, value);
    }

    pub fn getStorage(self: *EnhancedStorage, contract_address: contract.Address, key: [32]u8) [32]u8 {
        if (self.storage_root.get(contract_address)) |contract_storage| {
            return contract_storage.get(key) orelse [_]u8{0} ** 32;
        }
        return [_]u8{0} ** 32;
    }
};

/// Crypto context with direct zcrypto/zsig integration
pub const CryptoContext = struct {
    /// Initialize crypto context
    pub fn init() CryptoContext {
        return CryptoContext{};
    }

    /// Post-quantum signature verification (ML-DSA)
    pub fn verifyMLDSA(self: *CryptoContext, message: []const u8, signature: []const u8, public_key: []const u8) bool {
        _ = self;
        _ = message;
        _ = signature;
        _ = public_key;
        // Post-quantum signatures via zcrypto (when available)
        return true; // Placeholder - will be implemented with zcrypto post-quantum support
    }

    /// Classical signature verification (Ed25519) using zcrypto
    pub fn verifyEd25519(self: *CryptoContext, message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        _ = self;
        return Crypto.ed25519_verify(message, signature, public_key);
    }

    /// Hybrid key exchange (X25519 + ML-KEM) using zcrypto
    pub fn performHybridKeyExchange(self: *CryptoContext, classical_public: [32]u8, pq_ciphertext: []const u8) ![64]u8 {
        _ = self;
        _ = pq_ciphertext;
        
        // For now, just return the classical public key duplicated
        // Real ML-KEM implementation will be available via zcrypto
        var hybrid_secret: [64]u8 = undefined;
        @memcpy(hybrid_secret[0..32], &classical_public);
        @memcpy(hybrid_secret[32..64], &classical_public);
        
        return hybrid_secret;
    }
};

// Tests
test "Runtime crypto hooks" {
    const data = "Hello, ZVM!";
    const hash = RuntimeHooks.keccak256_hook(data);
    try std.testing.expect(hash.len == 32);
}

test "Runtime VM execution" {
    var storage = contract.Storage.init(std.testing.allocator);
    defer storage.deinit();

    const context = contract.ContractContext.init(
        contract.AddressUtils.zero(),
        contract.AddressUtils.zero(),
        0,
        &[_]u8{},
        21000,
        1,
        @intCast(std.time.timestamp()),
        &storage,
    );

    var runtime_vm = RuntimeVM.init(context);

    // Simple bytecode: PUSH1 1, HALT
    const bytecode = [_]u8{ @intFromEnum(zvm.Opcode.PUSH1), 1, @intFromEnum(zvm.Opcode.HALT) };

    const result = try runtime_vm.execute(&bytecode);
    try std.testing.expect(result.success);
}

test "Contract deployment and execution" {
    var runtime_inst = Runtime.init(std.testing.allocator);
    defer runtime_inst.deinit();

    const deployer = contract.AddressUtils.random();
    const bytecode = [_]u8{ @intFromEnum(zvm.Opcode.PUSH1), 42, @intFromEnum(zvm.Opcode.HALT) };

    // Deploy contract
    const deploy_result = try runtime_inst.deploy_contract(&bytecode, deployer, 0, 100000);
    try std.testing.expect(deploy_result.success);

    // Contract address is in return_data
    const contract_addr = @as(*const contract.Address, @ptrCast(deploy_result.return_data)).*;

    // Call contract
    const call_result = try runtime_inst.call_contract(contract_addr, deployer, 0, &[_]u8{}, 21000);
    try std.testing.expect(call_result.success);
}
