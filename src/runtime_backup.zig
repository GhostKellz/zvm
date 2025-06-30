//! ZVM Runtime - Enhanced hybrid runtime with networking, crypto, and storage
const std = @import("std");
const zvm = @import("zvm.zig");
const zevm = @import("zevm.zig");
const wasm = @import("wasm.zig");
const contract = @import("contract.zig");
const networking = @import("networking.zig");

/// Enhanced Runtime with hybrid execution capabilities
pub const HybridRuntime = struct {
    allocator: std.mem.Allocator,
    zvm_runtime: OriginalRuntime,
    wasm_runtime: wasm.WasmRuntime,
    network_node: ?*networking.NetworkNode,
    storage: Storage,
    crypto: CryptoContext,
    
    /// Initialize hybrid runtime
    pub fn init(allocator: std.mem.Allocator) HybridRuntime {
        return HybridRuntime{
            .allocator = allocator,
            .zvm_runtime = Runtime.init(allocator),
            .wasm_runtime = wasm.WasmRuntime.init(allocator),
            .network_node = null,
            .storage = Storage.init(allocator),
            .crypto = CryptoContext.init(),
        };
    }
    
    /// Deinitialize hybrid runtime
    pub fn deinit(self: *HybridRuntime) void {
        self.zvm_runtime.deinit();
        self.wasm_runtime.deinit();
        self.storage.deinit();
        if (self.network_node) |node| {
            node.deinit();
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
                return self.zvm_runtime.deploy_contract(bytecode, deployer, value, gas_limit);
            },
            .EVM => {
                std.debug.print("Deploying EVM contract\n", .{});
                var zevm_runtime = zevm.ZevmRuntime.init(self.allocator);
                defer zevm_runtime.deinit();
                
                const result = try zevm_runtime.execute_evm(bytecode, deployer, value, &[_]u8{}, gas_limit);
                
                return contract.ExecutionResult{
                    .success = result.success,
                    .gas_used = result.gas_used,
                    .return_data = result.return_data,
                    .logs = &[_]contract.Log{}, // TODO: Convert EVM logs
                    .error_msg = result.error_msg,
                    .contract_address = if (result.success) contract.AddressUtils.random() else null,
                };
            },
            .WASM => {
                std.debug.print("Deploying WASM contract\n", .{});
                const module = try self.wasm_runtime.loadModule(bytecode);
                
                // Execute constructor if available
                const result = self.wasm_runtime.executeFunction(module, "_constructor", &[_]wasm.WasmValue{}) catch |err| {
                    return contract.ExecutionResult{
                        .success = false,
                        .gas_used = self.wasm_runtime.gas_used,
                        .return_data = &[_]u8{},
                        .logs = &[_]contract.Log{},
                        .error_msg = @errorName(err),
                        .contract_address = null,
                    };
                };
                
                _ = result;
                
                return contract.ExecutionResult{
                    .success = true,
                    .gas_used = self.wasm_runtime.gas_used,
                    .return_data = &[_]u8{},
                    .logs = &[_]contract.Log{},
                    .error_msg = null,
                    .contract_address = contract.AddressUtils.random(),
                };
            },
            .Unknown => {
                return contract.ExecutionResult{
                    .success = false,
                    .gas_used = 0,
                    .return_data = &[_]u8{},
                    .logs = &[_]contract.Log{},
                    .error_msg = "Unknown bytecode format",
                    .contract_address = null,
                };
            },
        }
    }
    
    /// Execute contract call with automatic format detection
    pub fn callContract(self: *HybridRuntime, contract_address: contract.Address, caller: contract.Address, value: u64, data: []const u8, gas_limit: u64) !contract.ExecutionResult {
        // Get contract bytecode from storage
        const bytecode = self.storage.getContract(contract_address) orelse {
            return contract.ExecutionResult{
                .success = false,
                .gas_used = 0,
                .return_data = &[_]u8{},
                .logs = &[_]contract.Log{},
                .error_msg = "Contract not found",
                .contract_address = null,
            };
        };
        
        const format = detectBytecodeFormat(bytecode);
        
        switch (format) {
            .ZVM => {
                return self.zvm_runtime.call_contract(contract_address, caller, value, data, gas_limit);
            },
            .EVM => {
                var zevm_runtime = zevm.ZevmRuntime.init(self.allocator);
                defer zevm_runtime.deinit();
                
                const result = try zevm_runtime.execute_evm(bytecode, caller, value, data, gas_limit);
                
                return contract.ExecutionResult{
                    .success = result.success,
                    .gas_used = result.gas_used,
                    .return_data = result.return_data,
                    .logs = &[_]contract.Log{},
                    .error_msg = result.error_msg,
                    .contract_address = null,
                };
            },
            .WASM => {
                const module = try self.wasm_runtime.loadModule(bytecode);
                
                // Determine function to call based on data
                const function_name = if (data.len >= 4) "call" else "main";
                const result = try self.wasm_runtime.executeFunction(module, function_name, &[_]wasm.WasmValue{});
                
                _ = result;
                
                return contract.ExecutionResult{
                    .success = true,
                    .gas_used = self.wasm_runtime.gas_used,
                    .return_data = &[_]u8{},
                    .logs = &[_]contract.Log{},
                    .error_msg = null,
                    .contract_address = null,
                };
            },
            .Unknown => {
                return contract.ExecutionResult{
                    .success = false,
                    .gas_used = 0,
                    .return_data = &[_]u8{},
                    .logs = &[_]contract.Log{},
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
            .wasm_modules_loaded = self.wasm_runtime.getModuleCount(),
        };
    }
};

/// Runtime statistics
pub const RuntimeStatistics = struct {
    contracts_deployed: u64,
    total_gas_used: u64,
    network_peers: usize,
    wasm_modules_loaded: u64,
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
    if (std.mem.eql(u8, bytecode[0..4], &[_]u8{0x00, 0x61, 0x73, 0x6D})) {
        return .WASM;
    }
    
    // ZVM magic opcodes
    if (bytecode[0] == @intFromEnum(zvm.Opcode.PUSH1) or 
        bytecode[0] == @intFromEnum(zvm.Opcode.PUSH2) or
        bytecode[0] == @intFromEnum(zvm.Opcode.CALLER)) {
        return .ZVM;
    }
    
    // EVM magic opcodes  
    if (bytecode[0] == @intFromEnum(zevm.EvmOpcode.PUSH1) or
        bytecode[0] == @intFromEnum(zevm.EvmOpcode.PUSH2) or
        bytecode[0] == @intFromEnum(zevm.EvmOpcode.CALLER)) {
        return .EVM;
    }
    
    return .Unknown;
}

/// Enhanced storage interface
pub const Storage = struct {
    allocator: std.mem.Allocator,
    contracts: std.HashMap(contract.Address, []u8, contract.AddressHashContext, std.hash_map.default_max_load_percentage),
    storage_root: std.HashMap(contract.Address, std.HashMap([32]u8, [32]u8, std.HashMap([32]u8, [32]u8, void, std.hash_map.default_max_load_percentage).Context, std.hash_map.default_max_load_percentage), contract.AddressHashContext, std.hash_map.default_max_load_percentage),
    
    pub fn init(allocator: std.mem.Allocator) Storage {
        return Storage{
            .allocator = allocator,
            .contracts = std.HashMap(contract.Address, []u8, contract.AddressHashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .storage_root = std.HashMap(contract.Address, std.HashMap([32]u8, [32]u8, std.HashMap([32]u8, [32]u8, void, std.hash_map.default_max_load_percentage).Context, std.hash_map.default_max_load_percentage), contract.AddressHashContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *Storage) void {
        var contract_iterator = self.contracts.iterator();
        while (contract_iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.contracts.deinit();
        
        var storage_iterator = self.storage_root.iterator();
        while (storage_iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.storage_root.deinit();
    }
    
    pub fn storeContract(self: *Storage, address: contract.Address, bytecode: []const u8) !void {
        const owned_bytecode = try self.allocator.dupe(u8, bytecode);
        try self.contracts.put(address, owned_bytecode);
    }
    
    pub fn getContract(self: *Storage, address: contract.Address) ?[]const u8 {
        return self.contracts.get(address);
    }
    
    pub fn getContractCount(self: *Storage) u64 {
        return self.contracts.count();
    }
    
    pub fn setStorage(self: *Storage, contract_address: contract.Address, key: [32]u8, value: [32]u8) !void {
        var contract_storage = self.storage_root.getPtr(contract_address);
        if (contract_storage == null) {
            var new_storage = std.HashMap([32]u8, [32]u8, std.HashMap([32]u8, [32]u8, void, std.hash_map.default_max_load_percentage).Context, std.hash_map.default_max_load_percentage).init(self.allocator);
            try self.storage_root.put(contract_address, new_storage);
            contract_storage = self.storage_root.getPtr(contract_address);
        }
        
        try contract_storage.?.put(key, value);
    }
    
    pub fn getStorage(self: *Storage, contract_address: contract.Address, key: [32]u8) [32]u8 {
        if (self.storage_root.get(contract_address)) |contract_storage| {
            return contract_storage.get(key) orelse [_]u8{0} ** 32;
        }
        return [_]u8{0} ** 32;
    }
};

/// Enhanced crypto context with zcrypto integration
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
        // TODO: Integrate with zcrypto.pq.ml_dsa
        return true;
    }
    
    /// Classical signature verification (Ed25519)
    pub fn verifyEd25519(self: *CryptoContext, message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        _ = self;
        _ = message;
        _ = signature;
        _ = public_key;
        // TODO: Integrate with zcrypto.asym.ed25519
        return true;
    }
    
    /// Hybrid key exchange (X25519 + ML-KEM)
    pub fn performHybridKeyExchange(self: *CryptoContext, classical_public: [32]u8, pq_ciphertext: []const u8) ![64]u8 {
        _ = self;
        _ = classical_public;
        _ = pq_ciphertext;
        // TODO: Integrate with zcrypto hybrid key exchange
        return [_]u8{0} ** 64;
    }
};
