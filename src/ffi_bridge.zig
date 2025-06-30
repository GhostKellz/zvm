//! FFI Bridge for ZVM ↔ Rust Service Integration
//! Provides seamless interoperability with ghostd and walletd Rust services
const std = @import("std");
const contract = @import("contract.zig");

/// FFI Result types for error handling
pub const FfiResult = extern struct {
    success: bool,
    data_ptr: [*]const u8,
    data_len: usize,
    error_code: i32,
    error_msg_ptr: [*]const u8,
    error_msg_len: usize,

    pub fn toSlice(self: FfiResult, allocator: std.mem.Allocator) ![]const u8 {
        if (!self.success) {
            const error_msg = if (self.error_msg_len > 0) 
                self.error_msg_ptr[0..self.error_msg_len] 
            else 
                "Unknown FFI error";
            std.log.err("FFI Error {}: {s}", .{ self.error_code, error_msg });
            return error.FfiError;
        }

        if (self.data_len == 0) return &[_]u8{};
        
        const result = try allocator.alloc(u8, self.data_len);
        @memcpy(result, self.data_ptr[0..self.data_len]);
        return result;
    }

    pub fn free(self: FfiResult) void {
        if (self.data_len > 0) {
            ffi_free_result(self);
        }
    }
};

/// FFI Contract Address (compatible with Rust [u8; 20])
pub const FfiAddress = extern struct {
    bytes: [20]u8,

    pub fn fromZig(addr: contract.Address) FfiAddress {
        return FfiAddress{ .bytes = addr };
    }

    pub fn toZig(self: FfiAddress) contract.Address {
        return self.bytes;
    }
};

/// FFI Transaction structure for Rust interop
pub const FfiTransaction = extern struct {
    from: FfiAddress,
    to: ?FfiAddress,
    value: u64,
    gas_limit: u64,
    gas_price: u64,
    data_ptr: [*]const u8,
    data_len: usize,
    nonce: u64,
};

/// FFI Contract Deployment structure
pub const FfiContractDeploy = extern struct {
    bytecode_ptr: [*]const u8,
    bytecode_len: usize,
    deployer: FfiAddress,
    value: u64,
    gas_limit: u64,
    constructor_args_ptr: [*]const u8,
    constructor_args_len: usize,
};

/// FFI Contract Call structure
pub const FfiContractCall = extern struct {
    contract_address: FfiAddress,
    caller: FfiAddress,
    value: u64,
    gas_limit: u64,
    function_data_ptr: [*]const u8,
    function_data_len: usize,
};

/// FFI Wallet operations
pub const FfiWalletRequest = extern struct {
    wallet_id_ptr: [*]const u8,
    wallet_id_len: usize,
    operation_type: u32,
    data_ptr: [*]const u8,
    data_len: usize,
};

// External C-compatible function declarations for Rust FFI
extern "C" fn ghostd_deploy_contract(deploy: *const FfiContractDeploy) FfiResult;
extern "C" fn ghostd_call_contract(call: *const FfiContractCall) FfiResult;
extern "C" fn ghostd_submit_transaction(tx: *const FfiTransaction) FfiResult;
extern "C" fn ghostd_get_balance(address: *const FfiAddress) FfiResult;
extern "C" fn ghostd_get_block_number() u64;
extern "C" fn ghostd_get_block_timestamp() u64;

extern "C" fn walletd_create_wallet(name_ptr: [*]const u8, name_len: usize, account_type_ptr: [*]const u8, account_type_len: usize) FfiResult;
extern "C" fn walletd_sign_transaction(wallet_req: *const FfiWalletRequest) FfiResult;
extern "C" fn walletd_verify_signature(address: *const FfiAddress, message_ptr: [*]const u8, message_len: usize, signature_ptr: [*]const u8, signature_len: usize) bool;
extern "C" fn walletd_get_wallet_address(wallet_id_ptr: [*]const u8, wallet_id_len: usize) FfiResult;

// Memory management
extern "C" fn ffi_free_result(result: FfiResult) void;
extern "C" fn ffi_alloc(size: usize) [*]u8;
extern "C" fn ffi_free(ptr: [*]u8, size: usize) void;

/// High-level FFI Bridge interface
pub const FfiBridge = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) FfiBridge {
        return FfiBridge{ .allocator = allocator };
    }

    /// Deploy contract via ghostd FFI
    pub fn deployContract(self: *FfiBridge, bytecode: []const u8, deployer: contract.Address, value: u64, gas_limit: u64, constructor_args: []const u8) !contract.ExecutionResult {
        const deploy = FfiContractDeploy{
            .bytecode_ptr = bytecode.ptr,
            .bytecode_len = bytecode.len,
            .deployer = FfiAddress.fromZig(deployer),
            .value = value,
            .gas_limit = gas_limit,
            .constructor_args_ptr = constructor_args.ptr,
            .constructor_args_len = constructor_args.len,
        };

        const result = ghostd_deploy_contract(&deploy);
        defer result.free();

        const response_data = try result.toSlice(self.allocator);
        defer self.allocator.free(response_data);

        // Parse JSON response from ghostd
        const deploy_result = try std.json.parseFromSlice(struct {
            success: bool,
            contract_address: ?[40]u8, // Hex string
            gas_used: u64,
            transaction_hash: []const u8,
            error_message: ?[]const u8,
        }, self.allocator, response_data);

        if (!deploy_result.success) {
            return contract.ExecutionResult{
                .success = false,
                .gas_used = deploy_result.gas_used,
                .return_data = &[_]u8{},
                .error_msg = deploy_result.error_message,
                .contract_address = null,
            };
        }

        const contract_addr = if (deploy_result.contract_address) |addr_hex|
            try contract.AddressUtils.from_hex(&addr_hex)
        else
            null;

        return contract.ExecutionResult{
            .success = true,
            .gas_used = deploy_result.gas_used,
            .return_data = deploy_result.transaction_hash,
            .error_msg = null,
            .contract_address = contract_addr,
        };
    }

    /// Call contract function via ghostd FFI
    pub fn callContract(self: *FfiBridge, contract_address: contract.Address, caller: contract.Address, value: u64, gas_limit: u64, function_data: []const u8) !contract.ExecutionResult {
        const call = FfiContractCall{
            .contract_address = FfiAddress.fromZig(contract_address),
            .caller = FfiAddress.fromZig(caller),
            .value = value,
            .gas_limit = gas_limit,
            .function_data_ptr = function_data.ptr,
            .function_data_len = function_data.len,
        };

        const result = ghostd_call_contract(&call);
        defer result.free();

        const response_data = try result.toSlice(self.allocator);
        defer self.allocator.free(response_data);

        const call_result = try std.json.parseFromSlice(struct {
            success: bool,
            return_data: []const u8,
            gas_used: u64,
            error_message: ?[]const u8,
        }, self.allocator, response_data);

        return contract.ExecutionResult{
            .success = call_result.success,
            .gas_used = call_result.gas_used,
            .return_data = try self.allocator.dupe(u8, call_result.return_data),
            .error_msg = if (call_result.error_message) |msg| try self.allocator.dupe(u8, msg) else null,
            .contract_address = contract_address,
        };
    }

    /// Submit transaction via ghostd FFI
    pub fn submitTransaction(self: *FfiBridge, from: contract.Address, to: ?contract.Address, value: u64, gas_limit: u64, gas_price: u64, data: []const u8, nonce: u64) !struct { 
        success: bool, 
        transaction_hash: ?[]const u8, 
        gas_used: u64 
    } {
        const tx = FfiTransaction{
            .from = FfiAddress.fromZig(from),
            .to = if (to) |addr| FfiAddress.fromZig(addr) else null,
            .value = value,
            .gas_limit = gas_limit,
            .gas_price = gas_price,
            .data_ptr = data.ptr,
            .data_len = data.len,
            .nonce = nonce,
        };

        const result = ghostd_submit_transaction(&tx);
        defer result.free();

        const response_data = try result.toSlice(self.allocator);
        defer self.allocator.free(response_data);

        const tx_result = try std.json.parseFromSlice(struct {
            success: bool,
            transaction_hash: ?[]const u8,
            gas_used: u64,
        }, self.allocator, response_data);

        return .{
            .success = tx_result.success,
            .transaction_hash = if (tx_result.transaction_hash) |hash| try self.allocator.dupe(u8, hash) else null,
            .gas_used = tx_result.gas_used,
        };
    }

    /// Get account balance via ghostd FFI
    pub fn getBalance(self: *FfiBridge, address: contract.Address) !u64 {
        const ffi_addr = FfiAddress.fromZig(address);
        const result = ghostd_get_balance(&ffi_addr);
        defer result.free();

        const response_data = try result.toSlice(self.allocator);
        defer self.allocator.free(response_data);

        const balance_result = try std.json.parseFromSlice(struct {
            balance: u64,
        }, self.allocator, response_data);

        return balance_result.balance;
    }

    /// Get current block information from ghostd
    pub fn getBlockInfo(self: *FfiBridge) struct { number: u64, timestamp: u64 } {
        _ = self;
        return .{
            .number = ghostd_get_block_number(),
            .timestamp = ghostd_get_block_timestamp(),
        };
    }

    /// Create wallet via walletd FFI
    pub fn createWallet(self: *FfiBridge, name: []const u8, account_type: []const u8) !struct { 
        wallet_id: []const u8, 
        address: contract.Address 
    } {
        const result = walletd_create_wallet(name.ptr, name.len, account_type.ptr, account_type.len);
        defer result.free();

        const response_data = try result.toSlice(self.allocator);
        defer self.allocator.free(response_data);

        const wallet_result = try std.json.parseFromSlice(struct {
            wallet: struct {
                id: []const u8,
                address: [40]u8, // Hex string
            },
        }, self.allocator, response_data);

        const address = try contract.AddressUtils.from_hex(&wallet_result.wallet.address);

        return .{
            .wallet_id = try self.allocator.dupe(u8, wallet_result.wallet.id),
            .address = address,
        };
    }

    /// Sign transaction via walletd FFI
    pub fn signTransaction(self: *FfiBridge, wallet_id: []const u8, transaction_data: []const u8) ![]const u8 {
        const wallet_req = FfiWalletRequest{
            .wallet_id_ptr = wallet_id.ptr,
            .wallet_id_len = wallet_id.len,
            .operation_type = 1, // SIGN_TRANSACTION
            .data_ptr = transaction_data.ptr,
            .data_len = transaction_data.len,
        };

        const result = walletd_sign_transaction(&wallet_req);
        defer result.free();

        const response_data = try result.toSlice(self.allocator);
        defer self.allocator.free(response_data);

        const sign_result = try std.json.parseFromSlice(struct {
            signature: []const u8,
        }, self.allocator, response_data);

        return try self.allocator.dupe(u8, sign_result.signature);
    }

    /// Verify signature via walletd FFI
    pub fn verifySignature(self: *FfiBridge, address: contract.Address, message: []const u8, signature: []const u8) bool {
        _ = self;
        const ffi_addr = FfiAddress.fromZig(address);
        return walletd_verify_signature(&ffi_addr, message.ptr, message.len, signature.ptr, signature.len);
    }

    /// Get wallet address from wallet ID
    pub fn getWalletAddress(self: *FfiBridge, wallet_id: []const u8) !contract.Address {
        const result = walletd_get_wallet_address(wallet_id.ptr, wallet_id.len);
        defer result.free();

        const response_data = try result.toSlice(self.allocator);
        defer self.allocator.free(response_data);

        const addr_result = try std.json.parseFromSlice(struct {
            address: [40]u8, // Hex string
        }, self.allocator, response_data);

        return try contract.AddressUtils.from_hex(&addr_result.address);
    }
};

/// FFI-enabled Runtime that uses Rust services
pub const FfiRuntime = struct {
    allocator: std.mem.Allocator,
    ffi_bridge: FfiBridge,

    pub fn init(allocator: std.mem.Allocator) FfiRuntime {
        return FfiRuntime{
            .allocator = allocator,
            .ffi_bridge = FfiBridge.init(allocator),
        };
    }

    /// Deploy contract using Rust ghostd service
    pub fn deployContract(self: *FfiRuntime, bytecode: []const u8, deployer: contract.Address, value: u64, gas_limit: u64) !contract.ExecutionResult {
        return self.ffi_bridge.deployContract(bytecode, deployer, value, gas_limit, &[_]u8{});
    }

    /// Call contract using Rust ghostd service
    pub fn callContract(self: *FfiRuntime, contract_address: contract.Address, caller: contract.Address, value: u64, gas_limit: u64, function_data: []const u8) !contract.ExecutionResult {
        return self.ffi_bridge.callContract(contract_address, caller, value, gas_limit, function_data);
    }

    /// Enhanced contract execution with blockchain integration
    pub fn executeWithBlockchain(self: *FfiRuntime, contract_address: contract.Address, caller: contract.Address, input: []const u8, gas_limit: u64) !contract.ExecutionResult {
        // Get current blockchain state
        const block_info = self.ffi_bridge.getBlockInfo();
        const caller_balance = self.ffi_bridge.getBalance(caller) catch 0;

        std.log.info("Executing contract {} at block {} with caller balance {}", .{ 
            std.fmt.fmtSliceHexLower(&contract_address), 
            block_info.number, 
            caller_balance 
        });

        // Execute contract call with real blockchain state
        return self.callContract(contract_address, caller, 0, gas_limit, input);
    }
};

// Mock implementations for testing when Rust services are not available
pub const MockFfiBridge = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MockFfiBridge {
        return MockFfiBridge{ .allocator = allocator };
    }

    pub fn deployContract(self: *MockFfiBridge, bytecode: []const u8, deployer: contract.Address, value: u64, gas_limit: u64, constructor_args: []const u8) !contract.ExecutionResult {
        _ = bytecode;
        _ = deployer;
        _ = value;
        _ = constructor_args;

        const mock_address = contract.AddressUtils.random();
        std.log.info("Mock FFI: Deployed contract to {x}", .{std.fmt.fmtSliceHexLower(&mock_address)});

        return contract.ExecutionResult{
            .success = true,
            .gas_used = gas_limit / 2, // Mock gas usage
            .return_data = &mock_address,
            .error_msg = null,
            .contract_address = mock_address,
        };
    }

    pub fn callContract(self: *MockFfiBridge, contract_address: contract.Address, caller: contract.Address, value: u64, gas_limit: u64, function_data: []const u8) !contract.ExecutionResult {
        _ = caller;
        _ = value;
        _ = function_data;

        std.log.info("Mock FFI: Called contract {x}", .{std.fmt.fmtSliceHexLower(&contract_address)});

        const mock_result = try self.allocator.dupe(u8, "mock_return_data");

        return contract.ExecutionResult{
            .success = true,
            .gas_used = gas_limit / 3,
            .return_data = mock_result,
            .error_msg = null,
            .contract_address = contract_address,
        };
    }

    pub fn getBalance(self: *MockFfiBridge, address: contract.Address) !u64 {
        _ = self;
        _ = address;
        return 1000000; // Mock balance
    }
};

// Tests
test "FFI address conversion" {
    const zig_addr = contract.AddressUtils.random();
    const ffi_addr = FfiAddress.fromZig(zig_addr);
    const converted_back = ffi_addr.toZig();

    try std.testing.expectEqualSlices(u8, &zig_addr, &converted_back);
}

test "Mock FFI bridge" {
    var mock_bridge = MockFfiBridge.init(std.testing.allocator);
    
    const result = try mock_bridge.deployContract(
        &[_]u8{0x60, 0x80}, // Mock bytecode
        contract.AddressUtils.zero(),
        0,
        100000,
        &[_]u8{}
    );

    try std.testing.expect(result.success);
    try std.testing.expect(result.contract_address != null);
}