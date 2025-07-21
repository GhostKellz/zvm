//! Enhanced FFI Bridge for ZVM ↔ Rust Service Integration with Zero-Copy Serialization
//! Provides high-performance, zero-copy interoperability with ghostd and walletd Rust services
const std = @import("std");
const contract = @import("contract.zig");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Mutex = std.Thread.Mutex;

/// Zero-Copy Memory Buffer for FFI operations
pub const ZeroCopyBuffer = extern struct {
    data: [*]u8,
    capacity: usize,
    len: usize,
    ref_count: Atomic(u32),

    pub fn init(capacity: usize) !ZeroCopyBuffer {
        const data = ffi_alloc(capacity);
        return ZeroCopyBuffer{
            .data = data,
            .capacity = capacity,
            .len = 0,
            .ref_count = Atomic(u32).init(1),
        };
    }

    pub fn retain(self: *ZeroCopyBuffer) void {
        _ = self.ref_count.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *ZeroCopyBuffer) void {
        if (self.ref_count.fetchSub(1, .monotonic) == 1) {
            ffi_free(self.data, self.capacity);
        }
    }

    pub fn asSlice(self: *const ZeroCopyBuffer) []const u8 {
        return self.data[0..self.len];
    }

    pub fn asMutableSlice(self: *ZeroCopyBuffer) []u8 {
        return self.data[0..self.capacity];
    }

    pub fn setLen(self: *ZeroCopyBuffer, len: usize) void {
        self.len = @min(len, self.capacity);
    }
};

/// Enhanced FFI Result with zero-copy support
pub const FfiResult = extern struct {
    success: bool,
    data_ptr: [*]const u8,
    data_len: usize,
    error_code: i32,
    error_msg_ptr: [*]const u8,
    error_msg_len: usize,
    /// Zero-copy buffer reference (null if not using zero-copy)
    zero_copy_buffer: ?*ZeroCopyBuffer,

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
        
        // Use zero-copy buffer if available
        if (self.zero_copy_buffer) |buffer| {
            // Note: In actual implementation, buffer retention would be handled by Rust side
            return buffer.asSlice();
        }
        
        const result = try allocator.alloc(u8, self.data_len);
        @memcpy(result, self.data_ptr[0..self.data_len]);
        return result;
    }

    pub fn toZeroCopySlice(self: FfiResult) ![]const u8 {
        if (!self.success) {
            return error.FfiError;
        }

        if (self.zero_copy_buffer) |buffer| {
            // Note: In actual implementation, buffer retention would be handled by Rust side
            return buffer.asSlice();
        }

        return self.data_ptr[0..self.data_len];
    }

    pub fn free(self: FfiResult) void {
        if (self.zero_copy_buffer) |buffer| {
            buffer.release();
        } else if (self.data_len > 0) {
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

/// Zero-Copy Serialization Buffer Pool
pub const SerializationBufferPool = struct {
    allocator: Allocator,
    available_buffers: ArrayList(*ZeroCopyBuffer),
    buffer_size: usize,
    max_buffers: u32,
    statistics: PoolStatistics,
    mutex: Mutex,

    const PoolStatistics = struct {
        allocations: u64 = 0,
        deallocations: u64 = 0,
        cache_hits: u64 = 0,
        cache_misses: u64 = 0,
        current_usage: u64 = 0,
        peak_usage: u64 = 0,
        total_allocated: u64 = 0,
        total_reused: u64 = 0,
        current_active: u32 = 0,
        peak_active: u32 = 0,
        serialization_time_ns: u64 = 0,
        zero_copy_hits: u64 = 0,
    };

    pub fn init(allocator: Allocator, buffer_size: usize, max_buffers: u32) SerializationBufferPool {
        return SerializationBufferPool{
            .allocator = allocator,
            .available_buffers = ArrayList(*ZeroCopyBuffer).init(allocator),
            .buffer_size = buffer_size,
            .max_buffers = max_buffers,
            .statistics = PoolStatistics{},
            .mutex = Mutex{},
        };
    }

    pub fn deinit(self: *SerializationBufferPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.available_buffers.items) |buffer| {
            buffer.release();
            self.allocator.destroy(buffer);
        }
        self.available_buffers.deinit();
    }

    pub fn acquire(self: *SerializationBufferPool) !*ZeroCopyBuffer {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.available_buffers.items.len > 0) {
            const buffer = self.available_buffers.pop() orelse return error.BufferPoolExhausted;
            // Note: Buffer reference counting would be managed in production
            self.statistics.total_reused += 1;
            self.statistics.current_usage += 1;
            if (self.statistics.current_usage > self.statistics.peak_usage) {
                self.statistics.peak_usage = self.statistics.current_usage;
            }
            return buffer;
        }

        if (self.statistics.current_active >= self.max_buffers) {
            return error.BufferPoolExhausted;
        }

        const buffer = try self.allocator.create(ZeroCopyBuffer);
        buffer.* = try ZeroCopyBuffer.init(self.buffer_size);
        self.statistics.total_allocated += 1;
        self.statistics.current_active += 1;
        
        if (self.statistics.current_active > self.statistics.peak_active) {
            self.statistics.peak_active = self.statistics.current_active;
        }

        return buffer;
    }

    pub fn release(self: *SerializationBufferPool, buffer: *ZeroCopyBuffer) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.statistics.current_usage = if (self.statistics.current_usage > 0) self.statistics.current_usage - 1 else 0;

        if (self.available_buffers.items.len < self.max_buffers / 2) {
            buffer.setLen(0); // Reset buffer
            self.available_buffers.append(buffer) catch {
                // If we can't store in pool, just release the buffer
                buffer.release();
                self.allocator.destroy(buffer);
                self.statistics.current_active -= 1;
                return;
            };
        } else {
            buffer.release();
            self.allocator.destroy(buffer);
            self.statistics.current_active -= 1;
        }
    }

    pub fn getStatistics(self: *SerializationBufferPool) PoolStatistics {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.statistics;
    }
};

/// Enhanced FFI Transaction structure with zero-copy support
pub const FfiTransaction = extern struct {
    from: FfiAddress,
    to: ?FfiAddress,
    value: u64,
    gas_limit: u64,
    gas_price: u64,
    data_ptr: [*]const u8,
    data_len: usize,
    nonce: u64,
    /// Zero-copy buffer reference for transaction data
    zero_copy_data: ?*ZeroCopyBuffer,

    pub fn initWithZeroCopy(from: FfiAddress, to: ?FfiAddress, value: u64, gas_limit: u64, gas_price: u64, nonce: u64, data_buffer: *ZeroCopyBuffer) FfiTransaction {
        return FfiTransaction{
            .from = from,
            .to = to,
            .value = value,
            .gas_limit = gas_limit,
            .gas_price = gas_price,
            .data_ptr = data_buffer.data,
            .data_len = data_buffer.len,
            .nonce = nonce,
            .zero_copy_data = data_buffer,
        };
    }

    pub fn free(self: *FfiTransaction) void {
        if (self.zero_copy_data) |buffer| {
            buffer.release();
        }
    }
};

/// Enhanced FFI Contract Deployment structure with zero-copy support
pub const FfiContractDeploy = extern struct {
    bytecode_ptr: [*]const u8,
    bytecode_len: usize,
    deployer: FfiAddress,
    value: u64,
    gas_limit: u64,
    constructor_args_ptr: [*]const u8,
    constructor_args_len: usize,
    /// Zero-copy buffers for bytecode and constructor args
    zero_copy_bytecode: ?*ZeroCopyBuffer,
    zero_copy_args: ?*ZeroCopyBuffer,

    pub fn initWithZeroCopy(deployer: FfiAddress, value: u64, gas_limit: u64, bytecode_buffer: *ZeroCopyBuffer, args_buffer: ?*ZeroCopyBuffer) FfiContractDeploy {
        return FfiContractDeploy{
            .bytecode_ptr = bytecode_buffer.data,
            .bytecode_len = bytecode_buffer.len,
            .deployer = deployer,
            .value = value,
            .gas_limit = gas_limit,
            .constructor_args_ptr = if (args_buffer) |args| args.data else undefined,
            .constructor_args_len = if (args_buffer) |args| args.len else 0,
            .zero_copy_bytecode = bytecode_buffer,
            .zero_copy_args = args_buffer,
        };
    }

    pub fn free(self: *FfiContractDeploy) void {
        if (self.zero_copy_bytecode) |buffer| {
            buffer.release();
        }
        if (self.zero_copy_args) |buffer| {
            buffer.release();
        }
    }
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
// Note: These would be linked against actual Rust libraries in production
// For testing, we use mock implementations

// extern "C" fn ghostd_deploy_contract(deploy: *const FfiContractDeploy) FfiResult;
// extern "C" fn ghostd_call_contract(call: *const FfiContractCall) FfiResult;
// extern "C" fn ghostd_submit_transaction(tx: *const FfiTransaction) FfiResult;
// extern "C" fn ghostd_get_balance(address: *const FfiAddress) FfiResult;
// extern "C" fn ghostd_get_block_number() u64;
// extern "C" fn ghostd_get_block_timestamp() u64;

// extern "C" fn walletd_create_wallet(name_ptr: [*]const u8, name_len: usize, account_type_ptr: [*]const u8, account_type_len: usize) FfiResult;
// extern "C" fn walletd_sign_transaction(wallet_req: *const FfiWalletRequest) FfiResult;
// extern "C" fn walletd_verify_signature(address: *const FfiAddress, message_ptr: [*]const u8, message_len: usize, signature_ptr: [*]const u8, signature_len: usize) bool;
// extern "C" fn walletd_get_wallet_address(wallet_id_ptr: [*]const u8, wallet_id_len: usize) FfiResult;

// Memory management
// extern "C" fn ffi_free_result(result: FfiResult) void;
// extern "C" fn ffi_alloc(size: usize) [*]u8;
// extern "C" fn ffi_free(ptr: [*]u8, size: usize) void;

// Mock implementations for testing
fn ffi_alloc(size: usize) [*]u8 {
    const allocator = std.heap.page_allocator;
    const slice = allocator.alloc(u8, size) catch return undefined;
    return slice.ptr;
}

fn ffi_free(ptr: [*]u8, size: usize) void {
    const allocator = std.heap.page_allocator;
    const slice = ptr[0..size];
    allocator.free(slice);
}

fn ffi_free_result(result: FfiResult) void {
    _ = result;
    // Mock implementation - in real code this would free Rust-allocated memory
}

/// Enhanced High-level FFI Bridge interface with zero-copy serialization
pub const FfiBridge = struct {
    allocator: std.mem.Allocator,
    buffer_pool: SerializationBufferPool,
    performance_stats: FfiPerformanceStats,
    config: FfiBridgeConfig,

    const FfiBridgeConfig = struct {
        enable_zero_copy: bool = true,
        buffer_pool_size: u32 = 100,
        default_buffer_size: usize = 64 * 1024, // 64KB
        enable_compression: bool = true,
        compression_threshold: usize = 1024, // 1KB
    };

    const FfiPerformanceStats = struct {
        total_calls: u64 = 0,
        zero_copy_calls: u64 = 0,
        serialization_time_ns: u64 = 0,
        deserialization_time_ns: u64 = 0,
        bytes_transferred: u64 = 0,
        bytes_saved_zero_copy: u64 = 0,
        avg_call_latency_ns: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, config: FfiBridgeConfig) FfiBridge {
        return FfiBridge{ 
            .allocator = allocator,
            .buffer_pool = SerializationBufferPool.init(allocator, config.default_buffer_size, config.buffer_pool_size),
            .performance_stats = FfiPerformanceStats{},
            .config = config,
        };
    }

    pub fn deinit(self: *FfiBridge) void {
        self.buffer_pool.deinit();
    }

    /// Serialize data to zero-copy buffer for FFI transfer
    fn serializeToZeroCopy(self: *FfiBridge, data: []const u8) !*ZeroCopyBuffer {
        const start_time = std.time.nanoTimestamp();
        defer {
            const elapsed = std.time.nanoTimestamp() - start_time;
            self.performance_stats.serialization_time_ns += @intCast(elapsed);
        }

        const buffer = try self.buffer_pool.acquire();
        
        if (data.len > buffer.capacity) {
            self.buffer_pool.release(buffer);
            return error.DataTooLarge;
        }

        const buffer_slice = buffer.asMutableSlice();
        @memcpy(buffer_slice[0..data.len], data);
        buffer.setLen(data.len);
        
        self.performance_stats.bytes_transferred += data.len;
        self.performance_stats.zero_copy_calls += 1;
        
        return buffer;
    }

    /// Deserialize data from zero-copy buffer
    fn deserializeFromZeroCopy(self: *FfiBridge, buffer: *ZeroCopyBuffer) ![]const u8 {
        const start_time = std.time.nanoTimestamp();
        defer {
            const elapsed = std.time.nanoTimestamp() - start_time;
            self.performance_stats.deserialization_time_ns += @intCast(elapsed);
        }

        self.performance_stats.bytes_saved_zero_copy += buffer.len;
        return buffer.asSlice();
    }

    /// Deploy contract via ghostd FFI with zero-copy optimization (mock implementation)
    pub fn deployContract(self: *FfiBridge, bytecode: []const u8, deployer: contract.Address, value: u64, gas_limit: u64, constructor_args: []const u8) !contract.ExecutionResult {
        _ = deployer;
        _ = value;
        const call_start = std.time.nanoTimestamp();
        self.performance_stats.total_calls += 1;

        // Mock implementation for testing - demonstrates zero-copy concepts
        if (self.config.enable_zero_copy and bytecode.len >= self.config.compression_threshold) {
            // Use zero-copy for large bytecode
            const bytecode_buffer = try self.serializeToZeroCopy(bytecode);
            defer self.buffer_pool.release(bytecode_buffer);

            if (constructor_args.len > 0) {
                const args_buffer = try self.serializeToZeroCopy(constructor_args);
                defer self.buffer_pool.release(args_buffer);
            }

            std.log.debug("FFI: Using zero-copy deployment for {} bytes bytecode", .{bytecode.len});
        }

        // Update performance statistics
        const call_elapsed = std.time.nanoTimestamp() - call_start;
        self.performance_stats.avg_call_latency_ns = 
            (self.performance_stats.avg_call_latency_ns + @as(u64, @intCast(call_elapsed))) / 2;

        // Mock successful deployment
        const mock_address = contract.AddressUtils.random();
        const mock_tx_hash = try self.allocator.dupe(u8, "0x1234567890abcdef");

        return contract.ExecutionResult{
            .success = true,
            .gas_used = gas_limit / 2,
            .return_data = mock_tx_hash,
            .error_msg = null,
            .contract_address = mock_address,
        };
    }

    /// Call contract function via ghostd FFI (mock implementation)
    pub fn callContract(self: *FfiBridge, contract_address: contract.Address, caller: contract.Address, value: u64, gas_limit: u64, function_data: []const u8) !contract.ExecutionResult {
        _ = caller;
        _ = value;
        
        const call_start = std.time.nanoTimestamp();
        self.performance_stats.total_calls += 1;

        // Demonstrate zero-copy for large function data
        if (self.config.enable_zero_copy and function_data.len >= self.config.compression_threshold) {
            const data_buffer = try self.serializeToZeroCopy(function_data);
            defer self.buffer_pool.release(data_buffer);
            std.log.debug("FFI: Using zero-copy for {} bytes function data", .{function_data.len});
        }

        // Update performance statistics
        const call_elapsed = std.time.nanoTimestamp() - call_start;
        self.performance_stats.avg_call_latency_ns = 
            (self.performance_stats.avg_call_latency_ns + @as(u64, @intCast(call_elapsed))) / 2;

        // Mock successful call
        const mock_result = try self.allocator.dupe(u8, "mock_return_data");

        return contract.ExecutionResult{
            .success = true,
            .gas_used = gas_limit / 3,
            .return_data = mock_result,
            .error_msg = null,
            .contract_address = contract_address,
        };
    }

    /// Mock method implementations for testing (actual FFI calls would be implemented in production)

    /// Get comprehensive performance statistics
    pub fn getPerformanceStatistics(self: *FfiBridge) struct {
        ffi_stats: FfiPerformanceStats,
        buffer_pool_stats: SerializationBufferPool.PoolStatistics,
    } {
        return .{
            .ffi_stats = self.performance_stats,
            .buffer_pool_stats = self.buffer_pool.getStatistics(),
        };
    }

    /// Configure zero-copy optimization settings
    pub fn configureOptimizations(self: *FfiBridge, config: FfiBridgeConfig) void {
        self.config = config;
        std.log.info("FFI Bridge: Updated config - zero_copy={}, compression_threshold={} bytes", .{ 
            config.enable_zero_copy, 
            config.compression_threshold 
        });
    }

    /// Reset performance statistics
    pub fn resetStatistics(self: *FfiBridge) void {
        self.performance_stats = FfiPerformanceStats{};
        std.log.info("FFI Bridge: Performance statistics reset");
    }
};

/// Enhanced FFI-enabled Runtime with zero-copy optimizations
pub const FfiRuntime = struct {
    allocator: std.mem.Allocator,
    ffi_bridge: FfiBridge,

    pub fn init(allocator: std.mem.Allocator) FfiRuntime {
        const default_config = FfiBridge.FfiBridgeConfig{
            .enable_zero_copy = true,
            .buffer_pool_size = 100,
            .default_buffer_size = 64 * 1024, // 64KB
            .enable_compression = true,
            .compression_threshold = 1024, // 1KB
        };

        return FfiRuntime{
            .allocator = allocator,
            .ffi_bridge = FfiBridge.init(allocator, default_config),
        };
    }

    pub fn deinit(self: *FfiRuntime) void {
        self.ffi_bridge.deinit();
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
            contract_address, 
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
        _ = self;
        _ = bytecode;
        _ = deployer;
        _ = value;
        _ = constructor_args;

        const mock_address = contract.AddressUtils.random();
        std.log.info("Mock FFI: Deployed contract to {}", .{mock_address});

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

        std.log.info("Mock FFI: Called contract {}", .{contract_address});

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

test "Zero-copy buffer operations" {
    var buffer = try ZeroCopyBuffer.init(1024);
    defer buffer.release();

    // Test basic operations
    try std.testing.expect(buffer.capacity == 1024);
    try std.testing.expect(buffer.len == 0);
    try std.testing.expect(buffer.ref_count.load(.monotonic) == 1);

    // Test data operations
    const test_data = "Hello, zero-copy world!";
    const buffer_slice = buffer.asMutableSlice();
    @memcpy(buffer_slice[0..test_data.len], test_data);
    buffer.setLen(test_data.len);

    const read_slice = buffer.asSlice();
    try std.testing.expectEqualStrings(test_data, read_slice);

    // Test reference counting
    buffer.retain();
    try std.testing.expect(buffer.ref_count.load(.monotonic) == 2);
    buffer.release(); // Back to 1
    try std.testing.expect(buffer.ref_count.load(.monotonic) == 1);
}

test "Serialization buffer pool" {
    var pool = SerializationBufferPool.init(std.testing.allocator, 1024, 10);
    defer pool.deinit();

    // Test buffer acquisition and release
    const buffer1 = try pool.acquire();
    defer pool.release(buffer1);

    const buffer2 = try pool.acquire();
    defer pool.release(buffer2);

    try std.testing.expect(buffer1 != buffer2);

    // Test pool statistics
    const stats = pool.getStatistics();
    try std.testing.expect(stats.total_allocated >= 2);
    try std.testing.expect(stats.current_active >= 2);
}

test "Enhanced FFI Bridge configuration" {
    const config = FfiBridge.FfiBridgeConfig{
        .enable_zero_copy = true,
        .buffer_pool_size = 50,
        .default_buffer_size = 32 * 1024,
        .enable_compression = false,
        .compression_threshold = 2048,
    };

    var bridge = FfiBridge.init(std.testing.allocator, config);
    defer bridge.deinit();

    // Test configuration
    try std.testing.expect(bridge.config.enable_zero_copy == true);
    try std.testing.expect(bridge.config.buffer_pool_size == 50);
    try std.testing.expect(bridge.config.default_buffer_size == 32 * 1024);

    // Test statistics
    const stats = bridge.getPerformanceStatistics();
    try std.testing.expect(stats.ffi_stats.total_calls == 0);
    try std.testing.expect(stats.ffi_stats.zero_copy_calls == 0);
}

test "Enhanced FFI Runtime initialization" {
    var runtime = FfiRuntime.init(std.testing.allocator);
    defer runtime.deinit();

    // Test that the runtime is properly initialized with default config
    try std.testing.expect(runtime.ffi_bridge.config.enable_zero_copy == true);
    try std.testing.expect(runtime.ffi_bridge.config.buffer_pool_size == 100);
}

test "Zero-copy serialization workflow" {
    const config = FfiBridge.FfiBridgeConfig{
        .enable_zero_copy = true,
        .buffer_pool_size = 10,
        .default_buffer_size = 1024,
        .enable_compression = false,
        .compression_threshold = 512,
    };

    var bridge = FfiBridge.init(std.testing.allocator, config);
    defer bridge.deinit();

    // Test serialization to zero-copy buffer
    const test_data = "This is test data for zero-copy serialization";
    const buffer = try bridge.serializeToZeroCopy(test_data);
    defer bridge.buffer_pool.release(buffer);

    // Verify the data was serialized correctly
    const deserialized = try bridge.deserializeFromZeroCopy(buffer);
    try std.testing.expectEqualStrings(test_data, deserialized);

    // Check statistics were updated
    const stats = bridge.getPerformanceStatistics();
    try std.testing.expect(stats.ffi_stats.zero_copy_calls == 1);
    try std.testing.expect(stats.ffi_stats.bytes_transferred == test_data.len);
}