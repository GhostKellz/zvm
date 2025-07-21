//! Enhanced Contract execution context and state management with caching and gas optimization
const std = @import("std");
const zvm = @import("zvm.zig");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const HashMap = std.HashMap;
const AutoHashMap = std.AutoHashMap;
const Mutex = std.Thread.Mutex;
const Atomic = std.atomic.Value;

/// Contract address type (20 bytes like Ethereum)
pub const Address = [20]u8;

/// Hash context for Address type in HashMap
pub const AddressHashContext = std.hash_map.AutoContext(Address);

/// Address utilities
pub const AddressUtils = struct {
    /// Create zero address
    pub fn zero() Address {
        return [_]u8{0} ** 20;
    }
    
    /// Create random address (for testing)
    pub fn random() Address {
        var address: Address = undefined;
        var rng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        rng.fill(&address);
        return address;
    }
    
    /// Create address from hex string
    pub fn fromHex(hex_str: []const u8) !Address {
        if (hex_str.len < 40) return error.InvalidLength;
        
        var address: Address = undefined;
        const start: usize = if (std.mem.startsWith(u8, hex_str, "0x")) 2 else 0;
        
        for (0..20) |i| {
            const hex_byte = hex_str[start + i * 2 .. start + i * 2 + 2];
            address[i] = try std.fmt.parseInt(u8, hex_byte, 16);
        }
        
        return address;
    }
    
    /// Convert address to hex string
    pub fn toHex(address: Address, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.alloc(u8, 42); // "0x" + 40 hex chars
        result[0] = '0';
        result[1] = 'x';
        
        for (address, 0..) |byte, i| {
            _ = std.fmt.bufPrint(result[2 + i * 2 ..][0..2], "{x:0>2}", .{byte}) catch unreachable;
        }
        
        return result;
    }
    
    /// Alias for toHex (snake_case version)
    pub fn to_hex(address: Address, allocator: std.mem.Allocator) ![]u8 {
        return toHex(address, allocator);
    }
    
    /// Alias for fromHex (snake_case version)
    pub fn from_hex(hex_str: []const u8) !Address {
        return fromHex(hex_str);
    }
};

/// Contract execution result
pub const ExecutionResult = struct {
    success: bool,
    gas_used: u64,
    return_data: []const u8,
    error_msg: ?[]const u8,
    contract_address: Address,
    cache_hit: bool = false,
    gas_savings: u64 = 0,
    execution_time_ns: u64 = 0,
};

/// Contract execution context
pub const ContractContext = struct {
    /// Address of the contract being executed
    address: Address,
    /// Address of the caller (msg.sender)
    sender: Address,
    /// Value transferred with the call (in wei/smallest unit)
    value: u256,
    /// Input data for the contract call
    input: []const u8,
    /// Gas limit for this execution
    gas_limit: u64,
    /// Block number (for deterministic execution)
    block_number: u64,
    /// Block timestamp
    block_timestamp: u64,
    /// Storage reference (will be managed by runtime)
    storage: *Storage,

    pub fn init(
        address: Address,
        sender: Address,
        value: u256,
        input: []const u8,
        gas_limit: u64,
        block_number: u64,
        block_timestamp: u64,
        storage: *Storage,
    ) ContractContext {
        return ContractContext{
            .address = address,
            .sender = sender,
            .value = value,
            .input = input,
            .gas_limit = gas_limit,
            .block_number = block_number,
            .block_timestamp = block_timestamp,
            .storage = storage,
        };
    }
};

/// Contract storage interface
pub const Storage = struct {
    /// Storage backend - either in-memory or persistent
    backend: StorageBackend,
    /// Contract address for persistent storage
    contract_address: ?Address = null,
    
    const StorageBackend = union(enum) {
        memory: std.ArrayHashMap(u256, u256, std.array_hash_map.AutoContext(u256), false),
        persistent: *@import("database.zig").PersistentStorage,
    };

    pub fn init(allocator: std.mem.Allocator) Storage {
        return Storage{
            .backend = .{ .memory = std.ArrayHashMap(u256, u256, std.array_hash_map.AutoContext(u256), false).init(allocator) },
        };
    }
    
    pub fn initPersistent(_: std.mem.Allocator, persistent_storage: *@import("database.zig").PersistentStorage, contract_address: Address) Storage {
        return Storage{
            .backend = .{ .persistent = persistent_storage },
            .contract_address = contract_address,
        };
    }

    pub fn deinit(self: *Storage) void {
        switch (self.backend) {
            .memory => |*memory| memory.deinit(),
            .persistent => {}, // Persistent storage is managed externally
        }
    }

    pub fn load(self: *Storage, key: u256) u256 {
        switch (self.backend) {
            .memory => |*memory| return memory.get(key) orelse 0,
            .persistent => |persistent| {
                if (self.contract_address) |addr| {
                    return persistent.load(addr, key) catch 0;
                }
                return 0;
            },
        }
    }

    pub fn store(self: *Storage, key: u256, value: u256) void {
        switch (self.backend) {
            .memory => |*memory| {
                memory.put(key, value) catch {
                    std.debug.panic("Failed to store value", .{});
                };
            },
            .persistent => |persistent| {
                if (self.contract_address) |addr| {
                    // For now, use zeros for block number and tx hash
                    // In real implementation, these would come from execution context
                    persistent.store(addr, key, value, 0, [_]u8{0} ** 32) catch {
                        std.debug.panic("Failed to store value in persistent storage", .{});
                    };
                }
            },
        }
    }

    /// Enhanced storage interface for caching integration
    pub fn loadWithCaching(self: *Storage, key: u256, cache: ?*AutoHashMap(u256, u256)) u256 {
        // Check cache first if provided
        if (cache) |storage_cache| {
            if (storage_cache.get(key)) |cached_value| {
                return cached_value;
            }
        }

        // Load from storage
        const value = self.load(key);

        // Update cache if provided
        if (cache) |storage_cache| {
            storage_cache.put(key, value) catch {}; // Ignore cache errors
        }

        return value;
    }

    /// Store with cache invalidation
    pub fn storeWithCaching(self: *Storage, key: u256, value: u256, cache: ?*AutoHashMap(u256, u256)) void {
        self.store(key, value);

        // Update cache if provided
        if (cache) |storage_cache| {
            storage_cache.put(key, value) catch {}; // Ignore cache errors
        }
    }
};

/// Contract bytecode and metadata
pub const Contract = struct {
    /// Contract bytecode
    code: []const u8,
    /// Contract ABI (for external calls)
    abi: ?[]const u8,
    /// Contract address
    address: Address,
    /// Creation timestamp
    created_at: u64,

    pub fn init(code: []const u8, address: Address, created_at: u64) Contract {
        return Contract{
            .code = code,
            .abi = null,
            .address = address,
            .created_at = created_at,
        };
    }

    /// Execute contract with given context
    pub fn execute(self: *Contract, context: ContractContext) zvm.VMError!ExecutionResult {
        var vm = zvm.VM.init();
        vm.load_bytecode(self.code, context.gas_limit);

        // Set up contract execution environment
        // Push context data onto stack (simplified)
        try vm.stack.push(@as(u256, @intCast(context.value)));
        try vm.stack.push(@as(u256, @intCast(context.block_number)));
        try vm.stack.push(@as(u256, @intCast(context.block_timestamp)));

        // Execute the contract
        vm.run() catch |err| switch (err) {
            zvm.VMError.ExecutionReverted => {
                return ExecutionResult{
                    .success = false,
                    .gas_used = vm.gas_used(),
                    .return_data = &[_]u8{},
                    .error_msg = "Execution reverted",
                    .contract_address = self.address,
                };
            },
            else => return err,
        };

        return ExecutionResult{
            .success = true,
            .gas_used = vm.gas_used(),
            .return_data = &[_]u8{}, // TODO: Extract from VM state
            .error_msg = null,
            .contract_address = self.address,
        };
    }
};


/// Contract execution cache entry
pub const CachedExecution = struct {
    result: ExecutionResult,
    input_hash: u64,
    context_hash: u64,
    timestamp: i64,
    hit_count: u32,
    gas_cost: u64,

    pub fn isValid(self: *const CachedExecution, ttl_seconds: i64) bool {
        const now = std.time.timestamp();
        return (now - self.timestamp) < ttl_seconds;
    }
};

/// Gas optimization configuration
pub const GasOptimizationConfig = struct {
    /// Enable execution result caching
    enable_caching: bool = true,
    /// Cache TTL in seconds
    cache_ttl_seconds: i64 = 300, // 5 minutes
    /// Maximum cache size (number of entries)
    max_cache_size: u32 = 10000,
    /// Enable gas metering optimizations
    enable_gas_optimizations: bool = true,
    /// Enable storage access caching
    enable_storage_cache: bool = true,
    /// Storage cache size
    storage_cache_size: u32 = 5000,
};

/// Gas optimization statistics
pub const GasOptimizationStats = struct {
    total_executions: u64 = 0,
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
    total_gas_saved: u64 = 0,
    avg_execution_time_ns: u64 = 0,
    storage_cache_hits: u64 = 0,
    storage_cache_misses: u64 = 0,
};

/// Enhanced smart contract registry with execution caching and gas optimization
pub const ContractRegistry = struct {
    allocator: Allocator,
    contracts: std.ArrayHashMap(Address, Contract, AddressContext, false),
    execution_cache: AutoHashMap(u64, CachedExecution),
    storage_cache: AutoHashMap(StorageCacheKey, u256),
    gas_optimization_config: GasOptimizationConfig,
    optimization_stats: GasOptimizationStats,
    cache_mutex: Mutex,
    storage_cache_mutex: Mutex,

    const StorageCacheKey = struct {
        contract_address: Address,
        storage_key: u256,

        pub fn hash(self: @This()) u64 {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(&self.contract_address);
            hasher.update(std.mem.asBytes(&self.storage_key));
            return hasher.final();
        }

        pub fn eql(self: @This(), other: @This()) bool {
            return std.mem.eql(u8, &self.contract_address, &other.contract_address) and
                self.storage_key == other.storage_key;
        }
    };

    const AddressContext = struct {
        pub fn hash(self: @This(), s: Address) u32 {
            _ = self;
            return @truncate(std.hash_map.hashString(&s));
        }

        pub fn eql(self: @This(), a: Address, b: Address, b_index: usize) bool {
            _ = self;
            _ = b_index;
            return std.mem.eql(u8, &a, &b);
        }
    };

    pub fn init(allocator: std.mem.Allocator) ContractRegistry {
        return ContractRegistry{
            .allocator = allocator,
            .contracts = std.ArrayHashMap(Address, Contract, AddressContext, false).init(allocator),
            .execution_cache = AutoHashMap(u64, CachedExecution).init(allocator),
            .storage_cache = AutoHashMap(StorageCacheKey, u256).init(allocator),
            .gas_optimization_config = GasOptimizationConfig{},
            .optimization_stats = GasOptimizationStats{},
            .cache_mutex = Mutex{},
            .storage_cache_mutex = Mutex{},
        };
    }

    pub fn deinit(self: *ContractRegistry) void {
        self.contracts.deinit();
        self.execution_cache.deinit();
        self.storage_cache.deinit();
    }

    pub fn deploy(self: *ContractRegistry, code: []const u8, address: Address) !void {
        const contract_obj = Contract.init(code, address, @intCast(std.time.timestamp()));
        try self.contracts.put(address, contract_obj);
    }

    pub fn get(self: *ContractRegistry, address: Address) ?*Contract {
        return self.contracts.getPtr(address);
    }

    /// Enhanced contract call with caching and gas optimization
    pub fn call(self: *ContractRegistry, contract_address: Address, context: ContractContext) !ExecutionResult {
        const start_time = std.time.nanoTimestamp();
        self.optimization_stats.total_executions += 1;

        if (self.get(contract_address)) |contract_obj| {
            // Generate cache key from input and context
            const cache_key = try self.generateCacheKey(contract_address, context);

            // Check execution cache first
            if (self.gas_optimization_config.enable_caching) {
                if (self.getCachedExecution(cache_key)) |cached| {
                    if (cached.isValid(self.gas_optimization_config.cache_ttl_seconds)) {
                        // Cache hit!
                        self.optimization_stats.cache_hits += 1;
                        self.optimization_stats.total_gas_saved += cached.gas_cost;

                        var result = cached.result;
                        result.cache_hit = true;
                        result.gas_savings = cached.gas_cost;
                        result.execution_time_ns = @intCast(std.time.nanoTimestamp() - start_time);

                        std.log.debug("Contract execution cache hit for {any}", .{contract_address});
                        return result;
                    }
                }
                self.optimization_stats.cache_misses += 1;
            }

            // Execute with gas optimization
            var result = try self.executeWithOptimizations(contract_obj, context);
            result.execution_time_ns = @intCast(std.time.nanoTimestamp() - start_time);

            // Cache the result if enabled
            if (self.gas_optimization_config.enable_caching and result.success) {
                try self.cacheExecution(cache_key, result, context);
            }

            // Update statistics
            self.optimization_stats.avg_execution_time_ns =
                (self.optimization_stats.avg_execution_time_ns + result.execution_time_ns) / 2;

            return result;
        } else {
            return ExecutionResult{
                .success = false,
                .gas_used = 0,
                .return_data = &[_]u8{},
                .error_msg = "Contract not found",
                .contract_address = AddressUtils.zero(),
                .execution_time_ns = @intCast(std.time.nanoTimestamp() - start_time),
            };
        }
    }

    /// Execute contract with gas optimizations
    fn executeWithOptimizations(self: *ContractRegistry, contract_obj: *Contract, context: ContractContext) !ExecutionResult {
        // Create optimized execution context
        var optimized_context = context;

        // If gas optimizations are enabled, apply them
        if (self.gas_optimization_config.enable_gas_optimizations) {
            // Pre-warm storage cache for common patterns
            try self.prewarmStorageCache(contract_obj.address, context);

            // Optimize gas limit based on historical data
            optimized_context.gas_limit = self.optimizeGasLimit(contract_obj.address, context.gas_limit);
        }

        // Execute the contract
        var result = try contract_obj.execute(optimized_context);

        // Apply post-execution optimizations
        if (result.success and self.gas_optimization_config.enable_gas_optimizations) {
            const gas_savings = self.calculateGasSavings(context.gas_limit, result.gas_used);
            result.gas_savings = gas_savings;
            self.optimization_stats.total_gas_saved += gas_savings;
        }

        return result;
    }

    /// Generate cache key for execution
    fn generateCacheKey(self: *ContractRegistry, contract_address: Address, context: ContractContext) !u64 {
        _ = self;
        var hasher = std.hash.Wyhash.init(0);

        // Hash contract address
        hasher.update(&contract_address);

        // Hash input data
        hasher.update(context.input);

        // Hash relevant context (excluding gas_limit which shouldn't affect deterministic execution)
        hasher.update(&context.sender);
        hasher.update(std.mem.asBytes(&context.value));
        hasher.update(std.mem.asBytes(&context.block_number));
        hasher.update(std.mem.asBytes(&context.block_timestamp));

        return hasher.final();
    }

    /// Get cached execution result
    fn getCachedExecution(self: *ContractRegistry, cache_key: u64) ?CachedExecution {
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        if (self.execution_cache.get(cache_key)) |cached| {
            // Update hit count
            var updated_cached = cached;
            updated_cached.hit_count += 1;
            self.execution_cache.put(cache_key, updated_cached) catch {};
            return updated_cached;
        }
        return null;
    }

    /// Cache execution result
    fn cacheExecution(self: *ContractRegistry, cache_key: u64, result: ExecutionResult, context: ContractContext) !void {
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        // Check cache size limit
        if (self.execution_cache.count() >= self.gas_optimization_config.max_cache_size) {
            try self.evictOldestCacheEntries();
        }

        const cached_execution = CachedExecution{
            .result = result,
            .input_hash = std.hash_map.hashString(context.input),
            .context_hash = cache_key,
            .timestamp = std.time.timestamp(),
            .hit_count = 0,
            .gas_cost = result.gas_used,
        };

        try self.execution_cache.put(cache_key, cached_execution);
        std.log.debug("Cached execution result for key {any}", .{cache_key});
    }

    /// Evict oldest cache entries when cache is full
    fn evictOldestCacheEntries(self: *ContractRegistry) !void {
        const evict_count = self.gas_optimization_config.max_cache_size / 4; // Evict 25%
        var entries_to_remove = ArrayList(u64).init(self.allocator);
        defer entries_to_remove.deinit();

        var iterator = self.execution_cache.iterator();
        while (iterator.next()) |entry| {
            if (entries_to_remove.items.len < evict_count) {
                try entries_to_remove.append(entry.key_ptr.*);
            } else {
                // Find oldest entry to replace
                var oldest_idx: usize = 0;
                var oldest_time = self.execution_cache.get(entries_to_remove.items[0]).?.timestamp;

                for (entries_to_remove.items, 0..) |key, i| {
                    const cached = self.execution_cache.get(key).?;
                    if (cached.timestamp < oldest_time) {
                        oldest_time = cached.timestamp;
                        oldest_idx = i;
                    }
                }

                const current_cached = entry.value_ptr.*;
                const oldest_cached = self.execution_cache.get(entries_to_remove.items[oldest_idx]).?;
                if (current_cached.timestamp < oldest_cached.timestamp) {
                    entries_to_remove.items[oldest_idx] = entry.key_ptr.*;
                }
            }
        }

        // Remove selected entries
        for (entries_to_remove.items) |key| {
            _ = self.execution_cache.remove(key);
        }

        std.log.debug("Evicted {} cache entries", .{entries_to_remove.items.len});
    }

    /// Pre-warm storage cache with likely-to-be-accessed storage slots
    fn prewarmStorageCache(self: *ContractRegistry, contract_address: Address, context: ContractContext) !void {
        if (!self.gas_optimization_config.enable_storage_cache) return;

        // Simple heuristic: cache storage slots 0-10 which are commonly used
        // In a real implementation, this could be based on analysis of the contract bytecode
        _ = context;

        self.storage_cache_mutex.lock();
        defer self.storage_cache_mutex.unlock();

        var i: u256 = 0;
        while (i < 10) : (i += 1) {
            const cache_key = StorageCacheKey{
                .contract_address = contract_address,
                .storage_key = i,
            };

            // Only cache if not already present
            if (!self.storage_cache.contains(cache_key)) {
                // TODO: Load from actual storage backend
                const value: u256 = 0; // Placeholder
                try self.storage_cache.put(cache_key, value);
                self.optimization_stats.storage_cache_misses += 1;
            } else {
                self.optimization_stats.storage_cache_hits += 1;
            }
        }
    }

    /// Optimize gas limit based on historical execution data
    fn optimizeGasLimit(self: *ContractRegistry, contract_address: Address, original_gas_limit: u64) u64 {
        _ = contract_address; // TODO: Use contract-specific optimization

        // Simple optimization: if average execution uses less gas, suggest a lower limit
        if (self.optimization_stats.total_executions > 10) {
            const avg_gas_used = self.optimization_stats.total_gas_saved / self.optimization_stats.total_executions;
            if (avg_gas_used < original_gas_limit) {
                // Suggest 120% of average usage, but not less than 21000 (minimum transaction gas)
                const optimized_limit = @max(21000, (avg_gas_used * 120) / 100);
                return @min(optimized_limit, original_gas_limit);
            }
        }

        return original_gas_limit;
    }

    /// Calculate gas savings from optimizations
    fn calculateGasSavings(self: *ContractRegistry, gas_limit: u64, gas_used: u64) u64 {
        _ = self;
        if (gas_limit > gas_used) {
            // Simple savings calculation - in practice this would be more sophisticated
            const unused_gas = gas_limit - gas_used;
            return unused_gas / 10; // 10% credit for unused gas
        }
        return 0;
    }

    /// Get optimization statistics
    pub fn getOptimizationStatistics(self: *ContractRegistry) GasOptimizationStats {
        return self.optimization_stats;
    }

    /// Configure gas optimizations
    pub fn configureOptimizations(self: *ContractRegistry, config: GasOptimizationConfig) void {
        self.gas_optimization_config = config;
        std.log.info("Updated gas optimization config: caching={}, gas_opts={}", .{ config.enable_caching, config.enable_gas_optimizations });
    }

    /// Clear execution cache
    pub fn clearCache(self: *ContractRegistry) void {
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();

        self.execution_cache.clearAndFree();
        self.storage_cache.clearAndFree();

        std.log.info("Cleared contract execution and storage caches");
    }
};


// Tests
test "Contract context creation" {
    var storage = Storage.init(std.testing.allocator);
    defer storage.deinit();

    const context = ContractContext.init(
        AddressUtils.zero(),
        AddressUtils.zero(),
        1000,
        &[_]u8{0x42},
        21000,
        12345,
        1640995200,
        &storage,
    );

    try std.testing.expect(context.value == 1000);
    try std.testing.expect(context.gas_limit == 21000);
    try std.testing.expect(context.input[0] == 0x42);
}

test "Storage operations" {
    var storage = Storage.init(std.testing.allocator);
    defer storage.deinit();

    storage.store(42, 100);
    try std.testing.expect(storage.load(42) == 100);
    try std.testing.expect(storage.load(99) == 0); // Non-existent key
}

test "Address utilities" {
    const zero_addr = AddressUtils.zero();
    try std.testing.expect(std.mem.eql(u8, &zero_addr, &[_]u8{0} ** 20));

    const random_addr = AddressUtils.random();
    const hex = try AddressUtils.to_hex(random_addr, std.testing.allocator);
    defer std.testing.allocator.free(hex);
    const parsed = try AddressUtils.from_hex(hex);
    try std.testing.expect(std.mem.eql(u8, &random_addr, &parsed));
}

test "Contract registry" {
    var registry = ContractRegistry.init(std.testing.allocator);
    defer registry.deinit();

    const addr = AddressUtils.random();
    const code = [_]u8{@intFromEnum(zvm.Opcode.HALT)};

    try registry.deploy(&code, addr);

    const contract_obj = registry.get(addr);
    try std.testing.expect(contract_obj != null);
    try std.testing.expect(std.mem.eql(u8, contract_obj.?.code, &code));
}

test "Contract execution caching" {
    var registry = ContractRegistry.init(std.testing.allocator);
    defer registry.deinit();

    // Configure caching
    registry.configureOptimizations(GasOptimizationConfig{
        .enable_caching = true,
        .cache_ttl_seconds = 60,
        .max_cache_size = 100,
    });

    const addr = AddressUtils.random();
    const code = [_]u8{@intFromEnum(zvm.Opcode.HALT)};

    try registry.deploy(&code, addr);

    var storage = Storage.init(std.testing.allocator);
    defer storage.deinit();

    const context = ContractContext.init(
        addr,
        AddressUtils.random(),
        0,
        &[_]u8{ 0x42, 0x43 },
        21000,
        12345,
        1640995200,
        &storage,
    );

    // First execution (cache miss)
    const result1 = try registry.call(addr, context);
    try std.testing.expect(!result1.cache_hit);

    // Second execution with same context (should be cache hit)
    const result2 = try registry.call(addr, context);
    try std.testing.expect(result2.cache_hit);

    // Verify statistics
    const stats = registry.getOptimizationStatistics();
    try std.testing.expect(stats.cache_hits == 1);
    try std.testing.expect(stats.cache_misses == 1);
    try std.testing.expect(stats.total_executions == 2);
}

test "Gas optimization statistics" {
    var registry = ContractRegistry.init(std.testing.allocator);
    defer registry.deinit();

    registry.configureOptimizations(GasOptimizationConfig{
        .enable_gas_optimizations = true,
        .enable_storage_cache = true,
    });

    const stats = registry.getOptimizationStatistics();
    try std.testing.expect(stats.total_executions == 0);
    try std.testing.expect(stats.total_gas_saved == 0);
}
