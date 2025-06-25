//! Contract execution context and state management
const std = @import("std");
const zvm = @import("zvm.zig");

/// Contract address type (20 bytes like Ethereum)
pub const Address = [20]u8;

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
    /// Simple key-value storage for contracts
    /// In a real implementation, this would be backed by a database
    data: std.ArrayHashMap(u256, u256, std.array_hash_map.AutoContext(u256), false),
    
    pub fn init(allocator: std.mem.Allocator) Storage {
        return Storage{
            .data = std.ArrayHashMap(u256, u256, std.array_hash_map.AutoContext(u256), false).init(allocator),
        };
    }
    
    pub fn deinit(self: *Storage) void {
        self.data.deinit();
    }
    
    pub fn load(self: *Storage, key: u256) u256 {
        return self.data.get(key) orelse 0;
    }
    
    pub fn store(self: *Storage, key: u256, value: u256) void {
        self.data.put(key, value) catch {
            // In a real implementation, we'd handle this error properly
            std.debug.panic("Failed to store value", .{});
        };
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
                };
            },
            else => return err,
        };
        
        return ExecutionResult{
            .success = true,
            .gas_used = vm.gas_used(),
            .return_data = &[_]u8{}, // TODO: Extract from VM state
            .error_msg = null,
        };
    }
};

/// Result of contract execution
pub const ExecutionResult = struct {
    success: bool,
    gas_used: u64,
    return_data: []const u8,
    error_msg: ?[]const u8,
};

/// Smart contract registry for deployed contracts
pub const ContractRegistry = struct {
    contracts: std.ArrayHashMap(Address, Contract, AddressContext, false),
    
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
            .contracts = std.ArrayHashMap(Address, Contract, AddressContext, false).init(allocator),
        };
    }
    
    pub fn deinit(self: *ContractRegistry) void {
        self.contracts.deinit();
    }
    
    pub fn deploy(self: *ContractRegistry, code: []const u8, address: Address) !void {
        const contract_obj = Contract.init(code, address, @intCast(std.time.timestamp()));
        try self.contracts.put(address, contract_obj);
    }
    
    pub fn get(self: *ContractRegistry, address: Address) ?*Contract {
        return self.contracts.getPtr(address);
    }
    
    pub fn call(
        self: *ContractRegistry, 
        contract_address: Address,
        context: ContractContext
    ) !ExecutionResult {
        if (self.get(contract_address)) |contract_obj| {
            return contract_obj.execute(context);
        } else {
            return ExecutionResult{
                .success = false,
                .gas_used = 0,
                .return_data = &[_]u8{},
                .error_msg = "Contract not found",
            };
        }
    }
};

/// Utility functions for addresses
pub const AddressUtils = struct {
    pub fn zero() Address {
        return [_]u8{0} ** 20;
    }
    
    pub fn from_hex(hex: []const u8) !Address {
        if (hex.len != 40) return error.InvalidLength;
        var addr: Address = undefined;
        for (0..20) |i| {
            addr[i] = try std.fmt.parseInt(u8, hex[i*2..i*2+2], 16);
        }
        return addr;
    }
    
    pub fn to_hex(addr: Address) [40]u8 {
        var result: [40]u8 = undefined;
        for (addr, 0..) |byte, i| {
            _ = std.fmt.bufPrint(result[i*2..i*2+2], "{:02x}", .{byte}) catch unreachable;
        }
        return result;
    }
    
    pub fn random() Address {
        var addr: Address = undefined;
        std.crypto.random.bytes(&addr);
        return addr;
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
    const hex = AddressUtils.to_hex(random_addr);
    const parsed = try AddressUtils.from_hex(&hex);
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
