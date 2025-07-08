//! RPC Server for ZVM Remote Contract Execution
//! Provides JSON-RPC and GhostWire-based API for blockchain operations
const std = @import("std");
const shroud = @import("shroud");
const ghostwire = shroud.ghostwire;
const contract = @import("contract.zig");
const runtime = @import("runtime.zig");
const database = @import("database.zig");
const ffi_bridge = @import("ffi_bridge.zig");
const quic_client = @import("quic_client.zig");

/// RPC Method types
pub const RpcMethod = enum {
    // Contract Operations
    deploy_contract,
    call_contract,
    get_contract_info,
    get_contract_storage,
    
    // Transaction Operations
    send_transaction,
    get_transaction,
    get_transaction_receipt,
    
    // Account Operations
    get_balance,
    get_nonce,
    create_account,
    
    // Blockchain Operations
    get_block_number,
    get_block,
    get_logs,
    
    // ZVM Specific
    execute_zvm_bytecode,
    execute_wasm_module,
    get_vm_statistics,
    
    // System Operations
    health_check,
    get_node_info,

    pub fn fromString(method: []const u8) ?RpcMethod {
        const method_map = std.ComptimeStringMap(RpcMethod, .{
            .{ "deploy_contract", .deploy_contract },
            .{ "call_contract", .call_contract },
            .{ "get_contract_info", .get_contract_info },
            .{ "get_contract_storage", .get_contract_storage },
            .{ "send_transaction", .send_transaction },
            .{ "get_transaction", .get_transaction },
            .{ "get_transaction_receipt", .get_transaction_receipt },
            .{ "get_balance", .get_balance },
            .{ "get_nonce", .get_nonce },
            .{ "create_account", .create_account },
            .{ "get_block_number", .get_block_number },
            .{ "get_block", .get_block },
            .{ "get_logs", .get_logs },
            .{ "execute_zvm_bytecode", .execute_zvm_bytecode },
            .{ "execute_wasm_module", .execute_wasm_module },
            .{ "get_vm_statistics", .get_vm_statistics },
            .{ "health_check", .health_check },
            .{ "get_node_info", .get_node_info },
        });
        
        return method_map.get(method);
    }
};

/// JSON-RPC 2.0 Request
pub const RpcRequest = struct {
    jsonrpc: []const u8 = "2.0",
    method: []const u8,
    params: ?std.json.Value = null,
    id: ?std.json.Value = null,
};

/// JSON-RPC 2.0 Response
pub const RpcResponse = struct {
    jsonrpc: []const u8 = "2.0",
    result: ?std.json.Value = null,
    @"error": ?RpcError = null,
    id: ?std.json.Value = null,
};

/// JSON-RPC Error
pub const RpcError = struct {
    code: i32,
    message: []const u8,
    data: ?std.json.Value = null,

    pub const PARSE_ERROR = -32700;
    pub const INVALID_REQUEST = -32600;
    pub const METHOD_NOT_FOUND = -32601;
    pub const INVALID_PARAMS = -32602;
    pub const INTERNAL_ERROR = -32603;
    pub const SERVER_ERROR = -32000;
};

/// RPC Server Configuration
pub const RpcConfig = struct {
    bind_address: []const u8 = "0.0.0.0",
    port: u16 = 8545, // Ethereum-compatible default
    max_connections: u32 = 1000,
    enable_cors: bool = true,
    cors_origins: []const []const u8 = &[_][]const u8{"*"},
    request_timeout_ms: u32 = 30000,
    max_request_size: usize = 1024 * 1024, // 1MB
    enable_quic: bool = true,
    quic_port: u16 = 8546,
};

/// RPC Server Context
pub const RpcContext = struct {
    allocator: std.mem.Allocator,
    config: RpcConfig,
    hybrid_runtime: *runtime.HybridRuntime,
    database: *database.PersistentStorage,
    ffi_bridge: ?*ffi_bridge.FfiBridge,
    quic_client: ?*quic_client.QuicClient,
    
    // Statistics
    requests_handled: std.atomic.Value(u64),
    active_connections: std.atomic.Value(u32),
    start_time: i64,
};

/// HTTP/JSON-RPC Server
pub const HttpRpcServer = struct {
    context: *RpcContext,
    server: std.http.Server,
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, context: *RpcContext) !HttpRpcServer {
        const server = std.http.Server.init(allocator, .{});
        
        return HttpRpcServer{
            .context = context,
            .server = server,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *HttpRpcServer) void {
        self.server.deinit();
    }

    pub fn start(self: *HttpRpcServer) !void {
        const address = try std.fmt.allocPrint(self.context.allocator, "{s}:{d}", .{ self.context.config.bind_address, self.context.config.port });
        defer self.context.allocator.free(address);

        const parsed_address = try std.net.Address.parseIp(self.context.config.bind_address, self.context.config.port);
        try self.server.listen(parsed_address);

        self.running.store(true, .release);
        std.log.info("ZVM RPC server listening on {s}", .{address});

        while (self.running.load(.acquire)) {
            const connection = self.server.accept(.{
                .allocator = self.context.allocator,
            }) catch |err| {
                std.log.err("Failed to accept connection: {}", .{err});
                continue;
            };

            // Handle connection in a separate thread
            const handle_thread = try std.Thread.spawn(.{}, handleConnection, .{ self, connection });
            handle_thread.detach();
        }
    }

    pub fn stop(self: *HttpRpcServer) void {
        self.running.store(false, .release);
    }

    fn handleConnection(self: *HttpRpcServer, connection: std.http.Server.Connection) void {
        defer connection.stream.close();
        
        _ = self.context.active_connections.fetchAdd(1, .acq_rel);
        defer _ = self.context.active_connections.fetchSub(1, .acq_rel);

        var buffer: [8192]u8 = undefined;
        
        const request = connection.stream.reader().readAll(&buffer) catch |err| {
            std.log.err("Failed to read request: {}", .{err});
            return;
        };

        const response = self.handleRpcRequest(request) catch |err| {
            std.log.err("Failed to handle RPC request: {}", .{err});
            self.sendErrorResponse(connection, RpcError.INTERNAL_ERROR, "Internal server error");
            return;
        };

        self.sendResponse(connection, response) catch |err| {
            std.log.err("Failed to send response: {}", .{err});
        };
    }

    fn handleRpcRequest(self: *HttpRpcServer, request_data: []const u8) ![]const u8 {
        _ = self.context.requests_handled.fetchAdd(1, .acq_rel);

        // Parse JSON-RPC request
        const parsed = std.json.parseFromSlice(RpcRequest, self.context.allocator, request_data) catch {
            return self.createErrorResponse(null, RpcError.PARSE_ERROR, "Parse error");
        };
        defer parsed.deinit();

        const request = parsed.value;
        
        // Validate JSON-RPC version
        if (!std.mem.eql(u8, request.jsonrpc, "2.0")) {
            return self.createErrorResponse(request.id, RpcError.INVALID_REQUEST, "Invalid JSON-RPC version");
        }

        // Get method
        const method = RpcMethod.fromString(request.method) orelse {
            return self.createErrorResponse(request.id, RpcError.METHOD_NOT_FOUND, "Method not found");
        };

        // Handle method
        const result = self.handleMethod(method, request.params) catch |err| {
            const error_msg = switch (err) {
                error.InvalidParams => "Invalid parameters",
                error.OutOfMemory => "Out of memory",
                else => "Internal error",
            };
            return self.createErrorResponse(request.id, RpcError.SERVER_ERROR, error_msg);
        };

        return self.createSuccessResponse(request.id, result);
    }

    fn handleMethod(self: *HttpRpcServer, method: RpcMethod, params: ?std.json.Value) !std.json.Value {
        switch (method) {
            .deploy_contract => return self.handleDeployContract(params),
            .call_contract => return self.handleCallContract(params),
            .get_contract_info => return self.handleGetContractInfo(params),
            .get_contract_storage => return self.handleGetContractStorage(params),
            .send_transaction => return self.handleSendTransaction(params),
            .get_transaction => return self.handleGetTransaction(params),
            .get_balance => return self.handleGetBalance(params),
            .get_block_number => return self.handleGetBlockNumber(params),
            .execute_zvm_bytecode => return self.handleExecuteZvmBytecode(params),
            .execute_wasm_module => return self.handleExecuteWasmModule(params),
            .get_vm_statistics => return self.handleGetVmStatistics(params),
            .health_check => return self.handleHealthCheck(params),
            .get_node_info => return self.handleGetNodeInfo(params),
            else => return error.MethodNotImplemented,
        }
    }

    fn handleDeployContract(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        const p = params orelse return error.InvalidParams;
        
        const deploy_params = try std.json.parseFromValue(struct {
            bytecode: []const u8,
            deployer: ?[]const u8 = null,
            value: ?u64 = 0,
            gas_limit: ?u64 = 1000000,
            constructor_args: ?[]const u8 = null,
        }, self.context.allocator, p);
        defer deploy_params.deinit();

        const deployer = if (deploy_params.value.deployer) |d|
            try contract.AddressUtils.from_hex(d)
        else
            contract.AddressUtils.zero();

        // Decode hex bytecode
        const bytecode = try self.decodeHex(deploy_params.value.bytecode);
        defer self.context.allocator.free(bytecode);

        const constructor_args = if (deploy_params.value.constructor_args) |args|
            try self.decodeHex(args)
        else
            &[_]u8{};
        defer if (constructor_args.len > 0) self.context.allocator.free(constructor_args);

        // Deploy contract
        const result = if (self.context.ffi_bridge) |ffi|
            try ffi.deployContract(bytecode, deployer, deploy_params.value.value.?, deploy_params.value.gas_limit.?, constructor_args)
        else
            try self.context.hybrid_runtime.deployContract(bytecode, deployer, deploy_params.value.value.?, deploy_params.value.gas_limit.?);

        return std.json.Value{ .object = std.json.ObjectMap.init(self.context.allocator) };
    }

    fn handleCallContract(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        const p = params orelse return error.InvalidParams;
        
        const call_params = try std.json.parseFromValue(struct {
            contract_address: []const u8,
            caller: ?[]const u8 = null,
            value: ?u64 = 0,
            gas_limit: ?u64 = 100000,
            data: []const u8,
        }, self.context.allocator, p);
        defer call_params.deinit();

        const contract_addr = try contract.AddressUtils.from_hex(call_params.value.contract_address);
        const caller = if (call_params.value.caller) |c|
            try contract.AddressUtils.from_hex(c)
        else
            contract.AddressUtils.zero();

        const data = try self.decodeHex(call_params.value.data);
        defer self.context.allocator.free(data);

        const result = if (self.context.ffi_bridge) |ffi|
            try ffi.callContract(contract_addr, caller, call_params.value.value.?, call_params.value.gas_limit.?, data)
        else
            try self.context.hybrid_runtime.callContract(contract_addr, caller, call_params.value.value.?, data, call_params.value.gas_limit.?);

        var response = std.json.ObjectMap.init(self.context.allocator);
        try response.put("success", std.json.Value{ .bool = result.success });
        try response.put("gas_used", std.json.Value{ .integer = @intCast(result.gas_used) });
        try response.put("return_data", std.json.Value{ .string = try self.encodeHex(result.return_data) });

        return std.json.Value{ .object = response };
    }

    fn handleGetBalance(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        const p = params orelse return error.InvalidParams;
        
        const balance_params = try std.json.parseFromValue(struct {
            address: []const u8,
        }, self.context.allocator, p);
        defer balance_params.deinit();

        const address = try contract.AddressUtils.from_hex(balance_params.value.address);

        const balance = if (self.context.ffi_bridge) |ffi|
            try ffi.getBalance(address)
        else
            runtime.Wallet.get_balance(address);

        return std.json.Value{ .integer = @intCast(balance) };
    }

    fn handleGetBlockNumber(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        _ = params;
        
        const block_number = if (self.context.ffi_bridge) |ffi|
            ffi.getBlockInfo().number
        else
            12345; // Mock block number

        return std.json.Value{ .integer = @intCast(block_number) };
    }

    fn handleExecuteZvmBytecode(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        const p = params orelse return error.InvalidParams;
        
        const exec_params = try std.json.parseFromValue(struct {
            bytecode: []const u8,
            gas_limit: ?u64 = 100000,
        }, self.context.allocator, p);
        defer exec_params.deinit();

        const bytecode = try self.decodeHex(exec_params.value.bytecode);
        defer self.context.allocator.free(bytecode);

        // Execute ZVM bytecode directly
        const deployer = contract.AddressUtils.zero();
        const result = try self.context.hybrid_runtime.deployContract(bytecode, deployer, 0, exec_params.value.gas_limit.?);

        var response = std.json.ObjectMap.init(self.context.allocator);
        try response.put("success", std.json.Value{ .bool = result.success });
        try response.put("gas_used", std.json.Value{ .integer = @intCast(result.gas_used) });

        return std.json.Value{ .object = response };
    }

    fn handleExecuteWasmModule(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        const p = params orelse return error.InvalidParams;
        
        const wasm_params = try std.json.parseFromValue(struct {
            wasm_bytecode: []const u8,
            function_name: ?[]const u8 = "main",
            gas_limit: ?u64 = 100000,
        }, self.context.allocator, p);
        defer wasm_params.deinit();

        const wasm_bytecode = try self.decodeHex(wasm_params.value.wasm_bytecode);
        defer self.context.allocator.free(wasm_bytecode);

        // Execute WASM module
        const deployer = contract.AddressUtils.zero();
        const result = try self.context.hybrid_runtime.deployContract(wasm_bytecode, deployer, 0, wasm_params.value.gas_limit.?);

        var response = std.json.ObjectMap.init(self.context.allocator);
        try response.put("success", std.json.Value{ .bool = result.success });
        try response.put("gas_used", std.json.Value{ .integer = @intCast(result.gas_used) });

        return std.json.Value{ .object = response };
    }

    fn handleGetVmStatistics(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        _ = params;
        
        const stats = self.context.hybrid_runtime.getStatistics();
        const db_stats = try self.context.database.getStatistics();

        var response = std.json.ObjectMap.init(self.context.allocator);
        try response.put("contracts_deployed", std.json.Value{ .integer = @intCast(stats.contracts_deployed) });
        try response.put("wasm_modules_loaded", std.json.Value{ .integer = @intCast(stats.wasm_modules_loaded) });
        try response.put("total_storage_entries", std.json.Value{ .integer = @intCast(db_stats.total_storage_entries) });
        try response.put("requests_handled", std.json.Value{ .integer = @intCast(self.context.requests_handled.load(.acquire)) });
        try response.put("active_connections", std.json.Value{ .integer = @intCast(self.context.active_connections.load(.acquire)) });

        return std.json.Value{ .object = response };
    }

    fn handleHealthCheck(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        _ = params;
        
        var response = std.json.ObjectMap.init(self.context.allocator);
        try response.put("status", std.json.Value{ .string = "healthy" });
        try response.put("uptime", std.json.Value{ .integer = std.time.timestamp() - self.context.start_time });
        try response.put("version", std.json.Value{ .string = "ZVM v0.2.0" });

        return std.json.Value{ .object = response };
    }

    fn handleGetNodeInfo(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        _ = params;
        
        var response = std.json.ObjectMap.init(self.context.allocator);
        try response.put("name", std.json.Value{ .string = "ZVM Hybrid Runtime" });
        try response.put("version", std.json.Value{ .string = "0.2.0" });
        try response.put("protocols", std.json.Value{ .array = std.ArrayList(std.json.Value).init(self.context.allocator) });

        return std.json.Value{ .object = response };
    }

    // Utility functions
    fn handleGetContractInfo(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        _ = self;
        _ = params;
        return std.json.Value{ .object = std.json.ObjectMap.init(self.context.allocator) };
    }

    fn handleGetContractStorage(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        _ = self;
        _ = params;
        return std.json.Value{ .object = std.json.ObjectMap.init(self.context.allocator) };
    }

    fn handleSendTransaction(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        _ = self;
        _ = params;
        return std.json.Value{ .object = std.json.ObjectMap.init(self.context.allocator) };
    }

    fn handleGetTransaction(self: *HttpRpcServer, params: ?std.json.Value) !std.json.Value {
        _ = self;
        _ = params;
        return std.json.Value{ .object = std.json.ObjectMap.init(self.context.allocator) };
    }

    fn decodeHex(self: *HttpRpcServer, hex: []const u8) ![]u8 {
        const start = if (std.mem.startsWith(u8, hex, "0x")) 2 else 0;
        const clean_hex = hex[start..];
        
        if (clean_hex.len % 2 != 0) return error.InvalidHex;
        
        const result = try self.context.allocator.alloc(u8, clean_hex.len / 2);
        for (0..result.len) |i| {
            result[i] = try std.fmt.parseInt(u8, clean_hex[i * 2 .. i * 2 + 2], 16);
        }
        
        return result;
    }

    fn encodeHex(self: *HttpRpcServer, data: []const u8) ![]u8 {
        const result = try self.context.allocator.alloc(u8, 2 + data.len * 2);
        result[0] = '0';
        result[1] = 'x';
        
        for (data, 0..) |byte, i| {
            _ = try std.fmt.bufPrint(result[2 + i * 2 .. 2 + i * 2 + 2], "{x:02}", .{byte});
        }
        
        return result;
    }

    fn createErrorResponse(self: *HttpRpcServer, id: ?std.json.Value, code: i32, message: []const u8) ![]const u8 {
        const error_obj = RpcError{
            .code = code,
            .message = message,
        };
        
        const response = RpcResponse{
            .@"error" = error_obj,
            .id = id,
        };
        
        return try std.json.stringifyAlloc(self.context.allocator, response);
    }

    fn createSuccessResponse(self: *HttpRpcServer, id: ?std.json.Value, result: std.json.Value) ![]const u8 {
        const response = RpcResponse{
            .result = result,
            .id = id,
        };
        
        return try std.json.stringifyAlloc(self.context.allocator, response);
    }

    fn sendResponse(self: *HttpRpcServer, connection: std.http.Server.Connection, response: []const u8) !void {
        _ = self;
        
        const headers = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "access-control-allow-origin", .value = "*" },
            .{ .name = "access-control-allow-methods", .value = "POST, OPTIONS" },
            .{ .name = "access-control-allow-headers", .value = "Content-Type" },
        };

        try connection.writeAll("HTTP/1.1 200 OK\r\n");
        for (headers) |header| {
            try connection.writeAll(header.name);
            try connection.writeAll(": ");
            try connection.writeAll(header.value);
            try connection.writeAll("\r\n");
        }
        try connection.writeAll("content-length: ");
        try connection.writeAll(try std.fmt.allocPrint(connection.allocator, "{d}", .{response.len}));
        try connection.writeAll("\r\n\r\n");
        try connection.writeAll(response);
    }

    fn sendErrorResponse(self: *HttpRpcServer, connection: std.http.Server.Connection, code: i32, message: []const u8) void {
        const error_response = self.createErrorResponse(null, code, message) catch return;
        defer self.context.allocator.free(error_response);
        
        self.sendResponse(connection, error_response) catch {};
    }
};

/// GhostWire RPC Server for high-performance operations
pub const QuicRpcServer = struct {
    context: *RpcContext,
    server: ghostwire.UnifiedServer,
    running: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, context: *RpcContext) !QuicRpcServer {
        const ghostwire_config = ghostwire.UnifiedServerConfig{
            .bind_address = context.config.bind_address,
            .http3_port = context.config.quic_port,
            .max_connections = context.config.max_connections,
            .enable_tls = true,
        };
        
        const server = try ghostwire.createUnifiedServer(allocator, ghostwire_config);

        return QuicRpcServer{
            .context = context,
            .server = server,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *QuicRpcServer) void {
        self.server.deinit();
    }

    pub fn start(self: *QuicRpcServer) !void {
        self.running.store(true, .release);
        std.log.info("ZVM GhostWire RPC server listening on {s}:{d}", .{ self.context.config.bind_address, self.context.config.quic_port });

        // Start the unified server
        try self.server.start();
        
        // Add request handlers
        self.server.addHandler("/rpc", handleRpcRequest);
        
        std.log.info("ZVM GhostWire RPC server started successfully");
    }

    pub fn stop(self: *QuicRpcServer) void {
        self.running.store(false, .release);
        self.server.stop();
    }

    fn handleRpcRequest(request: *ghostwire.UnifiedRequest, response: *ghostwire.UnifiedResponse) anyerror!void {
        _ = request;
        response.setStatus(200);
        response.setHeader("Content-Type", "application/json");
        response.setBody("{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":1}");
    }

};

// Tests
test "RPC method parsing" {
    try std.testing.expect(RpcMethod.fromString("deploy_contract") == .deploy_contract);
    try std.testing.expect(RpcMethod.fromString("invalid_method") == null);
}

test "Hex encoding/decoding" {
    var server = HttpRpcServer{
        .context = undefined,
        .server = undefined,
        .running = std.atomic.Value(bool).init(false),
    };
    
    // Mock context for hex functions
    var context = RpcContext{
        .allocator = std.testing.allocator,
        .config = RpcConfig{},
        .hybrid_runtime = undefined,
        .database = undefined,
        .ffi_bridge = null,
        .quic_client = null,
        .requests_handled = std.atomic.Value(u64).init(0),
        .active_connections = std.atomic.Value(u32).init(0),
        .start_time = 0,
    };
    server.context = &context;

    const original = [_]u8{ 0x12, 0x34, 0xAB, 0xCD };
    const encoded = try server.encodeHex(&original);
    defer std.testing.allocator.free(encoded);

    const decoded = try server.decodeHex(encoded);
    defer std.testing.allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &original, decoded);
}