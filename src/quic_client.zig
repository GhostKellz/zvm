//! QUIC Client for ZVM Integration with ghostd and walletd
//! Provides real ZQUIC transport for blockchain operations
const std = @import("std");
const zquic = @import("zquic");
const contract = @import("contract.zig");

/// QUIC Message Types for GhostChain Protocol
pub const MessageType = enum(u8) {
    // Wallet Operations (0x01-0x0F)
    WALLET_TRANSACTION = 0x01,
    BALANCE_QUERY = 0x02,
    WALLET_CREATE = 0x03,
    WALLET_SIGN = 0x04,
    IDENTITY_VERIFY = 0x05,

    // Contract Operations (0x10-0x1F)
    CONTRACT_DEPLOY = 0x10,
    CONTRACT_CALL = 0x11,
    CONTRACT_QUERY = 0x12,
    CONTRACT_EVENT_STREAM = 0x13,

    // P2P Operations (0x20-0x2F)
    BLOCK_SYNC = 0x20,
    TX_BROADCAST = 0x21,
    PEER_DISCOVERY = 0x22,
    CONSENSUS_MESSAGE = 0x23,

    // System Operations (0x30-0x3F)
    HEALTH_CHECK = 0x30,
    STATUS_QUERY = 0x31,
    METRICS_REQUEST = 0x32,
};

/// QUIC Request/Response structures
pub const QuicRequest = struct {
    message_type: MessageType,
    request_id: u64,
    payload: []const u8,
    timestamp: i64,
};

pub const QuicResponse = struct {
    success: bool,
    request_id: u64,
    payload: []const u8,
    error_message: ?[]const u8,
    timestamp: i64,
};

/// Transaction Request for ghostd
pub const TransactionRequest = struct {
    from: contract.Address,
    to: ?contract.Address,
    value: u64,
    gas_limit: u64,
    gas_price: u64,
    data: []const u8,
    nonce: u64,
};

/// Contract Deployment Request
pub const ContractDeployRequest = struct {
    bytecode: []const u8,
    constructor_args: []const u8,
    gas_limit: u64,
    value: u64,
    deployer: contract.Address,
};

/// Contract Call Request
pub const ContractCallRequest = struct {
    contract_address: contract.Address,
    function_data: []const u8,
    gas_limit: u64,
    caller: contract.Address,
    value: u64,
};

/// QUIC Client for ZVM Integration
pub const QuicClient = struct {
    allocator: std.mem.Allocator,
    zquic_client: zquic.Client,
    ghostd_endpoint: []const u8,
    walletd_endpoint: []const u8,
    connected: bool,

    pub fn init(allocator: std.mem.Allocator, ghostd_endpoint: []const u8, walletd_endpoint: []const u8) !QuicClient {
        const client = try zquic.Client.init(allocator, .{
            .server_name = "ghostchain.local",
            .alpn_protocols = &[_][]const u8{ "ghostchain-v1", "grpc" },
            .max_idle_timeout = 30000,
            .enable_0rtt = true,
        });

        return QuicClient{
            .allocator = allocator,
            .zquic_client = client,
            .ghostd_endpoint = ghostd_endpoint,
            .walletd_endpoint = walletd_endpoint,
            .connected = false,
        };
    }

    pub fn deinit(self: *QuicClient) void {
        self.zquic_client.deinit();
    }

    /// Connect to ghostd and walletd services
    pub fn connect(self: *QuicClient) !void {
        try self.zquic_client.connect(self.ghostd_endpoint);
        std.log.info("Connected to ghostd at {s}", .{self.ghostd_endpoint});

        // Test connection with health check
        const health_result = self.healthCheck(.ghostd) catch |err| {
            std.log.err("Failed to connect to ghostd: {}", .{err});
            return err;
        };

        if (!health_result.success) {
            return error.GhostdConnectionFailed;
        }

        self.connected = true;
        std.log.info("Successfully connected to GhostChain services");
    }

    /// Send QUIC message with automatic retry
    fn sendMessage(self: *QuicClient, endpoint: []const u8, message_type: MessageType, payload: []const u8) !QuicResponse {
        if (!self.connected) {
            try self.connect();
        }

        const request = QuicRequest{
            .message_type = message_type,
            .request_id = @intCast(std.time.timestamp()),
            .payload = payload,
            .timestamp = std.time.timestamp(),
        };

        const request_bytes = try std.json.stringifyAlloc(self.allocator, request);
        defer self.allocator.free(request_bytes);

        // Create QUIC message: [message_type][payload_length][payload]
        const message = try self.allocator.alloc(u8, 1 + 4 + request_bytes.len);
        defer self.allocator.free(message);

        message[0] = @intFromEnum(message_type);
        std.mem.writeInt(u32, message[1..5], @intCast(request_bytes.len), .little);
        @memcpy(message[5..], request_bytes);

        const response_bytes = try self.zquic_client.send(endpoint, message);
        defer self.allocator.free(response_bytes);

        return try std.json.parseFromSlice(QuicResponse, self.allocator, response_bytes);
    }

    /// Deploy contract to ghostd
    pub fn deployContract(self: *QuicClient, request: ContractDeployRequest) !contract.ExecutionResult {
        const payload = try std.json.stringifyAlloc(self.allocator, request);
        defer self.allocator.free(payload);

        const response = try self.sendMessage(self.ghostd_endpoint, .CONTRACT_DEPLOY, payload);

        if (!response.success) {
            return contract.ExecutionResult{
                .success = false,
                .gas_used = 0,
                .return_data = &[_]u8{},
                .error_msg = response.error_message,
                .contract_address = null,
            };
        }

        // Parse contract address from response
        const deploy_result = try std.json.parseFromSlice(struct {
            contract_address: [40]u8, // Hex string
            gas_used: u64,
            transaction_hash: []const u8,
        }, self.allocator, response.payload);

        const contract_addr = try contract.AddressUtils.from_hex(&deploy_result.contract_address);

        return contract.ExecutionResult{
            .success = true,
            .gas_used = deploy_result.gas_used,
            .return_data = &[_]u8{}, // TODO: Return transaction hash
            .error_msg = null,
            .contract_address = contract_addr,
        };
    }

    /// Call contract function via ghostd
    pub fn callContract(self: *QuicClient, request: ContractCallRequest) !contract.ExecutionResult {
        const payload = try std.json.stringifyAlloc(self.allocator, request);
        defer self.allocator.free(payload);

        const response = try self.sendMessage(self.ghostd_endpoint, .CONTRACT_CALL, payload);

        if (!response.success) {
            return contract.ExecutionResult{
                .success = false,
                .gas_used = 0,
                .return_data = &[_]u8{},
                .error_msg = response.error_message,
                .contract_address = request.contract_address,
            };
        }

        const call_result = try std.json.parseFromSlice(struct {
            return_data: []const u8,
            gas_used: u64,
            success: bool,
        }, self.allocator, response.payload);

        return contract.ExecutionResult{
            .success = call_result.success,
            .gas_used = call_result.gas_used,
            .return_data = call_result.return_data,
            .error_msg = null,
            .contract_address = request.contract_address,
        };
    }

    /// Submit transaction to ghostd
    pub fn submitTransaction(self: *QuicClient, request: TransactionRequest) !struct { success: bool, tx_hash: ?[]const u8, gas_used: u64 } {
        const payload = try std.json.stringifyAlloc(self.allocator, request);
        defer self.allocator.free(payload);

        const response = try self.sendMessage(self.ghostd_endpoint, .WALLET_TRANSACTION, payload);

        if (!response.success) {
            return .{ .success = false, .tx_hash = null, .gas_used = 0 };
        }

        const tx_result = try std.json.parseFromSlice(struct {
            transaction_hash: []const u8,
            gas_used: u64,
        }, self.allocator, response.payload);

        return .{ 
            .success = true, 
            .tx_hash = tx_result.transaction_hash, 
            .gas_used = tx_result.gas_used 
        };
    }

    /// Get account balance from ghostd
    pub fn getBalance(self: *QuicClient, address: contract.Address) !u64 {
        const balance_request = struct {
            address: [40]u8, // Hex string
        }{
            .address = contract.AddressUtils.to_hex(address),
        };

        const payload = try std.json.stringifyAlloc(self.allocator, balance_request);
        defer self.allocator.free(payload);

        const response = try self.sendMessage(self.ghostd_endpoint, .BALANCE_QUERY, payload);

        if (!response.success) {
            return error.BalanceQueryFailed;
        }

        const balance_result = try std.json.parseFromSlice(struct {
            balance: u64,
        }, self.allocator, response.payload);

        return balance_result.balance;
    }

    /// Sign transaction with walletd
    pub fn signTransaction(self: *QuicClient, wallet_id: []const u8, transaction_data: []const u8) ![]const u8 {
        const sign_request = struct {
            wallet_id: []const u8,
            data: []const u8,
            use_enhanced_crypto: bool = true,
        }{
            .wallet_id = wallet_id,
            .data = transaction_data,
        };

        const payload = try std.json.stringifyAlloc(self.allocator, sign_request);
        defer self.allocator.free(payload);

        const response = try self.sendMessage(self.walletd_endpoint, .WALLET_SIGN, payload);

        if (!response.success) {
            return error.SigningFailed;
        }

        const sign_result = try std.json.parseFromSlice(struct {
            signature: []const u8,
        }, self.allocator, response.payload);

        return try self.allocator.dupe(u8, sign_result.signature);
    }

    /// Create wallet via walletd
    pub fn createWallet(self: *QuicClient, name: []const u8, account_type: []const u8) !struct { 
        wallet_id: []const u8, 
        address: contract.Address,
        public_key: []const u8 
    } {
        const create_request = struct {
            name: []const u8,
            account_type: []const u8,
            use_zquic: bool = true,
        }{
            .name = name,
            .account_type = account_type,
        };

        const payload = try std.json.stringifyAlloc(self.allocator, create_request);
        defer self.allocator.free(payload);

        const response = try self.sendMessage(self.walletd_endpoint, .WALLET_CREATE, payload);

        if (!response.success) {
            return error.WalletCreationFailed;
        }

        const wallet_result = try std.json.parseFromSlice(struct {
            wallet: struct {
                id: []const u8,
                address: [40]u8, // Hex string
                public_key: []const u8,
            }
        }, self.allocator, response.payload);

        const address = try contract.AddressUtils.from_hex(&wallet_result.wallet.address);

        return .{
            .wallet_id = try self.allocator.dupe(u8, wallet_result.wallet.id),
            .address = address,
            .public_key = try self.allocator.dupe(u8, wallet_result.wallet.public_key),
        };
    }

    /// Health check for services
    pub fn healthCheck(self: *QuicClient, service: enum { ghostd, walletd }) !QuicResponse {
        const endpoint = switch (service) {
            .ghostd => self.ghostd_endpoint,
            .walletd => self.walletd_endpoint,
        };

        const health_payload = "{}";
        return self.sendMessage(endpoint, .HEALTH_CHECK, health_payload);
    }

    /// Stream contract events (returns iterator)
    pub fn streamContractEvents(self: *QuicClient, contract_address: contract.Address) !ContractEventStream {
        const stream_request = struct {
            contract_address: [40]u8,
            stream_type: []const u8 = "events",
        }{
            .contract_address = contract.AddressUtils.to_hex(contract_address),
        };

        const payload = try std.json.stringifyAlloc(self.allocator, stream_request);
        defer self.allocator.free(payload);

        // Create persistent QUIC stream for events
        const stream = try self.zquic_client.openStream(self.ghostd_endpoint);
        
        // Send stream request
        const message = try self.allocator.alloc(u8, 1 + 4 + payload.len);
        defer self.allocator.free(message);

        message[0] = @intFromEnum(MessageType.CONTRACT_EVENT_STREAM);
        std.mem.writeInt(u32, message[1..5], @intCast(payload.len), .little);
        @memcpy(message[5..], payload);

        try stream.write(message);

        return ContractEventStream{
            .allocator = self.allocator,
            .stream = stream,
            .contract_address = contract_address,
        };
    }
};

/// Contract Event Stream for real-time events
pub const ContractEventStream = struct {
    allocator: std.mem.Allocator,
    stream: zquic.Stream,
    contract_address: contract.Address,

    pub const ContractEvent = struct {
        event_name: []const u8,
        data: []const u8,
        topics: [][]const u8,
        block_number: u64,
        transaction_hash: []const u8,
        timestamp: i64,
    };

    pub fn next(self: *ContractEventStream) !?ContractEvent {
        const event_data = self.stream.read() catch |err| {
            if (err == error.StreamClosed) return null;
            return err;
        };
        defer self.allocator.free(event_data);

        return try std.json.parseFromSlice(ContractEvent, self.allocator, event_data);
    }

    pub fn close(self: *ContractEventStream) void {
        self.stream.close();
    }
};

// Tests
test "QUIC client connection" {
    var client = try QuicClient.init(std.testing.allocator, "127.0.0.1:50051", "127.0.0.1:9090");
    defer client.deinit();

    // Test would require actual ghostd/walletd services running
    // For now, just test initialization
    try std.testing.expect(!client.connected);
}

test "Message serialization" {
    const request = QuicRequest{
        .message_type = .CONTRACT_DEPLOY,
        .request_id = 123,
        .payload = "test payload",
        .timestamp = 1640995200,
    };

    const json = try std.json.stringifyAlloc(std.testing.allocator, request);
    defer std.testing.allocator.free(json);

    try std.testing.expect(json.len > 0);
}