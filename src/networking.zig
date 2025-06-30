//! ZVM Networking Module - QUIC-based P2P networking with post-quantum crypto
//! Integrates zquic v0.3.0 and zcrypto v0.5.0 for secure, high-performance networking
const std = @import("std");
const builtin = @import("builtin");

// Import dependencies (these will be available when build.zig is updated)
// const zquic = @import("zquic");
// const zcrypto = @import("zcrypto");

/// Network configuration for ZVM
pub const NetworkConfig = struct {
    /// Local bind address for the node
    bind_address: []const u8 = "127.0.0.1",
    /// Local bind port
    bind_port: u16 = 8443,
    /// Maximum number of concurrent connections
    max_connections: u32 = 1000,
    /// Connection timeout in milliseconds
    connection_timeout_ms: u32 = 30000,
    /// Enable post-quantum key exchange
    enable_pq_crypto: bool = true,
    /// Enable peer discovery
    enable_discovery: bool = true,
    /// Bootstrap peers for initial connection
    bootstrap_peers: []const []const u8 = &[_][]const u8{},
};

/// Network peer information
pub const PeerInfo = struct {
    /// Peer ID (derived from public key)
    id: [32]u8,
    /// Peer address
    address: []const u8,
    /// Peer port
    port: u16,
    /// Connection state
    state: ConnectionState,
    /// Last seen timestamp
    last_seen: i64,
    /// Peer capabilities
    capabilities: PeerCapabilities,

    pub const ConnectionState = enum {
        disconnected,
        connecting,
        connected,
        failed,
    };

    pub const PeerCapabilities = packed struct {
        supports_zvm: bool = true,
        supports_evm: bool = true,
        supports_wasm: bool = true,
        supports_contracts: bool = true,
        supports_discovery: bool = true,
        _reserved: u3 = 0,
    };
};

/// Network message types for ZVM protocol
pub const MessageType = enum(u8) {
    // Handshake messages
    handshake_init = 0x01,
    handshake_response = 0x02,
    handshake_complete = 0x03,

    // Discovery messages
    peer_discovery = 0x10,
    peer_announcement = 0x11,
    peer_list_request = 0x12,
    peer_list_response = 0x13,

    // Contract messages
    contract_deploy = 0x20,
    contract_call = 0x21,
    contract_result = 0x22,
    contract_event = 0x23,

    // Blockchain messages
    block_announcement = 0x30,
    block_request = 0x31,
    block_response = 0x32,
    transaction_broadcast = 0x33,

    // RPC messages
    rpc_request = 0x40,
    rpc_response = 0x41,
    rpc_error = 0x42,

    // Administrative
    ping = 0xF0,
    pong = 0xF1,
    disconnect = 0xFF,
};

/// Network message structure
pub const NetworkMessage = struct {
    /// Message type
    message_type: MessageType,
    /// Sender peer ID
    sender: [32]u8,
    /// Recipient peer ID (all zeros for broadcast)
    recipient: [32]u8,
    /// Message payload
    payload: []const u8,
    /// Message timestamp
    timestamp: i64,
    /// Message signature (post-quantum)
    signature: ?[]const u8 = null,

    /// Serialize message to bytes
    pub fn serialize(self: *const NetworkMessage, allocator: std.mem.Allocator) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        try buffer.append(@intFromEnum(self.message_type));
        try buffer.appendSlice(&self.sender);
        try buffer.appendSlice(&self.recipient);

        // Write timestamp (8 bytes, little endian)
        var timestamp_bytes: [8]u8 = undefined;
        std.mem.writeInt(i64, &timestamp_bytes, self.timestamp, .little);
        try buffer.appendSlice(&timestamp_bytes);

        // Write payload length (4 bytes, little endian)
        var payload_len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload_len_bytes, @intCast(self.payload.len), .little);
        try buffer.appendSlice(&payload_len_bytes);

        // Write payload
        try buffer.appendSlice(self.payload);

        // Write signature if present
        if (self.signature) |sig| {
            var sig_len_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &sig_len_bytes, @intCast(sig.len), .little);
            try buffer.appendSlice(&sig_len_bytes);
            try buffer.appendSlice(sig);
        } else {
            try buffer.appendSlice(&[_]u8{ 0, 0, 0, 0 });
        }

        return buffer.toOwnedSlice();
    }

    /// Deserialize message from bytes
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !NetworkMessage {
        if (data.len < 1 + 32 + 32 + 8 + 4) return error.InvalidMessage;

        var offset: usize = 0;

        const message_type: MessageType = @enumFromInt(data[offset]);
        offset += 1;

        const sender = data[offset .. offset + 32].*;
        offset += 32;

        const recipient = data[offset .. offset + 32].*;
        offset += 32;

        const timestamp = std.mem.readInt(i64, data[offset .. offset + 8], .little);
        offset += 8;

        const payload_len = std.mem.readInt(u32, data[offset .. offset + 4], .little);
        offset += 4;

        if (offset + payload_len > data.len) return error.InvalidMessage;

        const payload = try allocator.dupe(u8, data[offset .. offset + payload_len]);
        offset += payload_len;

        var signature: ?[]u8 = null;
        if (offset + 4 <= data.len) {
            const sig_len = std.mem.readInt(u32, data[offset .. offset + 4], .little);
            offset += 4;

            if (sig_len > 0 and offset + sig_len <= data.len) {
                signature = try allocator.dupe(u8, data[offset .. offset + sig_len]);
            }
        }

        return NetworkMessage{
            .message_type = message_type,
            .sender = sender,
            .recipient = recipient,
            .payload = payload,
            .timestamp = timestamp,
            .signature = signature,
        };
    }
};

/// Contract deployment message payload
pub const ContractDeployPayload = struct {
    /// Contract bytecode
    bytecode: []const u8,
    /// Bytecode format (ZVM, EVM, or WASM)
    format: BytecodeFormat,
    /// Constructor arguments
    constructor_args: []const u8,
    /// Gas limit for deployment
    gas_limit: u64,
    /// Contract metadata
    metadata: ContractMetadata,

    pub const BytecodeFormat = enum(u8) {
        zvm = 0x01,
        evm = 0x02,
        wasm = 0x03,
    };

    pub const ContractMetadata = struct {
        name: []const u8,
        version: []const u8,
        description: []const u8,
        author: []const u8,
    };
};

/// Contract call message payload
pub const ContractCallPayload = struct {
    /// Contract address
    contract_address: [20]u8,
    /// Function selector
    function_selector: [4]u8,
    /// Function arguments
    args: []const u8,
    /// Gas limit for execution
    gas_limit: u64,
    /// Value sent with call
    value: u64,
};

/// Network error types
pub const NetworkError = error{
    ConnectionFailed,
    InvalidMessage,
    PeerNotFound,
    HandshakeFailed,
    CryptoError,
    OutOfMemory,
    Timeout,
    InvalidAddress,
    MaxConnectionsReached,
};

/// ZVM Network Node - Main networking component
pub const NetworkNode = struct {
    allocator: std.mem.Allocator,
    config: NetworkConfig,
    local_peer_id: [32]u8,
    // quic_server: ?zquic.QuicServer,
    // crypto_context: zcrypto.CryptoContext,
    peers: std.HashMap([32]u8, PeerInfo, std.hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage),
    message_handlers: std.HashMap(MessageType, MessageHandler, std.hash_map.AutoContext(MessageType), std.hash_map.default_max_load_percentage),
    running: bool,

    const MessageHandler = *const fn (node: *NetworkNode, message: NetworkMessage) anyerror!void;

    /// Initialize network node
    pub fn init(allocator: std.mem.Allocator, config: NetworkConfig) !NetworkNode {
        // Generate local peer ID from random bytes for now
        // In production, this would be derived from a persistent keypair
        var local_peer_id: [32]u8 = undefined;
        std.crypto.random.bytes(&local_peer_id);

        var node = NetworkNode{
            .allocator = allocator,
            .config = config,
            .local_peer_id = local_peer_id,
            // .quic_server = null,
            // .crypto_context = undefined,
            .peers = std.HashMap([32]u8, PeerInfo, std.hash_map.HashMap([32]u8, PeerInfo).KeyContext, std.hash_map.default_max_load_percentage).init(allocator),
            .message_handlers = std.HashMap(MessageType, MessageHandler, std.hash_map.AutoContext(MessageType), std.hash_map.default_max_load_percentage).init(allocator),
            .running = false,
        };

        // Register default message handlers
        try node.registerDefaultHandlers();

        return node;
    }

    /// Deinitialize network node
    pub fn deinit(self: *NetworkNode) void {
        self.stop();
        self.peers.deinit();
        self.message_handlers.deinit();
    }

    /// Start the network node
    pub fn start(self: *NetworkNode) !void {
        if (self.running) return;

        std.debug.print("Starting ZVM Network Node...\n", .{});
        std.debug.print("Local Peer ID: {x}\n", .{std.fmt.fmtSliceHexLower(&self.local_peer_id)});
        std.debug.print("Bind Address: {s}:{d}\n", .{ self.config.bind_address, self.config.bind_port });

        // TODO: Initialize QUIC server with zcrypto integration
        // self.quic_server = try zquic.QuicServer.init(self.allocator, .{
        //     .bind_address = self.config.bind_address,
        //     .bind_port = self.config.bind_port,
        //     .max_connections = self.config.max_connections,
        //     .enable_pq_crypto = self.config.enable_pq_crypto,
        // });

        self.running = true;

        // Connect to bootstrap peers
        if (self.config.bootstrap_peers.len > 0) {
            try self.connectToBootstrapPeers();
        }

        std.debug.print("ZVM Network Node started successfully\n", .{});
    }

    /// Stop the network node
    pub fn stop(self: *NetworkNode) void {
        if (!self.running) return;

        std.debug.print("Stopping ZVM Network Node...\n", .{});

        self.running = false;

        // TODO: Close QUIC server
        // if (self.quic_server) |*server| {
        //     server.deinit();
        //     self.quic_server = null;
        // }

        std.debug.print("ZVM Network Node stopped\n", .{});
    }

    /// Register a message handler
    pub fn registerMessageHandler(self: *NetworkNode, message_type: MessageType, handler: MessageHandler) !void {
        try self.message_handlers.put(message_type, handler);
    }

    /// Send a message to a specific peer
    pub fn sendMessage(self: *NetworkNode, peer_id: [32]u8, message: NetworkMessage) !void {
        const peer = self.peers.get(peer_id) orelse return NetworkError.PeerNotFound;

        // TODO: Serialize message and send via QUIC
        _ = peer;

        std.debug.print("Sending message type {} to peer {x}\n", .{ message.message_type, std.fmt.fmtSliceHexLower(&peer_id) });
    }

    /// Broadcast a message to all connected peers
    pub fn broadcastMessage(self: *NetworkNode, message: NetworkMessage) !void {
        var iterator = self.peers.iterator();
        while (iterator.next()) |entry| {
            const peer_id = entry.key_ptr.*;
            try self.sendMessage(peer_id, message);
        }
    }

    /// Deploy a contract to the network
    pub fn deployContract(self: *NetworkNode, bytecode: []const u8, format: ContractDeployPayload.BytecodeFormat, metadata: ContractDeployPayload.ContractMetadata) !void {
        const payload = ContractDeployPayload{
            .bytecode = bytecode,
            .format = format,
            .constructor_args = &[_]u8{},
            .gas_limit = 1000000,
            .metadata = metadata,
        };

        // TODO: Serialize payload
        _ = payload;

        const message = NetworkMessage{
            .message_type = .contract_deploy,
            .sender = self.local_peer_id,
            .recipient = [_]u8{0} ** 32, // Broadcast
            .payload = &[_]u8{}, // TODO: Serialized payload
            .timestamp = std.time.timestamp(),
        };

        try self.broadcastMessage(message);
        std.debug.print("Contract deployment broadcasted to network\n", .{});
    }

    /// Call a contract function
    pub fn callContract(self: *NetworkNode, contract_address: [20]u8, function_selector: [4]u8, args: []const u8, gas_limit: u64) !void {
        const payload = ContractCallPayload{
            .contract_address = contract_address,
            .function_selector = function_selector,
            .args = args,
            .gas_limit = gas_limit,
            .value = 0,
        };

        // TODO: Serialize payload
        _ = payload;

        const message = NetworkMessage{
            .message_type = .contract_call,
            .sender = self.local_peer_id,
            .recipient = [_]u8{0} ** 32, // Broadcast
            .payload = &[_]u8{}, // TODO: Serialized payload
            .timestamp = std.time.timestamp(),
        };

        try self.broadcastMessage(message);
        std.debug.print("Contract call broadcasted to network\n", .{});
    }

    /// Get connected peers
    pub fn getConnectedPeers(self: *NetworkNode) []const PeerInfo {
        // TODO: Return actual peer list
        _ = self;
        return &[_]PeerInfo{};
    }

    /// Connect to bootstrap peers
    fn connectToBootstrapPeers(self: *NetworkNode) !void {
        for (self.config.bootstrap_peers) |peer_addr| {
            std.debug.print("Connecting to bootstrap peer: {s}\n", .{peer_addr});
            // TODO: Parse address and connect via QUIC
        }
    }

    /// Register default message handlers
    fn registerDefaultHandlers(self: *NetworkNode) !void {
        try self.registerMessageHandler(.ping, handlePing);
        try self.registerMessageHandler(.pong, handlePong);
        try self.registerMessageHandler(.peer_discovery, handlePeerDiscovery);
        try self.registerMessageHandler(.contract_deploy, handleContractDeploy);
        try self.registerMessageHandler(.contract_call, handleContractCall);
    }

    /// Handle ping message
    fn handlePing(node: *NetworkNode, message: NetworkMessage) !void {
        std.debug.print("Received ping from {x}\n", .{std.fmt.fmtSliceHexLower(&message.sender)});

        const pong_message = NetworkMessage{
            .message_type = .pong,
            .sender = node.local_peer_id,
            .recipient = message.sender,
            .payload = &[_]u8{},
            .timestamp = std.time.timestamp(),
        };

        try node.sendMessage(message.sender, pong_message);
    }

    /// Handle pong message
    fn handlePong(node: *NetworkNode, message: NetworkMessage) !void {
        _ = node;
        std.debug.print("Received pong from {x}\n", .{std.fmt.fmtSliceHexLower(&message.sender)});
    }

    /// Handle peer discovery message
    fn handlePeerDiscovery(node: *NetworkNode, message: NetworkMessage) !void {
        _ = node;
        std.debug.print("Received peer discovery from {x}\n", .{std.fmt.fmtSliceHexLower(&message.sender)});
        // TODO: Process peer discovery and respond with peer list
    }

    /// Handle contract deployment message
    fn handleContractDeploy(node: *NetworkNode, message: NetworkMessage) !void {
        _ = node;
        std.debug.print("Received contract deployment from {x}\n", .{std.fmt.fmtSliceHexLower(&message.sender)});
        // TODO: Validate and process contract deployment
    }

    /// Handle contract call message
    fn handleContractCall(node: *NetworkNode, message: NetworkMessage) !void {
        _ = node;
        std.debug.print("Received contract call from {x}\n", .{std.fmt.fmtSliceHexLower(&message.sender)});
        // TODO: Execute contract call and return result
    }
};

/// RPC Server for external API access
pub const RPCServer = struct {
    allocator: std.mem.Allocator,
    network_node: *NetworkNode,
    // quic_server: ?zquic.QuicServer,
    running: bool,

    /// Initialize RPC server
    pub fn init(allocator: std.mem.Allocator, network_node: *NetworkNode) RPCServer {
        return RPCServer{
            .allocator = allocator,
            .network_node = network_node,
            // .quic_server = null,
            .running = false,
        };
    }

    /// Start RPC server
    pub fn start(self: *RPCServer, bind_address: []const u8, bind_port: u16) !void {
        if (self.running) return;

        std.debug.print("Starting ZVM RPC Server on {s}:{d}\n", .{ bind_address, bind_port });

        // TODO: Initialize QUIC server for RPC
        // self.quic_server = try zquic.QuicServer.init(self.allocator, .{
        //     .bind_address = bind_address,
        //     .bind_port = bind_port,
        //     .max_connections = 100,
        //     .enable_pq_crypto = true,
        // });

        self.running = true;
        std.debug.print("ZVM RPC Server started successfully\n", .{});
    }

    /// Stop RPC server
    pub fn stop(self: *RPCServer) void {
        if (!self.running) return;

        self.running = false;

        // TODO: Close QUIC server
        // if (self.quic_server) |*server| {
        //     server.deinit();
        //     self.quic_server = null;
        // }

        std.debug.print("ZVM RPC Server stopped\n", .{});
    }

    /// Deinitialize RPC server
    pub fn deinit(self: *RPCServer) void {
        self.stop();
    }
};

// Tests
test "network message serialization" {
    const allocator = std.testing.allocator;

    const message = NetworkMessage{
        .message_type = .ping,
        .sender = [_]u8{1} ** 32,
        .recipient = [_]u8{2} ** 32,
        .payload = "Hello, ZVM!",
        .timestamp = 1234567890,
    };

    const serialized = try message.serialize(allocator);
    defer allocator.free(serialized);

    const deserialized = try NetworkMessage.deserialize(allocator, serialized);
    defer {
        allocator.free(deserialized.payload);
        if (deserialized.signature) |sig| allocator.free(sig);
    }

    try std.testing.expect(deserialized.message_type == .ping);
    try std.testing.expectEqualSlices(u8, &message.sender, &deserialized.sender);
    try std.testing.expectEqualSlices(u8, &message.recipient, &deserialized.recipient);
    try std.testing.expectEqualSlices(u8, message.payload, deserialized.payload);
    try std.testing.expect(deserialized.timestamp == 1234567890);
}

test "network node initialization" {
    const allocator = std.testing.allocator;

    const config = NetworkConfig{
        .bind_address = "127.0.0.1",
        .bind_port = 8443,
        .max_connections = 100,
    };

    var node = try NetworkNode.init(allocator, config);
    defer node.deinit();

    try std.testing.expect(!node.running);
    try std.testing.expect(node.peers.count() == 0);
}
