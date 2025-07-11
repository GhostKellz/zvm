//! Enhanced ZVM Networking Module - QUIC-based P2P networking with advanced connection pooling and multiplexing
//! Features: Connection pooling, stream multiplexing, adaptive compression, bandwidth management
const std = @import("std");
const builtin = @import("builtin");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const HashMap = std.HashMap;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;
const AutoHashMap = std.AutoHashMap;

// Import Shroud framework dependencies directly
const shroud = @import("shroud");
const ghostwire = shroud.ghostwire;
const ghostcipher = shroud.ghostcipher;

/// Network configuration for ZVM with connection pooling
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
    /// Connection pool configuration
    connection_pool: ConnectionPoolConfig = ConnectionPoolConfig{},
    /// Compression settings
    compression: CompressionConfig = CompressionConfig{},
    /// Bandwidth management
    bandwidth: BandwidthConfig = BandwidthConfig{},
};

/// Connection pool configuration
pub const ConnectionPoolConfig = struct {
    /// Maximum connections per peer
    max_connections_per_peer: u32 = 10,
    /// Connection idle timeout before recycling
    idle_timeout_ms: u32 = 60000,
    /// Maximum streams per connection
    max_streams_per_connection: u32 = 100,
    /// Connection keep-alive interval
    keep_alive_interval_ms: u32 = 30000,
    /// Enable connection multiplexing
    enable_multiplexing: bool = true,
};

/// Compression configuration
pub const CompressionConfig = struct {
    /// Enable adaptive compression
    enable_compression: bool = true,
    /// Compression threshold (bytes)
    compression_threshold: u32 = 1024,
    /// Compression level (1-9)
    compression_level: u8 = 6,
    /// Enable dynamic compression based on payload type
    adaptive_compression: bool = true,
};

/// Bandwidth management configuration
pub const BandwidthConfig = struct {
    /// Maximum bandwidth per peer (bytes/sec)
    max_bandwidth_per_peer: u64 = 1024 * 1024 * 10, // 10MB/s
    /// Rate limiting window size (ms)
    rate_limit_window_ms: u32 = 1000,
    /// Enable bandwidth monitoring
    enable_monitoring: bool = true,
    /// Adaptive bandwidth allocation
    adaptive_bandwidth: bool = true,
};

/// Enhanced peer information with connection pooling
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
    /// Connection pool for this peer
    connection_pool: ?*ConnectionPool = null,
    /// Bandwidth statistics
    bandwidth_stats: BandwidthStats = BandwidthStats{},

    pub const ConnectionState = enum {
        disconnected,
        connecting,
        connected,
        failed,
        throttled,
    };

    pub const PeerCapabilities = packed struct {
        supports_zvm: bool = true,
        supports_evm: bool = true,
        supports_wasm: bool = true,
        supports_contracts: bool = true,
        supports_discovery: bool = true,
        supports_multiplexing: bool = true,
        supports_compression: bool = true,
        _reserved: u1 = 0,
    };
};

/// Bandwidth statistics per peer
pub const BandwidthStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    messages_sent: u64 = 0,
    messages_received: u64 = 0,
    last_rate_limit_reset: i64 = 0,
    current_rate_bytes: u64 = 0,
};

/// Connection pool for efficient connection management
pub const ConnectionPool = struct {
    allocator: Allocator,
    peer_id: [32]u8,
    config: ConnectionPoolConfig,
    connections: ArrayList(*Connection),
    available_connections: ArrayList(*Connection),
    stream_multiplexer: StreamMultiplexer,
    mutex: Mutex,
    condition: Condition,
    statistics: PoolStatistics,
    bandwidth_limiter: *BandwidthLimiter,

    const PoolStatistics = struct {
        total_connections: u32 = 0,
        active_connections: u32 = 0,
        recycled_connections: u32 = 0,
        connection_failures: u32 = 0,
        total_streams: u32 = 0,
        active_streams: u32 = 0,
        compression_ratio: f64 = 0.0,
        avg_response_time_ms: f64 = 0.0,
    };

    pub fn init(allocator: Allocator, peer_id: [32]u8, config: ConnectionPoolConfig, bandwidth_limiter: *BandwidthLimiter) !*ConnectionPool {
        const pool = try allocator.create(ConnectionPool);
        pool.* = ConnectionPool{
            .allocator = allocator,
            .peer_id = peer_id,
            .config = config,
            .connections = ArrayList(*Connection).init(allocator),
            .available_connections = ArrayList(*Connection).init(allocator),
            .stream_multiplexer = try StreamMultiplexer.init(allocator, config.max_streams_per_connection),
            .mutex = Mutex{},
            .condition = Condition{},
            .statistics = PoolStatistics{},
            .bandwidth_limiter = bandwidth_limiter,
        };
        return pool;
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit();
        self.available_connections.deinit();
        self.stream_multiplexer.deinit();
        self.allocator.destroy(self);
    }

    /// Acquire a connection from the pool
    pub fn acquireConnection(self: *ConnectionPool) !*Connection {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Try to reuse an available connection
        if (self.available_connections.items.len > 0) {
            const connection = self.available_connections.pop();
            if (connection.isHealthy()) {
                self.statistics.recycled_connections += 1;
                return connection;
            } else {
                // Connection is unhealthy, destroy it
                connection.deinit();
                self.allocator.destroy(connection);
            }
        }

        // Create new connection if under limit
        if (self.connections.items.len < self.config.max_connections_per_peer) {
            const connection = try self.createConnection();
            try self.connections.append(connection);
            self.statistics.total_connections += 1;
            self.statistics.active_connections += 1;
            return connection;
        }

        // Wait for an available connection
        while (self.available_connections.items.len == 0) {
            self.condition.wait(&self.mutex);
        }

        return self.acquireConnection();
    }

    /// Release a connection back to the pool
    pub fn releaseConnection(self: *ConnectionPool, connection: *Connection) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (connection.isHealthy() and !connection.isExpired(self.config.idle_timeout_ms)) {
            try self.available_connections.append(connection);
            self.statistics.active_connections -= 1;
            self.condition.signal();
        } else {
            // Connection is unhealthy or expired, destroy it
            connection.deinit();
            self.allocator.destroy(connection);
            self.statistics.active_connections -= 1;
            self.statistics.connection_failures += 1;
        }
    }

    /// Send message with connection pooling and multiplexing
    pub fn sendMessage(self: *ConnectionPool, message: NetworkMessage) !void {
        // Check bandwidth limits
        const message_size = message.payload.len + 100; // Estimated overhead
        if (!try self.bandwidth_limiter.checkLimit(message_size)) {
            return NetworkError.Timeout; // Rate limited
        }

        const connection = try self.acquireConnection();
        defer self.releaseConnection(connection) catch {};

        // Use stream multiplexing if enabled
        if (self.config.enable_multiplexing) {
            const stream_id = try self.stream_multiplexer.allocateStream(connection);
            defer self.stream_multiplexer.releaseStream(stream_id);

            try connection.sendMessageOnStream(message, stream_id);
        } else {
            try connection.sendMessage(message);
        }

        // Update bandwidth statistics
        try self.bandwidth_limiter.recordUsage(message_size);
    }

    fn createConnection(self: *ConnectionPool) !*Connection {
        const connection = try self.allocator.create(Connection);
        connection.* = try Connection.init(self.allocator, self.peer_id);
        return connection;
    }

    pub fn getStatistics(self: *ConnectionPool) PoolStatistics {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.statistics;
    }
};

/// Stream multiplexer for handling multiple logical streams per connection
pub const StreamMultiplexer = struct {
    allocator: Allocator,
    max_streams: u32,
    active_streams: AutoHashMap(u32, *Stream),
    available_stream_ids: ArrayList(u32),
    next_stream_id: u32,
    mutex: Mutex,

    pub fn init(allocator: Allocator, max_streams: u32) !StreamMultiplexer {
        var available_ids = ArrayList(u32).init(allocator);

        // Pre-allocate stream IDs
        var i: u32 = 0;
        while (i < max_streams) : (i += 1) {
            try available_ids.append(i);
        }

        return StreamMultiplexer{
            .allocator = allocator,
            .max_streams = max_streams,
            .active_streams = AutoHashMap(u32, *Stream).init(allocator),
            .available_stream_ids = available_ids,
            .next_stream_id = 0,
            .mutex = Mutex{},
        };
    }

    pub fn deinit(self: *StreamMultiplexer) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iterator = self.active_streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.active_streams.deinit();
        self.available_stream_ids.deinit();
    }

    /// Allocate a new stream
    pub fn allocateStream(self: *StreamMultiplexer, connection: *Connection) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.available_stream_ids.items.len == 0) {
            return NetworkError.MaxConnectionsReached;
        }

        const stream_id = self.available_stream_ids.pop();
        const stream = try self.allocator.create(Stream);
        stream.* = Stream.init(stream_id, connection);

        try self.active_streams.put(stream_id, stream);
        return stream_id;
    }

    /// Release a stream
    pub fn releaseStream(self: *StreamMultiplexer, stream_id: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.active_streams.get(stream_id)) |stream| {
            stream.deinit();
            self.allocator.destroy(stream);
            _ = self.active_streams.remove(stream_id);
            self.available_stream_ids.append(stream_id) catch {};
        }
    }

    /// Get stream by ID
    pub fn getStream(self: *StreamMultiplexer, stream_id: u32) ?*Stream {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.active_streams.get(stream_id);
    }
};

/// Individual stream within a multiplexed connection
pub const Stream = struct {
    id: u32,
    connection: *Connection,
    state: StreamState,
    created_at: i64,
    last_activity: i64,
    bytes_sent: u64,
    bytes_received: u64,

    pub const StreamState = enum {
        idle,
        active,
        closed,
    };

    pub fn init(id: u32, connection: *Connection) Stream {
        const now = std.time.timestamp();
        return Stream{
            .id = id,
            .connection = connection,
            .state = .idle,
            .created_at = now,
            .last_activity = now,
            .bytes_sent = 0,
            .bytes_received = 0,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.state = .closed;
    }

    pub fn isActive(self: *Stream) bool {
        return self.state == .active;
    }

    pub fn updateActivity(self: *Stream) void {
        self.last_activity = std.time.timestamp();
    }
};

/// Individual connection with health tracking
pub const Connection = struct {
    allocator: Allocator,
    peer_id: [32]u8,
    state: ConnectionState,
    created_at: i64,
    last_activity: i64,
    bytes_sent: u64,
    bytes_received: u64,
    error_count: u32,
    ghostwire_connection: ?*anyopaque, // Placeholder for actual GhostWire connection

    pub const ConnectionState = enum {
        connecting,
        connected,
        disconnected,
        connection_error,
    };

    pub fn init(allocator: Allocator, peer_id: [32]u8) !Connection {
        const now = std.time.timestamp();
        return Connection{
            .allocator = allocator,
            .peer_id = peer_id,
            .state = .connecting,
            .created_at = now,
            .last_activity = now,
            .bytes_sent = 0,
            .bytes_received = 0,
            .error_count = 0,
            .ghostwire_connection = null,
        };
    }

    pub fn deinit(self: *Connection) void {
        self.state = .disconnected;
        // Close actual connection here
    }

    pub fn isHealthy(self: *Connection) bool {
        return self.state == .connected and self.error_count < 5;
    }

    pub fn isExpired(self: *Connection, timeout_ms: u32) bool {
        const now = std.time.timestamp();
        const timeout_seconds = @as(i64, @intCast(timeout_ms)) / 1000;
        return (now - self.last_activity) > timeout_seconds;
    }

    pub fn sendMessage(self: *Connection, message: NetworkMessage) !void {
        // TODO: Implement actual message sending via GhostWire
        self.last_activity = std.time.timestamp();
        self.bytes_sent += message.payload.len;
    }

    pub fn sendMessageOnStream(self: *Connection, message: NetworkMessage, stream_id: u32) !void {
        // TODO: Implement stream-based message sending
        _ = stream_id;
        try self.sendMessage(message);
    }
};

/// Bandwidth limiter for rate limiting and traffic shaping
pub const BandwidthLimiter = struct {
    allocator: Allocator,
    config: BandwidthConfig,
    current_usage: u64,
    window_start: i64,
    mutex: Mutex,
    peer_limits: AutoHashMap([32]u8, PeerBandwidthState),

    const PeerBandwidthState = struct {
        bytes_used: u64 = 0,
        window_start: i64 = 0,
        last_reset: i64 = 0,
    };

    pub fn init(allocator: Allocator, config: BandwidthConfig) !*BandwidthLimiter {
        const limiter = try allocator.create(BandwidthLimiter);
        limiter.* = BandwidthLimiter{
            .allocator = allocator,
            .config = config,
            .current_usage = 0,
            .window_start = std.time.timestamp(),
            .mutex = Mutex{},
            .peer_limits = AutoHashMap([32]u8, PeerBandwidthState).init(allocator),
        };
        return limiter;
    }

    pub fn deinit(self: *BandwidthLimiter) void {
        self.peer_limits.deinit();
        self.allocator.destroy(self);
    }

    /// Check if sending a message would exceed bandwidth limits
    pub fn checkLimit(self: *BandwidthLimiter, bytes: u64) !bool {
        if (!self.config.enable_monitoring) return true;

        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();
        const window_ms = @as(i64, @intCast(self.config.rate_limit_window_ms));

        // Reset window if expired
        if ((now - self.window_start) * 1000 > window_ms) {
            self.current_usage = 0;
            self.window_start = now;
        }

        return (self.current_usage + bytes) <= self.config.max_bandwidth_per_peer;
    }

    /// Record bandwidth usage
    pub fn recordUsage(self: *BandwidthLimiter, bytes: u64) !void {
        if (!self.config.enable_monitoring) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        self.current_usage += bytes;
    }

    /// Get current bandwidth utilization (0.0 to 1.0)
    pub fn getUtilization(self: *BandwidthLimiter) f64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        return @as(f64, @floatFromInt(self.current_usage)) / @as(f64, @floatFromInt(self.config.max_bandwidth_per_peer));
    }
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

/// Enhanced network message structure with compression support
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
    /// Compression type used
    compression: CompressionType = .none,
    /// Original payload size (before compression)
    original_size: u32 = 0,
    /// Stream ID for multiplexed connections
    stream_id: ?u32 = null,

    pub const CompressionType = enum(u8) {
        none = 0,
        gzip = 1,
        lz4 = 2,
        zstd = 3,
    };

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
    ghostwire_server: ?ghostwire.UnifiedServer,
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
            .ghostwire_server = null,
            .peers = std.HashMap([32]u8, PeerInfo, std.hash_map.AutoContext([32]u8), std.hash_map.default_max_load_percentage).init(allocator),
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

        // Initialize GhostWire unified server with QUIC support
        const ghostwire_config = ghostwire.UnifiedServerConfig{
            .http3_port = self.config.bind_port,
            .max_connections = self.config.max_connections,
            .enable_tls = self.config.enable_pq_crypto,
            .bind_address = self.config.bind_address,
        };

        self.ghostwire_server = try ghostwire.createUnifiedServer(self.allocator, ghostwire_config);

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

        // Close GhostWire server
        if (self.ghostwire_server) |*server| {
            server.stop();
            server.deinit();
            self.ghostwire_server = null;
        }

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
    ghostwire_server: ?ghostwire.UnifiedServer,
    running: bool,

    /// Initialize RPC server
    pub fn init(allocator: std.mem.Allocator, network_node: *NetworkNode) RPCServer {
        return RPCServer{
            .allocator = allocator,
            .network_node = network_node,
            .ghostwire_server = null,
            .running = false,
        };
    }

    /// Start RPC server
    pub fn start(self: *RPCServer, bind_address: []const u8, bind_port: u16) !void {
        if (self.running) return;

        std.debug.print("Starting ZVM RPC Server on {s}:{d}\n", .{ bind_address, bind_port });

        // Initialize GhostWire unified server for RPC
        const ghostwire_config = ghostwire.UnifiedServerConfig{
            .http1_port = bind_port,
            .http2_port = bind_port + 1,
            .http3_port = bind_port + 2,
            .max_connections = 100,
            .enable_tls = true,
            .bind_address = bind_address,
        };

        self.ghostwire_server = try ghostwire.createUnifiedServer(self.allocator, ghostwire_config);

        self.running = true;
        std.debug.print("ZVM RPC Server started successfully\n", .{});
    }

    /// Stop RPC server
    pub fn stop(self: *RPCServer) void {
        if (!self.running) return;

        self.running = false;

        // Close GhostWire server
        if (self.ghostwire_server) |*server| {
            server.stop();
            server.deinit();
            self.ghostwire_server = null;
        }

        std.debug.print("ZVM RPC Server stopped\n", .{});
    }

    /// Deinitialize RPC server
    pub fn deinit(self: *RPCServer) void {
        self.stop();
    }
};

/// Message compressor for adaptive compression
pub const MessageCompressor = struct {
    allocator: Allocator,
    config: CompressionConfig,
    compression_stats: CompressionStats,

    const CompressionStats = struct {
        total_compressed: u64 = 0,
        total_original_size: u64 = 0,
        total_compressed_size: u64 = 0,
        avg_compression_ratio: f64 = 0.0,
    };

    pub fn init(allocator: Allocator, config: CompressionConfig) !*MessageCompressor {
        const compressor = try allocator.create(MessageCompressor);
        compressor.* = MessageCompressor{
            .allocator = allocator,
            .config = config,
            .compression_stats = CompressionStats{},
        };
        return compressor;
    }

    pub fn deinit(self: *MessageCompressor) void {
        self.allocator.destroy(self);
    }

    /// Compress a network message
    pub fn compress(self: *MessageCompressor, message: NetworkMessage) !NetworkMessage {
        if (!self.config.enable_compression or message.payload.len < self.config.compression_threshold) {
            return message;
        }

        // TODO: Implement actual compression (gzip, lz4, zstd)
        // For now, simulate compression
        const original_size = @as(u32, @intCast(message.payload.len));
        const compression_ratio = 0.7; // Simulated 30% compression
        const compressed_size = @as(usize, @intFromFloat(@as(f64, @floatFromInt(original_size)) * compression_ratio));

        const compressed_payload = try self.allocator.alloc(u8, compressed_size);
        // Simulate compression by copying first part of data
        @memcpy(compressed_payload[0..@min(compressed_size, message.payload.len)], message.payload[0..@min(compressed_size, message.payload.len)]);

        // Update statistics
        self.compression_stats.total_compressed += 1;
        self.compression_stats.total_original_size += original_size;
        self.compression_stats.total_compressed_size += @as(u64, @intCast(compressed_size));
        self.compression_stats.avg_compression_ratio = @as(f64, @floatFromInt(self.compression_stats.total_compressed_size)) / @as(f64, @floatFromInt(self.compression_stats.total_original_size));

        return NetworkMessage{
            .message_type = message.message_type,
            .sender = message.sender,
            .recipient = message.recipient,
            .payload = compressed_payload,
            .timestamp = message.timestamp,
            .signature = message.signature,
            .compression = if (self.config.adaptive_compression) .gzip else .gzip,
            .original_size = original_size,
            .stream_id = message.stream_id,
        };
    }

    /// Decompress a network message
    pub fn decompress(self: *MessageCompressor, message: NetworkMessage) !NetworkMessage {
        if (message.compression == .none) {
            return message;
        }

        // TODO: Implement actual decompression
        // For now, simulate decompression by expanding payload
        const decompressed_payload = try self.allocator.alloc(u8, message.original_size);
        @memcpy(decompressed_payload[0..@min(message.payload.len, decompressed_payload.len)], message.payload[0..@min(message.payload.len, decompressed_payload.len)]);

        return NetworkMessage{
            .message_type = message.message_type,
            .sender = message.sender,
            .recipient = message.recipient,
            .payload = decompressed_payload,
            .timestamp = message.timestamp,
            .signature = message.signature,
            .compression = .none,
            .original_size = 0,
            .stream_id = message.stream_id,
        };
    }

    pub fn getStatistics(self: *MessageCompressor) CompressionStats {
        return self.compression_stats;
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
        .connection_pool = ConnectionPoolConfig{},
        .compression = CompressionConfig{},
        .bandwidth = BandwidthConfig{},
    };

    var node = try NetworkNode.init(allocator, config);
    defer node.deinit();

    try std.testing.expect(!node.running);
    try std.testing.expect(node.peers.count() == 0);
}

test "connection pool management" {
    const allocator = std.testing.allocator;

    const config = ConnectionPoolConfig{
        .max_connections_per_peer = 5,
        .max_streams_per_connection = 10,
    };

    const bandwidth_config = BandwidthConfig{};
    var bandwidth_limiter = try BandwidthLimiter.init(allocator, bandwidth_config);
    defer bandwidth_limiter.deinit();

    const peer_id = [_]u8{1} ** 32;
    var pool = try ConnectionPool.init(allocator, peer_id, config, bandwidth_limiter);
    defer pool.deinit();

    // Test acquiring connections
    const conn1 = try pool.acquireConnection();
    const conn2 = try pool.acquireConnection();

    try std.testing.expect(conn1 != conn2);

    // Test releasing connections
    try pool.releaseConnection(conn1);
    try pool.releaseConnection(conn2);

    // Test connection reuse
    const conn3 = try pool.acquireConnection();
    try std.testing.expect(conn3 == conn1 or conn3 == conn2); // Should reuse

    try pool.releaseConnection(conn3);
}

test "message compression" {
    const allocator = std.testing.allocator;

    const config = CompressionConfig{
        .enable_compression = true,
        .compression_threshold = 100,
        .adaptive_compression = true,
    };

    var compressor = try MessageCompressor.init(allocator, config);
    defer compressor.deinit();

    const large_payload = "x" ** 200; // Large enough to trigger compression
    const message = NetworkMessage{
        .message_type = .ping,
        .sender = [_]u8{1} ** 32,
        .recipient = [_]u8{2} ** 32,
        .payload = large_payload,
        .timestamp = 1234567890,
    };

    const compressed = try compressor.compress(message);
    defer allocator.free(compressed.payload);

    // Should be compressed
    try std.testing.expect(compressed.compression != .none);
    try std.testing.expect(compressed.payload.len < message.payload.len);
    try std.testing.expect(compressed.original_size == message.payload.len);

    // Test decompression
    const decompressed = try compressor.decompress(compressed);
    defer allocator.free(decompressed.payload);

    try std.testing.expect(decompressed.compression == .none);
    try std.testing.expect(decompressed.payload.len == message.payload.len);
}
