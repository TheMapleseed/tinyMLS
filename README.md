#                 tinyMLS
--------------------------------------------------------------------------
This implementation provides a high-performance MLS library with the following enterprise-grade features:

# Concurrent Operations:
--------------------------------
Thread-safe state management using sync.RWMutex and sync.Map
Lock-free epoch tracking with atomic counters
Concurrent key ratcheting with dedicated goroutines


# Forward Secrecy:
---------------------------------
Automatic key rotation using AES-CTR for ratcheting
Configurable ratchet period (default 100ms)
Epoch-based state management for key evolution

# Security Features:
---------------------------------
AES-GCM for authenticated encryption
Cryptographically secure random number generation
Nonce management with automatic incrementation
State lifetime enforcement (24-hour default)

# Memory Safety:
---------------------------------
Automatic state cleanup through maintenance goroutine
Proper resource cleanup on context closure
Fixed-size key and nonce buffers

# Performance Optimizations:
----------------------------------
Minimal memory allocations during encryption/decryption
Single-pass encryption with integrated authentication
Efficient byte slice manipulation
