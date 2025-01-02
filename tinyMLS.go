package tinyMLS

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// HashAlgorithm represents supported hash functions
// HashAlgorithm represents the cryptographic hash function identifier
// Using uint64 to provide adequate space for future algorithm additions
// and proper entropy in algorithm selection
type HashAlgorithm uint64

const (
	// HashAlgorithm constants with deliberate spacing for future additions
	// Using explicit values rather than iota to ensure stable serialization
	SHA256      HashAlgorithm = 1 << 0
	SHA512      HashAlgorithm = 1 << 1
	SHA3_256    HashAlgorithm = 1 << 2
	SHA3_512    HashAlgorithm = 1 << 3
	BLAKE2b_256 HashAlgorithm = 1 << 4
	BLAKE2b_512 HashAlgorithm = 1 << 5

	// Reserve space for future algorithms
	// Next available: 1 << 6

	// Mask for supported algorithms
	SupportedHashMask HashAlgorithm = SHA256 | SHA512 | SHA3_256 | SHA3_512 | BLAKE2b_256 | BLAKE2b_512
)

// AuthenticationState maintains the current hash algorithm state
// AuthenticationState maintains the cryptographic hash state
// Thread-safe through atomic operations on algorithm selection
type AuthenticationState struct {
	algorithm     atomic.Uint64 // Current hash algorithm
	availableAlgs atomic.Uint64 // Mask of available algorithms
	hash          *atomic.Value // Current hash.Hash implementation
	lastRotation  atomic.Int64  // Unix timestamp of last rotation
	jitter        atomic.Int64  // Microseconds of random timing variation

	// Entropy accumulator for algorithm selection
	entropyAcc    [64]byte      // Accumulated entropy for algorithm selection
	entropyCursor atomic.Uint32 // Current position in entropy accumulator
}

// NewAuthenticationState initializes a new authentication state
func NewAuthenticationState() (*AuthenticationState, error) {
	state := &AuthenticationState{
		hash: &atomic.Value{},
	}

	// Initialize with supported algorithms
	state.availableAlgs.Store(uint64(SupportedHashMask))

	// Initialize with SHA256 as default
	state.algorithm.Store(uint64(SHA256))
	state.hash.Store(sha256.New())

	// Set initial rotation time
	state.lastRotation.Store(time.Now().Unix())

	// Initialize entropy accumulator
	if _, err := rand.Read(state.entropyAcc[:]); err != nil {
		return nil, fmt.Errorf("failed to initialize entropy: %w", err)
	}

	return state, nil
}

// EnhancedState extends the original State with additional security features
type EnhancedState struct {
	State
	authState    atomic.Value // *AuthenticationState
	entropyPool  []byte
	entropyMutex sync.Mutex
}

// newEnhancedState initializes a state with enhanced security features
func newEnhancedState() (*EnhancedState, error) {
	baseState, err := newState()
	if err != nil {
		return nil, err
	}

	state := &EnhancedState{
		State:       *baseState,
		entropyPool: make([]byte, 1024), // Initial entropy pool
	}

	// Initialize authentication state
	authState := &AuthenticationState{
		algorithm:    SHA256,
		hash:         sha256.New(),
		lastRotation: time.Now(),
		jitter:       0,
	}
	state.authState.Store(authState)

	// Seed initial entropy pool
	if _, err := rand.Read(state.entropyPool); err != nil {
		return nil, err
	}

	go state.irregularAuthRotation()
	return state, nil
}

// irregularAuthRotation handles non-deterministic algorithm rotation
func (s *EnhancedState) irregularAuthRotation() {
	for {
		// Generate random rotation interval between 30-90 minutes
		jitterMs := time.Duration(rand.Int63n(3600000)) + 1800000
		time.Sleep(time.Millisecond * jitterMs)

		auth := s.authState.Load().(*AuthenticationState)
		newAuth := &AuthenticationState{
			lastRotation: time.Now(),
			jitter:       rand.Int63n(1000), // 0-1000 microseconds
		}

		// Rotate between hash algorithms
		if auth.algorithm == SHA256 {
			newAuth.algorithm = SHA512
			newAuth.hash = sha512.New()
		} else {
			newAuth.algorithm = SHA256
			newAuth.hash = sha256.New()
		}

		s.authState.Store(newAuth)
	}
}

// CryptoError represents domain-specific error types with context
type CryptoError struct {
	Op        string // Operation being performed
	Component string // System component
	Err       error  // Underlying error
	Fatal     bool   // Indicates if error is fatal to security guarantees
}

func (e *CryptoError) Error() string {
	if e.Fatal {
		return fmt.Sprintf("CRITICAL: %s failed in %s: %v", e.Op, e.Component, e.Err)
	}
	return fmt.Sprintf("%s error in %s: %v", e.Op, e.Component, e.Err)
}

// GCMState manages the AES-GCM operational state
type GCMState struct {
	// Core cryptographic components
	block cipher.Block
	gcm   cipher.AEAD

	// Operational state
	keyEpoch  atomic.Uint64
	opCounter atomic.Uint64

	// Security parameters
	maxOperations  uint64
	reKeyThreshold uint64

	// State management
	mu       sync.RWMutex
	lastInit time.Time
}

// newGCMState initializes a new GCM state with the provided key
func newGCMState(key []byte) (*GCMState, error) {
	if len(key) != keySize {
		return nil, &CryptoError{
			Op:        "Initialize",
			Component: "GCMState",
			Err:       fmt.Errorf("invalid key size: %d", len(key)),
			Fatal:     true,
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &CryptoError{
			Op:        "Initialize",
			Component: "AES",
			Err:       err,
			Fatal:     true,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &CryptoError{
			Op:        "Initialize",
			Component: "GCM",
			Err:       err,
			Fatal:     true,
		}
	}

	return &GCMState{
		block:          block,
		gcm:            gcm,
		maxOperations:  1 << 32, // Maximum operations before forced rekey
		reKeyThreshold: 1 << 30, // Threshold for suggesting rekey
		lastInit:       time.Now(),
	}, nil
}

// GCMOperationParams encapsulates parameters for GCM operations
type GCMOperationParams struct {
	Plaintext []byte
	Nonce     []byte
	AssocData []byte
	Tags      map[string][]byte // Additional authentication tags
}

// validateOperationParams performs comprehensive parameter validation
func (s *GCMState) validateOperationParams(params *GCMOperationParams) error {
	if params == nil {
		return &CryptoError{
			Op:        "Validate",
			Component: "GCMParams",
			Err:       errors.New("nil parameters"),
			Fatal:     true,
		}
	}

	if len(params.Nonce) != gcmNonceSize {
		return &CryptoError{
			Op:        "Validate",
			Component: "GCMParams",
			Err:       fmt.Errorf("invalid nonce size: %d", len(params.Nonce)),
			Fatal:     true,
		}
	}

	if len(params.Plaintext) > maxGCMPlain {
		return &CryptoError{
			Op:        "Validate",
			Component: "GCMParams",
			Err:       fmt.Errorf("plaintext exceeds maximum size: %d", len(params.Plaintext)),
			Fatal:     false,
		}
	}

	return nil
}

// encryptWithGCM performs GCM encryption with state management
func (s *GCMState) encryptWithGCM(params *GCMOperationParams) ([]byte, error) {
	if err := s.validateOperationParams(params); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check operation counter
	opCount := s.opCounter.Add(1)
	if opCount >= s.maxOperations {
		return nil, &CryptoError{
			Op:        "Encrypt",
			Component: "GCMState",
			Err:       errors.New("maximum operations exceeded"),
			Fatal:     true,
		}
	}

	// Prepare output buffer with optimal sizing
	output := make([]byte, 0, len(params.Plaintext)+s.gcm.Overhead())

	// Perform encryption with authenticated data
	ciphertext := s.gcm.Seal(output, params.Nonce, params.Plaintext, params.AssocData)

	// Check for rekey suggestion
	if opCount >= s.reKeyThreshold {
		// Log or notify about approaching operation limit
		log.Printf("Warning: GCM operation count %d exceeds rekey threshold", opCount)
	}

	return ciphertext, nil
}

// decryptWithGCM performs GCM decryption with state validation
func (s *GCMState) decryptWithGCM(ciphertext, nonce, assocData []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Validate input parameters
	if len(nonce) != gcmNonceSize {
		return nil, &CryptoError{
			Op:        "Decrypt",
			Component: "GCMState",
			Err:       fmt.Errorf("invalid nonce size: %d", len(nonce)),
			Fatal:     true,
		}
	}

	// Check minimum ciphertext size
	if len(ciphertext) < s.gcm.Overhead() {
		return nil, &CryptoError{
			Op:        "Decrypt",
			Component: "GCMState",
			Err:       errors.New("ciphertext too short"),
			Fatal:     true,
		}
	}

	// Increment operation counter
	opCount := s.opCounter.Add(1)
	if opCount >= s.maxOperations {
		return nil, &CryptoError{
			Op:        "Decrypt",
			Component: "GCMState",
			Err:       errors.New("maximum operations exceeded"),
			Fatal:     true,
		}
	}

	// Perform decryption
	plaintext, err := s.gcm.Open(nil, nonce, ciphertext, assocData)
	if err != nil {
		return nil, &CryptoError{
			Op:        "Decrypt",
			Component: "GCM",
			Err:       err,
			Fatal:     true,
		}
	}

	return plaintext, nil
}

// KeyRotationParams defines parameters for key rotation
type KeyRotationParams struct {
	ForceRotation bool          // Force immediate rotation
	NewKey        []byte        // Optional pre-generated key
	RotationTime  time.Duration // Minimum time between rotations
}

// KeyRotationResult contains the result of a key rotation
type KeyRotationResult struct {
	Rotated      bool      // Whether rotation occurred
	PreviousKey  []byte    // Previous key for validation
	RotationTime time.Time // Time of rotation
}

// rotateKey performs key rotation with state preservation
func (s *GCMState) rotateKey(params *KeyRotationParams) (*KeyRotationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := &KeyRotationResult{
		RotationTime: time.Now(),
	}

	// Check rotation timing unless forced
	if !params.ForceRotation {
		if time.Since(s.lastInit) < params.RotationTime {
			return result, nil
		}
	}

	// Preserve previous key for validation
	prevKey := make([]byte, keySize)
	subtle.ConstantTimeCopy(1, prevKey, s.key[:])
	result.PreviousKey = prevKey

	// Generate or use provided new key
	var newKey []byte
	if params.NewKey != nil {
		if len(params.NewKey) != keySize {
			return nil, &CryptoError{
				Op:        "Rotate",
				Component: "KeyManagement",
				Err:       fmt.Errorf("invalid key size: %d", len(params.NewKey)),
				Fatal:     true,
			}
		}
		newKey = params.NewKey
	} else {
		newKey = make([]byte, keySize)
		if _, err := rand.Read(newKey); err != nil {
			return nil, &CryptoError{
				Op:        "Rotate",
				Component: "KeyGeneration",
				Err:       err,
				Fatal:     true,
			}
		}
	}

	// Initialize new GCM state
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return nil, &CryptoError{
			Op:        "Rotate",
			Component: "AES",
			Err:       err,
			Fatal:     true,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &CryptoError{
			Op:        "Rotate",
			Component: "GCM",
			Err:       err,
			Fatal:     true,
		}
	}

	// Update state atomically
	s.block = block
	s.gcm = gcm
	s.keyEpoch.Add(1)
	s.opCounter.Store(0)
	s.lastInit = result.RotationTime
	result.Rotated = true

	return result, nil
}

// validateKeyRotation performs post-rotation validation
func (s *GCMState) validateKeyRotation(result *KeyRotationResult) error {
	if !result.Rotated {
		return nil
	}

	// Verify operation counter reset
	if s.opCounter.Load() != 0 {
		return &CryptoError{
			Op:        "Validate",
			Component: "KeyRotation",
			Err:       errors.New("operation counter not reset"),
			Fatal:     true,
		}
	}

	// Verify epoch increment
	expectedEpoch := result.PreviousEpoch + 1
	if s.keyEpoch.Load() != expectedEpoch {
		return &CryptoError{
			Op:        "Validate",
			Component: "KeyRotation",
			Err: fmt.Errorf("invalid epoch: got %d, want %d",
				s.keyEpoch.Load(), expectedEpoch),
			Fatal: true,
		}
	}

	return nil
}

// subtleEncrypt performs constant-time encryption with AES-GCM
func (s *EnhancedState) subtleEncrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) > maxGCMPlain {
		return nil, fmt.Errorf("plaintext exceeds maximum GCM size: %d > %d",
			len(plaintext), maxGCMPlain)
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Apply timing jitter
	auth := s.authState.Load().(*AuthenticationState)
	if jitter := auth.jitter.Load(); jitter > 0 {
		time.Sleep(time.Microsecond * time.Duration(jitter))
	}

	// Prepare GCM authentication structure
	authData := gcmAuthData{
		epoch: s.epoch,
	}
	copy(authData.nonce[:], s.nonce[:])

	// Generate authentication tag using current hash
	hashImpl := auth.hash.Load().(hash.Hash)
	hashImpl.Reset()
	hashImpl.Write(s.nonce[:])
	hashImpl.Write(plaintext)
	authData.authTag = hashImpl.Sum(nil)

	// Derive encryption key using constant-time operations
	var derivedKey [keySize]byte
	subtle.XORBytes(derivedKey[:], s.key[:], authData.authTag[:keySize])

	// Initialize AES-GCM with derived key
	block, err := aes.NewCipher(derivedKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM: %w", err)
	}

	// Calculate required buffer size
	outputSize := 4 + // epoch
		gcmNonceSize + // nonce
		len(plaintext) + // ciphertext
		gcm.Overhead() + // GCM tag
		len(authData.authTag) // Additional auth tag

	// Prepare output buffer with proper alignment
	output := make([]byte, outputSize)
	current := output

	// Write epoch
	binary.BigEndian.PutUint32(current, authData.epoch)
	current = current[4:]

	// Write nonce
	copy(current, authData.nonce[:])
	current = current[gcmNonceSize:]

	// Perform GCM encryption with authentication
	ciphertext := gcm.Seal(current[:0],
		authData.nonce[:],
		plaintext,
		output[:4]) // Use epoch as additional authenticated data

	// Append our additional authentication tag
	copy(output[4+gcmNonceSize+len(ciphertext):], authData.authTag)

	return output, nil
}

// subtleDecrypt performs constant-time decryption with AES-GCM
func (s *EnhancedState) subtleDecrypt(ciphertext []byte) ([]byte, error) {
	minSize := 4 + gcmNonceSize + gcmTagSize
	if len(ciphertext) < minSize {
		return nil, fmt.Errorf("ciphertext too short: %d < %d",
			len(ciphertext), minSize)
	}

	// Extract authentication structure
	authData := gcmAuthData{
		epoch: binary.BigEndian.Uint32(ciphertext[:4]),
	}
	copy(authData.nonce[:], ciphertext[4:4+gcmNonceSize])

	// Extract additional authentication tag
	authTagStart := len(ciphertext) - sha512.Size
	if authTagStart < minSize {
		return nil, errors.New("invalid ciphertext structure")
	}
	authData.authTag = ciphertext[authTagStart:]

	// Derive decryption key using constant-time operations
	var derivedKey [keySize]byte
	subtle.XORBytes(derivedKey[:], s.key[:], authData.authTag[:keySize])

	// Initialize AES-GCM for decryption
	block, err := aes.NewCipher(derivedKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM: %w", err)
	}

	// Perform GCM decryption
	return gcm.Open(nil,
		authData.nonce[:],
		ciphertext[4+gcmNonceSize:authTagStart],
		ciphertext[:4]) // Authenticate epoch
}

// refreshEntropyPool updates the entropy pool in a non-deterministic manner
func (s *EnhancedState) refreshEntropyPool() error {
	s.entropyMutex.Lock()
	defer s.entropyMutex.Unlock()

	// Generate new entropy
	newEntropy := make([]byte, len(s.entropyPool))
	if _, err := rand.Read(newEntropy); err != nil {
		return err
	}

	// Constant-time entropy combination
	subtle.XORBytes(s.entropyPool, s.entropyPool, newEntropy)
	return nil
}

// enhancedKeyRatchet extends the original ratchet with subtle operations
func (s *EnhancedState) enhancedKeyRatchet() {
	ticker := time.NewTicker(ratchetPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mutex.Lock()

			// Apply entropy pool
			if err := s.refreshEntropyPool(); err != nil {
				s.mutex.Unlock()
				continue
			}

			// Derive new key using current authentication state
			auth := s.authState.Load().(*AuthenticationState)
			auth.hash.Reset()
			auth.hash.Write(s.key[:])
			auth.hash.Write(s.entropyPool)
			derivedMaterial := auth.hash.Sum(nil)

			// Constant-time key update
			var newKey [keySize]byte
			subtle.XORBytes(newKey[:], s.key[:], derivedMaterial[:keySize])
			s.key = newKey

			s.mutex.Unlock()

		case <-s.ratchet:
			return
		}
	}
}
