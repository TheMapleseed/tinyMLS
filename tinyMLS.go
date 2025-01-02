package mls

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/binary"
    "sync"
    "sync/atomic"
    "time"
)

const (
    keySize        = 32
    nonceSize      = 12
    ratchetPeriod  = 100 * time.Millisecond
    maxEpoch       = 1 << 32
    stateLifetime  = 24 * time.Hour
)

// State represents the encrypted session state
type State struct {
    epoch     uint32
    key       [keySize]byte
    nonce     [nonceSize]byte
    created   time.Time
    mutex     sync.RWMutex
    ratchet   chan struct{}
    lifetime  atomic.Value // time.Time
}

// Context maintains the crypto context
type Context struct {
    states    sync.Map // map[uint32]*State
    current   atomic.Uint32
    gcTicker  *time.Ticker
    done      chan struct{}
}

// New initializes a new MLS context with automatic key rotation
func New() (*Context, error) {
    ctx := &Context{
        gcTicker: time.NewTicker(time.Minute),
        done:     make(chan struct{}),
    }
    
    // Initialize first state
    state, err := newState()
    if err != nil {
        return nil, err
    }
    
    ctx.states.Store(uint32(0), state)
    go ctx.maintenance()
    return ctx, nil
}

// newState creates a new encrypted state
func newState() (*State, error) {
    state := &State{
        created: time.Now(),
        ratchet: make(chan struct{}),
    }
    
    // Generate initial key
    if _, err := rand.Read(state.key[:]); err != nil {
        return nil, err
    }
    
    // Generate initial nonce
    if _, err := rand.Read(state.nonce[:]); err != nil {
        return nil, err
    }
    
    state.lifetime.Store(time.Now().Add(stateLifetime))
    go state.keyRatchet()
    return state, nil
}

// keyRatchet implements forward secrecy through periodic key rotation
func (s *State) keyRatchet() {
    ticker := time.NewTicker(ratchetPeriod)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            s.mutex.Lock()
            // Ratchet key using AES in counter mode
            block, err := aes.NewCipher(s.key[:])
            if err != nil {
                s.mutex.Unlock()
                continue
            }
            
            stream := cipher.NewCTR(block, s.nonce[:])
            var newKey [keySize]byte
            stream.XORKeyStream(newKey[:], s.key[:])
            s.key = newKey
            
            // Increment nonce
            for i := nonceSize - 1; i >= 0; i-- {
                s.nonce[i]++
                if s.nonce[i] != 0 {
                    break
                }
            }
            s.mutex.Unlock()
            
        case <-s.ratchet:
            return
        }
    }
}

// maintenance handles state cleanup and rotation
func (ctx *Context) maintenance() {
    for {
        select {
        case <-ctx.gcTicker.C:
            now := time.Now()
            
            // Cleanup expired states
            ctx.states.Range(func(key, value interface{}) bool {
                state := value.(*State)
                if deadline, ok := state.lifetime.Load().(time.Time); ok {
                    if now.After(deadline) {
                        ctx.states.Delete(key)
                        close(state.ratchet)
                    }
                }
                return true
            })
            
        case <-ctx.done:
            ctx.gcTicker.Stop()
            return
        }
    }
}

// Encrypt encrypts data using the current state
func (ctx *Context) Encrypt(plaintext []byte) ([]byte, error) {
    epoch := ctx.current.Load()
    stateI, ok := ctx.states.Load(epoch)
    if !ok {
        return nil, ErrInvalidState
    }
    state := stateI.(*State)
    
    state.mutex.RLock()
    defer state.mutex.RUnlock()
    
    // Prepare output buffer: epoch + nonce + ciphertext
    output := make([]byte, 4+nonceSize+len(plaintext))
    binary.BigEndian.PutUint32(output, epoch)
    copy(output[4:], state.nonce[:])
    
    // Encrypt using AES-GCM
    block, err := aes.NewCipher(state.key[:])
    if err != nil {
        return nil, err
    }
    
    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    // Encrypt and authenticate
    ciphertext := aead.Seal(output[4+nonceSize:4+nonceSize], 
        state.nonce[:],
        plaintext, 
        output[:4])
    
    return output[:4+nonceSize+len(ciphertext)], nil
}

// Decrypt decrypts data using the specified epoch state
func (ctx *Context) Decrypt(ciphertext []byte) ([]byte, error) {
    if len(ciphertext) < 4+nonceSize {
        return nil, ErrInvalidCiphertext
    }
    
    epoch := binary.BigEndian.Uint32(ciphertext)
    stateI, ok := ctx.states.Load(epoch)
    if !ok {
        return nil, ErrInvalidEpoch
    }
    state := stateI.(*State)
    
    state.mutex.RLock()
    defer state.mutex.RUnlock()
    
    // Extract nonce
    var nonce [nonceSize]byte
    copy(nonce[:], ciphertext[4:4+nonceSize])
    
    // Decrypt using AES-GCM
    block, err := aes.NewCipher(state.key[:])
    if err != nil {
        return nil, err
    }
    
    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    return aead.Open(nil, 
        nonce[:],
        ciphertext[4+nonceSize:],
        ciphertext[:4])
}

// RotateKey creates a new epoch with fresh keys
func (ctx *Context) RotateKey() error {
    epoch := ctx.current.Load()
    if epoch >= maxEpoch {
        return ErrMaxEpochReached
    }
    
    state, err := newState()
    if err != nil {
        return err
    }
    
    ctx.states.Store(epoch+1, state)
    ctx.current.Add(1)
    return nil
}

// Close cleanly shuts down the context
func (ctx *Context) Close() error {
    close(ctx.done)
    ctx.states.Range(func(key, value interface{}) bool {
        state := value.(*State)
        close(state.ratchet)
        return true
    })
    return nil
}

// Error definitions
var (
    ErrInvalidState     = errors.New("invalid state")
    ErrInvalidCiphertext = errors.New("invalid ciphertext")
    ErrInvalidEpoch     = errors.New("invalid epoch")
    ErrMaxEpochReached  = errors.New("maximum epoch reached")
)
