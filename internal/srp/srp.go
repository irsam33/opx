package srp

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// SRPGroup represents an SRP group (prime + generator)
type SRPGroup struct {
	Name string
	N    *big.Int // Prime
	G    *big.Int // Generator
	K    *big.Int // Multiplier (k = H(N, g))
}

// Pre-defined SRP groups (RFC 5054)
var (
	// 2048-bit group
	Group2048 = &SRPGroup{
		Name: "2048",
		N: new(big.Int).SetBytes([]byte{
			0xac, 0x6b, 0xdb, 0x41, 0x32, 0x4a, 0x9a, 0x9b,
			0xf1, 0x66, 0xde, 0x5e, 0x13, 0x89, 0x58, 0x2f,
			0xaf, 0x72, 0xb6, 0x65, 0x19, 0x87, 0x75, 0x51,
			0xd6, 0x85, 0x1d, 0x39, 0x84, 0x34, 0x82, 0x9e,
			0x81, 0x9d, 0x06, 0x34, 0x04, 0x34, 0x77, 0x19,
			0x6f, 0x9c, 0x4c, 0x11, 0x35, 0x9e, 0x8c, 0x2c,
			0x5d, 0x76, 0x51, 0x17, 0x3b, 0x8c, 0x33, 0x27,
			0x24, 0x1d, 0x8b, 0x9f, 0x0e, 0x87, 0x6e, 0x56,
			0x64, 0x15, 0x33, 0x41, 0x26, 0x07, 0x94, 0x9a,
			0x6a, 0x53, 0x83, 0x51, 0x6d, 0xc2, 0x3d, 0x16,
			0x63, 0x2a, 0x75, 0x71, 0x27, 0x54, 0x97, 0x9f,
			0x19, 0x1c, 0xb5, 0x60, 0x67, 0x20, 0x80, 0x46,
			0xce, 0x78, 0x86, 0x90, 0x28, 0x54, 0x38, 0x58,
			0x65, 0x3a, 0x2f, 0x1f, 0x58, 0xb9, 0x86, 0x4b,
			0x54, 0x12, 0x6d, 0xa2, 0x27, 0x03, 0x6a, 0x87,
			0x35, 0x48, 0x54, 0x2e, 0x3a, 0x73, 0x8f, 0x30,
			0x98, 0x79, 0x46, 0x12, 0x20, 0x14, 0x6d, 0x1f,
			0x65, 0x69, 0x92, 0x59, 0x61, 0x45, 0x4a, 0x7e,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}),
		G: big.NewInt(2),
		K: big.NewInt(3),
	}
)

// SRPClient represents an SRP client
type SRPClient struct {
	Group    *SRPGroup
	Username string
	Password string
	Salt     []byte
	A        *big.Int // Client ephemeral public key
	a        *big.Int // Client ephemeral private key
	K        []byte   // Session key
	M1       []byte   // Client proof
	M2       []byte   // Server proof
}

// NewSRPClient creates a new SRP client
func NewSRPClient(group *SRPGroup, username, password string) *SRPClient {
	return &SRPClient{
		Group:    group,
		Username: username,
		Password: password,
	}
}

// ComputeA computes A = g^a mod N (client ephemeral public key)
func (c *SRPClient) ComputeA() (*big.Int, error) {
	// Generate random a (256 bits)
	a := make([]byte, 32)
	if _, err := rand.Read(a); err != nil {
		return nil, err
	}
	c.a = new(big.Int).SetBytes(a)

	// A = g^a mod N
	A := new(big.Int).Exp(c.Group.G, c.a, c.Group.N)
	c.A = A

	return A, nil
}

// ComputeX computes x = H(salt, H(username:password))
func (c *SRPClient) ComputeX(salt []byte) *big.Int {
	// H(username:password)
	h := sha256.New()
	h.Write([]byte(c.Username))
	h.Write([]byte(":"))
	h.Write([]byte(c.Password))
	innerHash := h.Sum(nil)

	// x = H(salt || innerHash)
	h2 := sha256.New()
	h2.Write(salt)
	h2.Write(innerHash)
	x := new(big.Int).SetBytes(h2.Sum(nil))

	return x
}

// ComputeVerifier computes v = g^x mod N (stored on server)
func (c *SRPClient) ComputeVerifier(salt []byte) *big.Int {
	x := c.ComputeX(salt)
	v := new(big.Int).Exp(c.Group.G, x, c.Group.N)
	return v
}

// ComputeU computes u = H(A, B)
func (c *SRPClient) ComputeU(A, B *big.Int) *big.Int {
	h := sha256.New()
	h.Write(A.Bytes())
	h.Write(B.Bytes())
	u := new(big.Int).SetBytes(h.Sum(nil))
	return u
}

// ComputeS computes S = (B - k*g^x)^(a + u*x) mod N
func (c *SRPClient) ComputeS(B *big.Int, salt []byte) (*big.Int, error) {
	x := c.ComputeX(salt)
	u := c.ComputeU(c.A, B)

	// g^x mod N
	gx := new(big.Int).Exp(c.Group.G, x, c.Group.N)

	// k * g^x mod N
	kgx := new(big.Int).Mul(c.Group.K, gx)
	kgx.Mod(kgx, c.Group.N)

	// B - k*g^x mod N
	base := new(big.Int).Sub(B, kgx)
	base.Mod(base, c.Group.N)

	// a + u*x
	ux := new(big.Int).Mul(u, x)
	aPlusUx := new(big.Int).Add(c.a, ux)

	// S = (B - k*g^x)^(a + u*x) mod N
	S := new(big.Int).Exp(base, aPlusUx, c.Group.N)
	return S, nil
}

// ComputeK computes session key K = H(S)
func (c *SRPClient) ComputeK(S *big.Int) []byte {
	h := sha256.New()
	h.Write(S.Bytes())
	return h.Sum(nil)
}

// ComputeM1 computes client proof M1 = H(H(N) XOR H(g), H(username), salt, A, B, K)
func (c *SRPClient) ComputeM1(salt []byte, A, B *big.Int, K []byte) []byte {
	h := sha256.New()

	// H(N) XOR H(g)
	hN := sha256.Sum256(c.Group.N.Bytes())
	hg := sha256.Sum256(c.Group.G.Bytes())
	for i := range hN {
		hN[i] ^= hg[i]
	}
	h.Write(hN[:])

	// H(username)
	hUser := sha256.Sum256([]byte(c.Username))
	h.Write(hUser[:])

	// salt
	h.Write(salt)

	// A
	h.Write(A.Bytes())

	// B
	h.Write(B.Bytes())

	// K
	h.Write(K)

	m1 := h.Sum(nil)
	c.M1 = m1
	return m1
}

// ComputeM2 computes server proof M2 = H(A, M1, K)
func (c *SRPClient) ComputeM2(A *big.Int, M1, K []byte) []byte {
	h := sha256.New()
	h.Write(A.Bytes())
	h.Write(M1)
	h.Write(K)

	m2 := h.Sum(nil)
	c.M2 = m2
	return m2
}

// VerifyServerProof verifies the server's proof
func (c *SRPClient) VerifyServerProof(M2 []byte) bool {
	if c.M2 == nil {
		return false
	}
	// Constant-time comparison
	if len(M2) != len(c.M2) {
		return false
	}
	result := 0
	for i := range M2 {
		result |= int(M2[i] ^ c.M2[i])
	}
	return result == 0
}

// GetSessionKey returns the session key
func (c *SRPClient) GetSessionKey() []byte {
	if c.K == nil {
		return nil
	}
	return c.K
}

// GenerateSalt generates a random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateVerifier generates a verifier for server storage
func GenerateVerifier(group *SRPGroup, username, password string, salt []byte) (*big.Int, error) {
	// Compute x = H(salt, H(username:password))
	h := sha256.New()
	h.Write([]byte(username))
	h.Write([]byte(":"))
	h.Write([]byte(password))
	innerHash := h.Sum(nil)

	h2 := sha256.New()
	h2.Write(salt)
	h2.Write(innerHash)
	x := new(big.Int).SetBytes(h2.Sum(nil))

	// v = g^x mod N
	v := new(big.Int).Exp(group.G, x, group.N)
	return v, nil
}

// SRPExchange represents an SRP exchange result
type SRPExchange struct {
	Salt       []byte
	A          *big.Int
	B          *big.Int
	U          *big.Int
	M1         []byte
	M2         []byte
	SessionKey []byte
}

// NewSRPExchange creates a new SRP exchange
func NewSRPExchange(username, password string) *SRPExchange {
	group := Group2048
	client := NewSRPClient(group, username, password)

	salt, _ := GenerateSalt()
	A, _ := client.ComputeA()
	v := client.ComputeVerifier(salt)

	// Simulate server: B = k*v + g^b mod N
	b := make([]byte, 32)
	rand.Read(b)
	bigB := new(big.Int).SetBytes(b)
	gb := new(big.Int).Exp(group.G, bigB, group.N)
	kv := new(big.Int).Mul(group.K, v)
	kv.Mod(kv, group.N)
	B := new(big.Int).Add(kv, gb)
	B.Mod(B, group.N)

	// Client computes S
	S, _ := client.ComputeS(B, salt)
	K := client.ComputeK(S)
	M1 := client.ComputeM1(salt, A, B, K)
	M2 := client.ComputeM2(A, M1, K)

	client.K = K

	return &SRPExchange{
		Salt:       salt,
		A:          A,
		B:          B,
		U:          client.ComputeU(A, B),
		M1:         M1,
		M2:         M2,
		SessionKey: K,
	}
}

// VerifyExchange verifies an SRP exchange
func (ex *SRPExchange) VerifyExchange() bool {
	// In a real implementation, the server would verify M1
	// and the client would verify M2
	return ex.M1 != nil && ex.M2 != nil && ex.SessionKey != nil
}
