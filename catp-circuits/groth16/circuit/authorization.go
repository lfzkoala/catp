package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// AuthorizationCircuit is the Groth16/BN254 CATP authorization circuit for
// compact EVM verification. It intentionally uses a separate commitment
// version from the Halo2 circuit so proof backends are not treated as
// wire-compatible.
type AuthorizationCircuit struct {
	PolicyCommitment frontend.Variable `gnark:",public"`
	ActionType       frontend.Variable `gnark:",public"`
	Protocol0        frontend.Variable `gnark:",public"`
	Protocol1        frontend.Variable `gnark:",public"`
	Protocol2        frontend.Variable `gnark:",public"`
	Protocol3        frontend.Variable `gnark:",public"`
	Token0           frontend.Variable `gnark:",public"`
	Token1           frontend.Variable `gnark:",public"`
	Token2           frontend.Variable `gnark:",public"`
	Token3           frontend.Variable `gnark:",public"`
	Value            frontend.Variable `gnark:",public"`
	CurrentTimestamp frontend.Variable `gnark:",public"`
	CumulativeSpend  frontend.Variable `gnark:",public"`

	AllowedAction   frontend.Variable
	AllowedProtocol [4]frontend.Variable
	AllowedToken    [4]frontend.Variable
	MaxValuePerTx   frontend.Variable
	MaxValueTotal   frontend.Variable
	ValidFrom       frontend.Variable
	ValidUntil      frontend.Variable
}

func (c *AuthorizationCircuit) Define(api frontend.API) error {
	for _, value := range []frontend.Variable{
		c.ActionType,
		c.Protocol0, c.Protocol1, c.Protocol2, c.Protocol3,
		c.Token0, c.Token1, c.Token2, c.Token3,
		c.Value,
		c.CurrentTimestamp,
		c.CumulativeSpend,
		c.AllowedAction,
		c.AllowedProtocol[0], c.AllowedProtocol[1], c.AllowedProtocol[2], c.AllowedProtocol[3],
		c.AllowedToken[0], c.AllowedToken[1], c.AllowedToken[2], c.AllowedToken[3],
		c.MaxValuePerTx,
		c.MaxValueTotal,
		c.ValidFrom,
		c.ValidUntil,
	} {
		api.ToBinary(value, 64)
	}

	api.AssertIsEqual(c.ActionType, c.AllowedAction)
	api.AssertIsEqual(c.Protocol0, c.AllowedProtocol[0])
	api.AssertIsEqual(c.Protocol1, c.AllowedProtocol[1])
	api.AssertIsEqual(c.Protocol2, c.AllowedProtocol[2])
	api.AssertIsEqual(c.Protocol3, c.AllowedProtocol[3])
	api.AssertIsEqual(c.Token0, c.AllowedToken[0])
	api.AssertIsEqual(c.Token1, c.AllowedToken[1])
	api.AssertIsEqual(c.Token2, c.AllowedToken[2])
	api.AssertIsEqual(c.Token3, c.AllowedToken[3])

	api.AssertIsLessOrEqual(1, c.Value)
	api.AssertIsLessOrEqual(c.Value, c.MaxValuePerTx)
	api.AssertIsLessOrEqual(api.Add(c.CumulativeSpend, c.Value), c.MaxValueTotal)
	api.AssertIsLessOrEqual(c.ValidFrom, c.CurrentTimestamp)
	api.AssertIsLessOrEqual(c.CurrentTimestamp, c.ValidUntil)

	hasher, err := mimc.New(api)
	if err != nil {
		return err
	}
	hasher.Write(
		frontend.Variable(0x43415450), // "CATP" domain tag
		frontend.Variable(2),          // Groth16 authorization commitment version
		c.AllowedAction,
		c.AllowedProtocol[0], c.AllowedProtocol[1], c.AllowedProtocol[2], c.AllowedProtocol[3],
		c.AllowedToken[0], c.AllowedToken[1], c.AllowedToken[2], c.AllowedToken[3],
		c.MaxValuePerTx,
		c.MaxValueTotal,
		c.ValidFrom,
		c.ValidUntil,
	)
	api.AssertIsEqual(c.PolicyCommitment, hasher.Sum())

	return nil
}
