package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/catp-protocol/catp/catp-circuits/groth16/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativeMiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const proofVersion = "authorization_groth16_v1"

type setupManifest struct {
	ProofVersion         string `json:"proofVersion"`
	Backend              string `json:"backend"`
	Curve                string `json:"curve"`
	CommitmentHash       string `json:"commitmentHash"`
	CommitmentVersion    uint64 `json:"commitmentVersion"`
	PublicInputCount     int    `json:"publicInputCount"`
	ProofBytes           int    `json:"proofBytes"`
	ConstraintCount      int    `json:"constraintCount"`
	ProvingKeySha256     string `json:"provingKeySha256"`
	VerifyingKeySha256   string `json:"verifyingKeySha256"`
	VerifierSourceSha256 string `json:"verifierSourceSha256"`
	VerifierContract     string `json:"verifierContract"`
	WrapperContract      string `json:"wrapperContract"`
}

type smokeOutput struct {
	ProofVersion     string   `json:"proofVersion"`
	PolicyCommitment string   `json:"policyCommitment"`
	PublicInputs     []string `json:"publicInputs"`
	ActionData       string   `json:"actionData"`
	CurrentTimestamp uint64   `json:"currentTimestamp"`
	CumulativeSpend  uint64   `json:"cumulativeSpend"`
	Value            uint64   `json:"value"`
	Proof            string   `json:"proof"`
	ConstraintCount  int      `json:"constraintCount"`
}

type proofData struct {
	ActionType       uint64
	Protocol         [4]uint64
	Token            [4]uint64
	Value            uint64
	CurrentTimestamp uint64
	CumulativeSpend  uint64
	AllowedAction    uint64
	AllowedProtocol  [4]uint64
	AllowedToken     [4]uint64
	MaxValuePerTx    uint64
	MaxValueTotal    uint64
	ValidFrom        uint64
	ValidUntil       uint64
}

type witnessFile struct {
	ActionType       flexibleU64 `json:"actionType"`
	Protocol         string      `json:"protocol"`
	Token            string      `json:"token"`
	Value            flexibleU64 `json:"value"`
	CurrentTimestamp flexibleU64 `json:"currentTimestamp"`
	CumulativeSpend  flexibleU64 `json:"cumulativeSpend"`
	AllowedAction    flexibleU64 `json:"allowedAction"`
	AllowedProtocol  string      `json:"allowedProtocol"`
	AllowedToken     string      `json:"allowedToken"`
	MaxValuePerTx    flexibleU64 `json:"maxValuePerTx"`
	MaxValueTotal    flexibleU64 `json:"maxValueTotal"`
	ValidFrom        flexibleU64 `json:"validFrom"`
	ValidUntil       flexibleU64 `json:"validUntil"`
}

type flexibleU64 uint64

func (v *flexibleU64) UnmarshalJSON(data []byte) error {
	var asString string
	if err := json.Unmarshal(data, &asString); err == nil {
		parsed, ok := new(big.Int).SetString(asString, 0)
		if !ok || parsed.Sign() < 0 || !parsed.IsUint64() {
			return fmt.Errorf("invalid u64 string %q", asString)
		}
		*v = flexibleU64(parsed.Uint64())
		return nil
	}

	var asNumber uint64
	if err := json.Unmarshal(data, &asNumber); err != nil {
		return err
	}
	*v = flexibleU64(asNumber)
	return nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func hex32(x *big.Int) string {
	return fmt.Sprintf("0x%064x", x)
}

func fieldElement(x uint64) fr.Element {
	var e fr.Element
	e.SetUint64(x)
	return e
}

func commitment(values ...uint64) *big.Int {
	h := nativeMiMC.NewMiMC()
	for _, value := range values {
		elem := fieldElement(value)
		bytes := elem.Bytes()
		_, err := h.Write(bytes[:])
		must(err)
	}
	sum := h.Sum(nil)
	return new(big.Int).SetBytes(sum)
}

func abiActionData(actionType uint64, protocol [4]uint64, token [4]uint64, value uint64) string {
	data := make([]byte, 128)
	data[31] = byte(actionType)
	writeLimbs(data[32:64], protocol)
	writeLimbs(data[64:96], token)
	new(big.Int).SetUint64(value).FillBytes(data[96:128])
	return "0x" + hex.EncodeToString(data)
}

func writeLimbs(out []byte, limbs [4]uint64) {
	for limbIndex, limb := range limbs {
		for i := 0; i < 8; i++ {
			out[limbIndex*8+i] = byte(limb >> (8 * i))
		}
	}
}

func main() {
	witnessPath := flag.String("witness", "", "optional JSON witness file; defaults to a built-in smoke witness")
	outputPath := flag.String("out", "", "optional proof artifact output path")
	proofOnly := flag.Bool("proof-only", false, "only write the proof artifact; do not rewrite Solidity verifier, setup manifest, or smoke fixture")
	flag.Parse()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	must(err)
	if _, err := os.Stat(filepath.Join(root, "catp-contracts")); err != nil {
		root, err = filepath.Abs(filepath.Join("..", "..", ".."))
		must(err)
	}

	outDir := filepath.Join(root, "catp-circuits", "groth16", "build")
	keyDir := filepath.Join(root, "catp-circuits", "groth16", "keys")
	contractOut := filepath.Join(root, "catp-contracts", "src", "authorization", "Groth16Verifier.sol")
	fixtureOut := filepath.Join(root, "catp-contracts", "test", "authorization", "Groth16SmokeFixture.sol")
	resolvedWitnessPath := *witnessPath
	if resolvedWitnessPath != "" && !filepath.IsAbs(resolvedWitnessPath) {
		resolvedWitnessPath = filepath.Join(root, resolvedWitnessPath)
	}

	proofOut := filepath.Join(outDir, proofVersion+".json")
	if *outputPath != "" {
		if filepath.IsAbs(*outputPath) {
			proofOut = *outputPath
		} else {
			proofOut = filepath.Join(root, *outputPath)
		}
	}
	must(os.MkdirAll(outDir, 0o755))
	must(os.MkdirAll(filepath.Dir(proofOut), 0o755))
	must(os.MkdirAll(keyDir, 0o755))

	var empty circuit.AuthorizationCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &empty)
	must(err)

	pkPath := filepath.Join(keyDir, proofVersion+".pk")
	vkPath := filepath.Join(keyDir, proofVersion+".vk")
	manifestPath := filepath.Join(keyDir, proofVersion+".manifest.json")
	pk, vk, err := loadOrCreateKeys(ccs, pkPath, vkPath)
	must(err)

	proofInput, err := loadProofData(resolvedWitnessPath)
	must(err)
	protocolWitness := [4]frontend.Variable{
		proofInput.AllowedProtocol[0],
		proofInput.AllowedProtocol[1],
		proofInput.AllowedProtocol[2],
		proofInput.AllowedProtocol[3],
	}
	tokenWitness := [4]frontend.Variable{
		proofInput.AllowedToken[0],
		proofInput.AllowedToken[1],
		proofInput.AllowedToken[2],
		proofInput.AllowedToken[3],
	}
	policyCommitment := commitment(
		0x43415450,
		2,
		proofInput.AllowedAction,
		proofInput.AllowedProtocol[0], proofInput.AllowedProtocol[1], proofInput.AllowedProtocol[2], proofInput.AllowedProtocol[3],
		proofInput.AllowedToken[0], proofInput.AllowedToken[1], proofInput.AllowedToken[2], proofInput.AllowedToken[3],
		proofInput.MaxValuePerTx,
		proofInput.MaxValueTotal,
		proofInput.ValidFrom,
		proofInput.ValidUntil,
	)

	assignment := circuit.AuthorizationCircuit{
		PolicyCommitment: policyCommitment,
		ActionType:       proofInput.ActionType,
		Protocol0:        proofInput.Protocol[0],
		Protocol1:        proofInput.Protocol[1],
		Protocol2:        proofInput.Protocol[2],
		Protocol3:        proofInput.Protocol[3],
		Token0:           proofInput.Token[0],
		Token1:           proofInput.Token[1],
		Token2:           proofInput.Token[2],
		Token3:           proofInput.Token[3],
		Value:            proofInput.Value,
		CurrentTimestamp: proofInput.CurrentTimestamp,
		CumulativeSpend:  proofInput.CumulativeSpend,
		AllowedAction:    proofInput.AllowedAction,
		AllowedProtocol:  protocolWitness,
		AllowedToken:     tokenWitness,
		MaxValuePerTx:    proofInput.MaxValuePerTx,
		MaxValueTotal:    proofInput.MaxValueTotal,
		ValidFrom:        proofInput.ValidFrom,
		ValidUntil:       proofInput.ValidUntil,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	must(err)
	publicWitness, err := witness.Public()
	must(err)

	proof, err := groth16.Prove(ccs, pk, witness)
	must(err)
	must(groth16.Verify(proof, vk, publicWitness))

	var verifierSource bytes.Buffer
	must(vk.ExportSolidity(&verifierSource))
	source := strings.Replace(verifierSource.String(), "contract Verifier {", "contract Groth16Verifier {", 1)
	verifierSourceSha256 := sha256HexBytes([]byte(source))
	if !*proofOnly {
		must(os.WriteFile(contractOut, []byte(source), 0o644))
	}

	var proofBuf bytes.Buffer
	_, err = proof.WriteRawTo(&proofBuf)
	must(err)
	proofBytes := proofBuf.Bytes()
	if len(proofBytes) < 256 {
		panic(fmt.Sprintf("expected at least 256 proof bytes, got %d", len(proofBytes)))
	}
	// The gnark Solidity Groth16 verifier expects only the uncompressed
	// Groth16 points A, B, C as uint256[8]. WriteRawTo appends commitment
	// metadata used by gnark's native verifier, so keep the Solidity prefix.
	proofBytes = proofBytes[:256]

	publicInputs := []*big.Int{
		policyCommitment,
		new(big.Int).SetUint64(proofInput.ActionType),
		new(big.Int).SetUint64(proofInput.Protocol[0]),
		new(big.Int).SetUint64(proofInput.Protocol[1]),
		new(big.Int).SetUint64(proofInput.Protocol[2]),
		new(big.Int).SetUint64(proofInput.Protocol[3]),
		new(big.Int).SetUint64(proofInput.Token[0]),
		new(big.Int).SetUint64(proofInput.Token[1]),
		new(big.Int).SetUint64(proofInput.Token[2]),
		new(big.Int).SetUint64(proofInput.Token[3]),
		new(big.Int).SetUint64(proofInput.Value),
		new(big.Int).SetUint64(proofInput.CurrentTimestamp),
		new(big.Int).SetUint64(proofInput.CumulativeSpend),
	}
	publicHex := make([]string, len(publicInputs))
	for i, input := range publicInputs {
		publicHex[i] = hex32(input)
	}

	output := smokeOutput{
		ProofVersion:     proofVersion,
		PolicyCommitment: hex32(policyCommitment),
		PublicInputs:     publicHex,
		ActionData:       abiActionData(proofInput.ActionType, proofInput.Protocol, proofInput.Token, proofInput.Value),
		CurrentTimestamp: proofInput.CurrentTimestamp,
		CumulativeSpend:  proofInput.CumulativeSpend,
		Value:            proofInput.Value,
		Proof:            "0x" + hex.EncodeToString(proofBytes),
		ConstraintCount:  ccs.GetNbConstraints(),
	}
	encoded, err := json.MarshalIndent(output, "", "  ")
	must(err)
	must(os.WriteFile(proofOut, encoded, 0o644))
	fixture := fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

library Groth16SmokeFixture {
    bytes32 internal constant POLICY_COMMITMENT = %s;
    uint256 internal constant PROOF_TIMESTAMP = %d;
    bytes internal constant ACTION_DATA = hex"%s";
    bytes internal constant PROOF = hex"%s";
}
`,
		output.PolicyCommitment,
		output.CurrentTimestamp,
		strings.TrimPrefix(output.ActionData, "0x"),
		strings.TrimPrefix(output.Proof, "0x"),
	)
	if !*proofOnly {
		must(os.WriteFile(fixtureOut, []byte(fixture), 0o644))
	}

	provingKeySha256, err := sha256HexFile(pkPath)
	must(err)
	verifyingKeySha256, err := sha256HexFile(vkPath)
	must(err)
	if !*proofOnly {
		manifest := setupManifest{
			ProofVersion:         proofVersion,
			Backend:              "groth16",
			Curve:                "bn254",
			CommitmentHash:       "mimc",
			CommitmentVersion:    2,
			PublicInputCount:     13,
			ProofBytes:           256,
			ConstraintCount:      ccs.GetNbConstraints(),
			ProvingKeySha256:     provingKeySha256,
			VerifyingKeySha256:   verifyingKeySha256,
			VerifierSourceSha256: verifierSourceSha256,
			VerifierContract:     "Groth16Verifier",
			WrapperContract:      "Groth16AuthorizationVerifier",
		}
		manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
		must(err)
		must(os.WriteFile(manifestPath, append(manifestJSON, '\n'), 0o644))
		fmt.Printf("Groth16 verifier written to %s\n", contractOut)
		fmt.Printf("Groth16 setup manifest written to %s\n", manifestPath)
		fmt.Printf("Solidity smoke fixture written to %s\n", fixtureOut)
	}
	fmt.Printf("Groth16 setup keys loaded from %s\n", keyDir)
	fmt.Printf("Proving key SHA-256: %s\n", provingKeySha256)
	fmt.Printf("Verifying key SHA-256: %s\n", verifyingKeySha256)
	fmt.Printf("Verifier source SHA-256: %s\n", verifierSourceSha256)
	fmt.Printf("Proof artifact written to %s\n", proofOut)
	fmt.Printf("Constraints: %d\n", ccs.GetNbConstraints())
}

func loadProofData(witnessPath string) (proofData, error) {
	if witnessPath == "" {
		now := uint64(time.Now().Unix())
		data := proofData{
			ActionType:       0,
			Protocol:         [4]uint64{0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa},
			Token:            [4]uint64{0xbbbbbbbbbbbbbbbb, 0xbbbbbbbbbbbbbbbb, 0xbbbbbbbbbbbbbbbb, 0xbbbbbbbbbbbbbbbb},
			Value:            500,
			CurrentTimestamp: now,
			CumulativeSpend:  0,
			AllowedAction:    0,
			AllowedProtocol:  [4]uint64{0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa},
			AllowedToken:     [4]uint64{0xbbbbbbbbbbbbbbbb, 0xbbbbbbbbbbbbbbbb, 0xbbbbbbbbbbbbbbbb, 0xbbbbbbbbbbbbbbbb},
			MaxValuePerTx:    1000,
			MaxValueTotal:    10000,
			ValidFrom:        now - 60,
			ValidUntil:       now + 86400,
		}
		return data, validateProofData(data)
	}

	encoded, err := os.ReadFile(witnessPath)
	if err != nil {
		return proofData{}, err
	}

	var input witnessFile
	if err := json.Unmarshal(encoded, &input); err != nil {
		return proofData{}, err
	}

	protocol, err := bytes32LimbsLE(input.Protocol, "protocol")
	if err != nil {
		return proofData{}, err
	}
	token, err := bytes32LimbsLE(input.Token, "token")
	if err != nil {
		return proofData{}, err
	}
	allowedProtocol, err := bytes32LimbsLE(input.AllowedProtocol, "allowedProtocol")
	if err != nil {
		return proofData{}, err
	}
	allowedToken, err := bytes32LimbsLE(input.AllowedToken, "allowedToken")
	if err != nil {
		return proofData{}, err
	}

	data := proofData{
		ActionType:       uint64(input.ActionType),
		Protocol:         protocol,
		Token:            token,
		Value:            uint64(input.Value),
		CurrentTimestamp: uint64(input.CurrentTimestamp),
		CumulativeSpend:  uint64(input.CumulativeSpend),
		AllowedAction:    uint64(input.AllowedAction),
		AllowedProtocol:  allowedProtocol,
		AllowedToken:     allowedToken,
		MaxValuePerTx:    uint64(input.MaxValuePerTx),
		MaxValueTotal:    uint64(input.MaxValueTotal),
		ValidFrom:        uint64(input.ValidFrom),
		ValidUntil:       uint64(input.ValidUntil),
	}
	return data, validateProofData(data)
}

func validateProofData(data proofData) error {
	if data.ActionType > 3 {
		return fmt.Errorf("actionType must be between 0 and 3")
	}
	if data.AllowedAction > 3 {
		return fmt.Errorf("allowedAction must be between 0 and 3")
	}
	if data.ActionType != data.AllowedAction {
		return fmt.Errorf("actionType must equal allowedAction")
	}
	if data.Protocol != data.AllowedProtocol {
		return fmt.Errorf("protocol must equal allowedProtocol")
	}
	if data.Token != data.AllowedToken {
		return fmt.Errorf("token must equal allowedToken")
	}
	if data.Value == 0 {
		return fmt.Errorf("value must be greater than zero")
	}
	if data.Value > data.MaxValuePerTx {
		return fmt.Errorf("value must be less than or equal to maxValuePerTx")
	}
	if data.CumulativeSpend > data.MaxValueTotal || data.Value > data.MaxValueTotal-data.CumulativeSpend {
		return fmt.Errorf("cumulativeSpend + value must be less than or equal to maxValueTotal")
	}
	if data.ValidFrom > data.CurrentTimestamp {
		return fmt.Errorf("validFrom must be less than or equal to currentTimestamp")
	}
	if data.CurrentTimestamp > data.ValidUntil {
		return fmt.Errorf("currentTimestamp must be less than or equal to validUntil")
	}
	return nil
}

func bytes32LimbsLE(value string, field string) ([4]uint64, error) {
	var limbs [4]uint64
	if !strings.HasPrefix(value, "0x") {
		return limbs, fmt.Errorf("%s must be 0x-prefixed bytes32", field)
	}
	clean := strings.TrimPrefix(value, "0x")
	if len(clean) != 64 {
		return limbs, fmt.Errorf("%s must be 32 bytes", field)
	}
	bytes, err := hex.DecodeString(clean)
	if err != nil {
		return limbs, fmt.Errorf("%s must be hex: %w", field, err)
	}
	for limb := 0; limb < 4; limb++ {
		for i := 0; i < 8; i++ {
			limbs[limb] |= uint64(bytes[limb*8+i]) << (8 * i)
		}
	}
	return limbs, nil
}

func loadOrCreateKeys(ccs constraint.ConstraintSystem, pkPath, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	reset := os.Getenv("CATP_GROTH16_RESET_SETUP") == "1"
	requireKeys := os.Getenv("CATP_GROTH16_REQUIRE_KEYS") == "1"
	if !reset {
		if _, err := os.Stat(pkPath); err == nil {
			if _, err := os.Stat(vkPath); err == nil {
				pk := groth16.NewProvingKey(ecc.BN254)
				vk := groth16.NewVerifyingKey(ecc.BN254)

				pkFile, err := os.Open(pkPath)
				if err != nil {
					return nil, nil, err
				}
				defer pkFile.Close()
				if _, err := pk.ReadFrom(pkFile); err != nil {
					return nil, nil, err
				}

				vkFile, err := os.Open(vkPath)
				if err != nil {
					return nil, nil, err
				}
				defer vkFile.Close()
				if _, err := vk.ReadFrom(vkFile); err != nil {
					return nil, nil, err
				}

				return pk, vk, nil
			}
		}
	}

	if requireKeys {
		return nil, nil, fmt.Errorf("missing persisted Groth16 setup keys for %s; refusing to create a new setup with CATP_GROTH16_REQUIRE_KEYS=1", proofVersion)
	}

	if reset && os.Getenv("CATP_GROTH16_ALLOW_RESET") != "1" {
		return nil, nil, fmt.Errorf("CATP_GROTH16_RESET_SETUP=1 requires CATP_GROTH16_ALLOW_RESET=1")
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, err
	}

	pkFile, err := os.Create(pkPath)
	if err != nil {
		return nil, nil, err
	}
	if _, err := pk.WriteTo(pkFile); err != nil {
		_ = pkFile.Close()
		return nil, nil, err
	}
	if err := pkFile.Close(); err != nil {
		return nil, nil, err
	}

	vkFile, err := os.Create(vkPath)
	if err != nil {
		return nil, nil, err
	}
	if _, err := vk.WriteTo(vkFile); err != nil {
		_ = vkFile.Close()
		return nil, nil, err
	}
	if err := vkFile.Close(); err != nil {
		return nil, nil, err
	}

	return pk, vk, nil
}

func sha256HexFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func sha256HexBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
