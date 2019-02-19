package fnConsensus

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/tendermint/tendermint/crypto"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/types"
)

var ErrFnVoteInvalidValidatorAddress = errors.New("invalid validator address for FnVote")
var ErrFnVoteInvalidSignature = errors.New("invalid validator signature")
var ErrFnVoteNotPresent = errors.New("Fn vote is not present for validator")
var ErrFnVoteAlreadyCasted = errors.New("Fn vote is already casted")
var ErrFnResponseSignatureAlreadyPresent = errors.New("Fn Response signature is already present")

var ErrFnVoteMergeDiffPayload = errors.New("merging is not allowed, as votes have different payload")

type FnIndividualExecutionResponse struct {
	Status          int64
	Error           string
	Hash            []byte
	OracleSignature []byte
}

func (f *FnIndividualExecutionResponse) Marshal() ([]byte, error) {
	return cdc.MarshalBinaryLengthPrefixed(f)
}

type reactorSetMarshallable struct {
	CurrentVoteSets          []*FnVoteSet
	PreviousTimedOutVoteSets []*FnVoteSet
	PreviousMaj23VoteSets    []*FnVoteSet
}

type ReactorState struct {
	CurrentVoteSets          map[string]*FnVoteSet
	PreviousTimedOutVoteSets map[string]*FnVoteSet
	PreviousMaj23VoteSets    map[string]*FnVoteSet
}

func (p *ReactorState) Marshal() ([]byte, error) {
	reactorStateMarshallable := &reactorSetMarshallable{
		CurrentVoteSets:          make([]*FnVoteSet, len(p.CurrentVoteSets)),
		PreviousTimedOutVoteSets: make([]*FnVoteSet, len(p.PreviousTimedOutVoteSets)),
		PreviousMaj23VoteSets:    make([]*FnVoteSet, len(p.PreviousMaj23VoteSets)),
	}

	i := 0
	for _, voteSet := range p.CurrentVoteSets {
		reactorStateMarshallable.CurrentVoteSets[i] = voteSet
		i++
	}

	i = 0
	for _, timedOutVoteSet := range p.PreviousTimedOutVoteSets {
		reactorStateMarshallable.PreviousTimedOutVoteSets[i] = timedOutVoteSet
		i++
	}

	i = 0
	for _, maj23VoteSet := range p.PreviousMaj23VoteSets {
		reactorStateMarshallable.PreviousMaj23VoteSets[i] = maj23VoteSet
		i++
	}

	return cdc.MarshalBinaryLengthPrefixed(reactorStateMarshallable)
}

func (p *ReactorState) Unmarshal(bz []byte) error {
	reactorStateMarshallable := &reactorSetMarshallable{}
	if err := cdc.UnmarshalBinaryLengthPrefixed(bz, reactorStateMarshallable); err != nil {
		return err
	}

	p.CurrentVoteSets = make(map[string]*FnVoteSet)
	p.PreviousTimedOutVoteSets = make(map[string]*FnVoteSet)
	p.PreviousMaj23VoteSets = make(map[string]*FnVoteSet)

	for _, voteSet := range reactorStateMarshallable.CurrentVoteSets {
		p.CurrentVoteSets[voteSet.Payload.Request.FnID] = voteSet
	}

	for _, timeOutVoteSet := range reactorStateMarshallable.PreviousTimedOutVoteSets {
		p.PreviousTimedOutVoteSets[timeOutVoteSet.Payload.Request.FnID] = timeOutVoteSet
	}

	for _, maj23VoteSet := range reactorStateMarshallable.PreviousMaj23VoteSets {
		p.PreviousMaj23VoteSets[maj23VoteSet.Payload.Request.FnID] = maj23VoteSet
	}

	return nil
}

func NewReactorState(nonce int64, payload *FnVotePayload, valSet *types.ValidatorSet) *ReactorState {
	return &ReactorState{
		CurrentVoteSets:          make(map[string]*FnVoteSet),
		PreviousTimedOutVoteSets: make(map[string]*FnVoteSet),
		PreviousMaj23VoteSets:    make(map[string]*FnVoteSet),
	}
}

type fnIDToNonce struct {
	FnID  string
	Nonce int64
}

type FnExecutionRequest struct {
	FnID string
}

func (f *FnExecutionRequest) Marshal() ([]byte, error) {
	return cdc.MarshalBinaryLengthPrefixed(f)
}

func (f *FnExecutionRequest) Unmarshal(bz []byte) error {
	return cdc.UnmarshalBinaryLengthPrefixed(bz, f)
}

func (f *FnExecutionRequest) CannonicalCompare(remoteRequest *FnExecutionRequest) bool {
	return f.FnID != remoteRequest.FnID
}

func (f *FnExecutionRequest) Compare(remoteRequest *FnExecutionRequest) bool {
	return f.CannonicalCompare(remoteRequest)
}

func (f *FnExecutionRequest) SignBytes() ([]byte, error) {
	return f.Marshal()
}

func NewFnExecutionRequest(fnID string, registry FnRegistry) (*FnExecutionRequest, error) {
	if registry.Get(fnID) == nil {
		return nil, fmt.Errorf("fnConsensusReactor: unable to create FnExecutionRequest as id is invalid")
	}

	return &FnExecutionRequest{
		FnID: fnID,
	}, nil
}

type FnExecutionResponse struct {
	Status int64
	Error  string
	Hash   []byte
	// Indexed by validator index in Current validator set
	OracleSignatures [][]byte
}

func (f *FnExecutionResponse) Marshal() ([]byte, error) {
	return cdc.MarshalBinaryLengthPrefixed(f)
}

func (f *FnExecutionResponse) Unmarshal(bz []byte) error {
	return cdc.UnmarshalBinaryLengthPrefixed(bz, f)
}

func (f *FnExecutionResponse) IsValid(currentValidatorSet *types.ValidatorSet) bool {
	if f.Hash == nil {
		return false
	}

	if currentValidatorSet.Size() != len(f.OracleSignatures) {
		return false
	}

	return true
}

func (f *FnExecutionResponse) CannonicalCompare(remoteResponse *FnExecutionResponse) bool {
	if f.Error != remoteResponse.Error {
		return false
	}

	if f.Status != remoteResponse.Status {
		return false
	}

	if bytes.Compare(f.Hash, remoteResponse.Hash) != 0 {
		return false
	}

	if len(f.OracleSignatures) != len(remoteResponse.OracleSignatures) {
		return false
	}

	return true
}

func (f *FnExecutionResponse) CannonicalCompareWithIndividualExecution(individualExecution *FnIndividualExecutionResponse) bool {
	if f.Status != individualExecution.Status || f.Error != individualExecution.Error || bytes.Compare(f.Hash, individualExecution.Hash) != 0 {
		return false
	}

	return true
}

func (f *FnExecutionResponse) SignBytes(validatorIndex int) ([]byte, error) {
	individualResponse := &FnIndividualExecutionResponse{
		Status:          f.Status,
		Error:           f.Error,
		Hash:            f.Hash,
		OracleSignature: f.OracleSignatures[validatorIndex],
	}

	return individualResponse.Marshal()
}

func (f *FnExecutionResponse) Compare(remoteResponse *FnExecutionResponse) bool {
	if !f.CannonicalCompare(remoteResponse) {
		return false
	}

	for i := 0; i < len(f.OracleSignatures); i++ {
		if bytes.Compare(f.OracleSignatures[i], remoteResponse.OracleSignatures[i]) != 0 {
			return false
		}
	}

	return true
}

func (f *FnExecutionResponse) AddSignature(validatorIndex int, signature []byte) error {
	if f.OracleSignatures[validatorIndex] != nil {
		return ErrFnResponseSignatureAlreadyPresent
	}

	f.OracleSignatures[validatorIndex] = signature
	return nil
}

func NewFnExecutionResponse(individualResponse *FnIndividualExecutionResponse, validatorIndex int, valSet *types.ValidatorSet) *FnExecutionResponse {
	newFnExecutionResponse := &FnExecutionResponse{
		Status: individualResponse.Status,
		Error:  individualResponse.Error,
		Hash:   individualResponse.Hash,
	}

	newFnExecutionResponse.OracleSignatures = make([][]byte, valSet.Size())
	newFnExecutionResponse.OracleSignatures[validatorIndex] = individualResponse.OracleSignature

	return newFnExecutionResponse
}

type FnVotePayload struct {
	Request  *FnExecutionRequest  `json:"fn_execution_request"`
	Response *FnExecutionResponse `json:"fn_execution_response"`
}

func (f *FnVotePayload) Marshal() ([]byte, error) {
	return cdc.MarshalBinaryLengthPrefixed(f)
}

func (f *FnVotePayload) Unmarshal(bz []byte) error {
	return cdc.UnmarshalBinaryLengthPrefixed(bz, f)
}

func (f *FnVotePayload) IsValid(currentValidatorSet *types.ValidatorSet) bool {
	if f.Request == nil || f.Response == nil {
		return false
	}

	if !f.Response.IsValid(currentValidatorSet) {
		return false
	}

	return true
}

func (f *FnVotePayload) CannonicalCompare(remotePayload *FnVotePayload) bool {
	if remotePayload == nil || remotePayload.Request == nil || remotePayload.Response == nil {
		return false
	}

	if !f.Request.CannonicalCompare(remotePayload.Request) {
		return false
	}

	if !f.Response.CannonicalCompare(remotePayload.Response) {
		return false
	}

	return true
}

func (f *FnVotePayload) Compare(remotePayload *FnVotePayload) bool {
	if remotePayload == nil || remotePayload.Request == nil || remotePayload.Response == nil {
		return false
	}

	if !f.Request.Compare(remotePayload.Request) {
		return false
	}

	if !f.Response.Compare(remotePayload.Response) {
		return false
	}

	return true
}

func (f *FnVotePayload) SignBytes(validatorIndex int) ([]byte, error) {
	requestSignBytes, err := f.Request.SignBytes()
	if err != nil {
		return nil, err
	}

	responseSignBytes, err := f.Response.SignBytes(validatorIndex)
	if err != nil {
		return nil, err
	}

	sepearator := []byte{0x50}

	signBytes := make([]byte, len(requestSignBytes)+len(responseSignBytes)+len(sepearator))

	copy(signBytes, requestSignBytes)
	copy(signBytes[len(requestSignBytes):], sepearator)
	copy(signBytes[len(requestSignBytes)+len(sepearator):], responseSignBytes)

	return signBytes, nil
}

func NewFnVotePayload(fnRequest *FnExecutionRequest, fnResponse *FnExecutionResponse) *FnVotePayload {
	return &FnVotePayload{
		Request:  fnRequest,
		Response: fnResponse,
	}
}

type FnVoteSet struct {
	ChainID             string         `json:"chain_id"`
	TotalVotingPower    int64          `json:"total_voting_power"`
	CreationTime        int64          `json:"creation_time"`
	VoteBitArray        *cmn.BitArray  `json:"vote_bitarray"`
	Payload             *FnVotePayload `json:"vote_payload"`
	ExecutionContext    []byte         `json:"execution_context"`
	ValidatorSignatures [][]byte       `json:"signature"`
	ValidatorAddresses  [][]byte       `json:"validator_address"`
}

func NewVoteSet(chainID string, expiresIn time.Duration, validatorIndex int, executionContext []byte, initialPayload *FnVotePayload, privValidator types.PrivValidator, valSet *types.ValidatorSet) (*FnVoteSet, error) {
	voteBitArray := cmn.NewBitArray(valSet.Size())
	signatures := make([][]byte, valSet.Size())
	validatorAddresses := make([][]byte, valSet.Size())

	var totalVotingPower int64

	if !initialPayload.IsValid(valSet) {
		return nil, fmt.Errorf("fnConsensusReactor: unable to create new voteSet as initialPayload passed is invalid")
	}

	valSet.Iterate(func(index int, validator *types.Validator) bool {
		if index == validatorIndex {
			totalVotingPower = validator.VotingPower
		}
		validatorAddresses[index] = validator.Address
		return false
	})

	voteBitArray.SetIndex(validatorIndex, true)

	if totalVotingPower == 0 {
		return nil, fmt.Errorf("fnConsensusReactor: unable to create new voteset as validatorIndex is invalid")
	}

	newVoteSet := &FnVoteSet{
		ChainID:             chainID,
		TotalVotingPower:    totalVotingPower,
		CreationTime:        time.Now().Unix(),
		Payload:             initialPayload,
		VoteBitArray:        voteBitArray,
		ExecutionContext:    executionContext,
		ValidatorSignatures: signatures,
		ValidatorAddresses:  validatorAddresses,
	}

	signBytes, err := newVoteSet.SignBytes(validatorIndex)
	if err != nil {
		return nil, fmt.Errorf("fnConsesnusReactor: unable to create new voteset as not able to get signbytes")
	}

	signature, err := privValidator.Sign(signBytes)
	if err != nil {
		return nil, fmt.Errorf("fnConsensusReactor: unable to create new voteset as not able to sign initial payload")
	}

	signatures[validatorIndex] = signature

	return newVoteSet, nil
}

func (voteSet *FnVoteSet) Marshal() ([]byte, error) {
	return cdc.MarshalBinaryLengthPrefixed(voteSet)
}

func (voteSet *FnVoteSet) Unmarshal(bz []byte) error {
	return cdc.UnmarshalBinaryLengthPrefixed(bz, voteSet)
}

func (voteSet *FnVoteSet) CannonicalCompare(remoteVoteSet *FnVoteSet) bool {
	if remoteVoteSet.Payload == nil {
		return false
	}

	if !voteSet.Payload.CannonicalCompare(remoteVoteSet.Payload) {
		return false
	}

	if len(voteSet.ValidatorSignatures) != len(remoteVoteSet.ValidatorSignatures) {
		return false
	}

	// For misbehaving nodes
	if len(voteSet.ValidatorAddresses) != len(remoteVoteSet.ValidatorAddresses) {
		return false
	}

	if bytes.Compare(voteSet.ExecutionContext, remoteVoteSet.ExecutionContext) != 0 {
		return false
	}

	for i := 0; i < len(voteSet.ValidatorAddresses); i++ {
		if bytes.Compare(voteSet.ValidatorAddresses[i], remoteVoteSet.ValidatorAddresses[i]) != 0 {
			return false
		}
	}

	return true
}

func (voteSet *FnVoteSet) SignBytes(validatorIndex int) ([]byte, error) {
	payloadBytes, err := voteSet.Payload.SignBytes(validatorIndex)
	if err != nil {
		return nil, err
	}

	var seperator = []byte{17, 19, 23, 29}

	prefix := []byte(fmt.Sprintf("CT:%d|CD:%s|VA:%s|PL:", voteSet.CreationTime,
		voteSet.ChainID, voteSet.ValidatorAddresses[validatorIndex]))

	signBytes := make([]byte, len(prefix)+len(seperator)+len(voteSet.ExecutionContext)+len(seperator)+len(payloadBytes))

	numCopied := 0

	copy(signBytes[numCopied:], prefix)
	numCopied += len(prefix)

	copy(signBytes[numCopied:], seperator)
	numCopied += len(seperator)

	copy(signBytes[numCopied:], voteSet.ExecutionContext)
	numCopied += len(voteSet.ExecutionContext)

	copy(signBytes[numCopied:], seperator)
	numCopied += len(seperator)

	copy(signBytes[numCopied:], payloadBytes)
	numCopied += len(payloadBytes)

	return signBytes, nil
}

func (voteSet *FnVoteSet) VerifyValidatorSign(validatorIndex int, pubKey crypto.PubKey) error {
	if !voteSet.VoteBitArray.GetIndex(validatorIndex) {
		return ErrFnVoteNotPresent
	}

	return voteSet.verifyInternal(voteSet.ValidatorSignatures[validatorIndex], validatorIndex,
		voteSet.ValidatorAddresses[validatorIndex], pubKey)
}

func (voteSet *FnVoteSet) verifyInternal(signature []byte, validatorIndex int, validatorAddress []byte, pubKey crypto.PubKey) error {
	if !bytes.Equal(pubKey.Address(), validatorAddress) {
		return ErrFnVoteInvalidValidatorAddress
	}

	signBytes, err := voteSet.SignBytes(validatorIndex)
	if err != nil {
		return err
	}

	if !pubKey.VerifyBytes(signBytes, signature) {
		return ErrFnVoteInvalidSignature
	}
	return nil
}

func (voteSet *FnVoteSet) IsExpired(validityPeriod time.Duration) bool {
	creationTime := time.Unix(voteSet.CreationTime, 0)
	expiryTime := creationTime.Add(validityPeriod)

	return expiryTime.Before(time.Now().UTC())
}

func (voteSet *FnVoteSet) GetFnID() string {
	return voteSet.Payload.Request.FnID
}

func (voteSet *FnVoteSet) IsMaj23(currentValidatorSet *types.ValidatorSet) bool {
	return voteSet.TotalVotingPower >= currentValidatorSet.TotalVotingPower()*2/3+1
}

// Should be the first function to be invoked on vote set received from Peer
func (voteSet *FnVoteSet) IsValid(chainID string, maxContextSize int, validityPeriod time.Duration, currentValidatorSet *types.ValidatorSet, registry FnRegistry) bool {
	isValid := true
	numValidators := voteSet.VoteBitArray.Size()

	var calculatedVotingPower int64

	// This if conditions are individual as, we want to pass different errors for each
	// condition in future.

	if voteSet.Payload == nil {
		isValid = false
		return isValid
	}

	if !voteSet.Payload.IsValid(currentValidatorSet) {
		isValid = false
		return isValid
	}

	if registry.Get(voteSet.GetFnID()) == nil {
		isValid = false
		return isValid
	}

	if voteSet.ChainID != chainID {
		isValid = false
		return isValid
	}

	if voteSet.IsExpired(validityPeriod) {
		isValid = false
		return isValid
	}

	if numValidators != len(voteSet.ValidatorAddresses) || numValidators != len(voteSet.ValidatorSignatures) || numValidators != currentValidatorSet.Size() {
		isValid = false
		return isValid
	}

	if len(voteSet.ExecutionContext) > maxContextSize {
		isValid = false
		return isValid
	}

	currentValidatorSet.Iterate(func(i int, val *types.Validator) bool {
		if bytes.Compare(voteSet.ValidatorAddresses[i], val.Address) != 0 {
			isValid = false
			return true
		}

		if !voteSet.VoteBitArray.GetIndex(i) {
			return false
		}

		if err := voteSet.VerifyValidatorSign(i, val.PubKey); err != nil {
			isValid = false
			return true
		}
		calculatedVotingPower += val.VotingPower
		return false
	})

	// Voting power contained in VoteSet should match the calculated voting power
	if voteSet.TotalVotingPower != calculatedVotingPower {
		isValid = false
		return false
	}

	return isValid
}

func (voteSet *FnVoteSet) Merge(anotherSet *FnVoteSet) (bool, error) {
	hasChanged := false

	if !voteSet.CannonicalCompare(anotherSet) {
		return hasChanged, ErrFnVoteMergeDiffPayload
	}

	numValidators := voteSet.VoteBitArray.Size()

	for i := 0; i < numValidators; i++ {
		if voteSet.VoteBitArray.GetIndex(i) || !anotherSet.VoteBitArray.GetIndex(i) {
			continue
		}

		hasChanged = true

		voteSet.ValidatorSignatures[i] = anotherSet.ValidatorSignatures[i]
		voteSet.ValidatorAddresses[i] = anotherSet.ValidatorAddresses[i]
		voteSet.VoteBitArray.SetIndex(i, true)
	}

	return hasChanged, nil
}

func (voteSet *FnVoteSet) AddVote(individualExecutionResponse *FnIndividualExecutionResponse, currentValidatorSet *types.ValidatorSet, validatorIndex int, privValidator types.PrivValidator) error {
	if voteSet.VoteBitArray.GetIndex(validatorIndex) {
		return ErrFnVoteAlreadyCasted
	}

	if !voteSet.Payload.Response.CannonicalCompareWithIndividualExecution(individualExecutionResponse) {
		return fmt.Errorf("fnConsensusReactor: unable to add vote as execution responses are different")
	}

	if err := voteSet.Payload.Response.AddSignature(validatorIndex, individualExecutionResponse.OracleSignature); err != nil {
		return fmt.Errorf("fnConsesnusReactor: unable to add vote as can't add signature, Error: %s", err.Error())
	}

	signBytes, err := voteSet.SignBytes(validatorIndex)
	if err != nil {
		return fmt.Errorf("fnConsensusReactor: unable to add vote as unable to get sign bytes. Error: %s", err.Error())
	}

	signature, err := privValidator.Sign(signBytes)
	if err != nil {
		return fmt.Errorf("fnConsensusReactor: unable to add vote as unable to sign signing bytes. Error: %s", err.Error())
	}

	voteSet.VoteBitArray.SetIndex(validatorIndex, true)
	voteSet.ValidatorSignatures[validatorIndex] = signature

	_, validator := currentValidatorSet.GetByIndex(validatorIndex)
	if validator == nil {
		return fmt.Errorf("fnConsensusReactor: unable to add vote as validatorIndex is not valid")
	}

	if bytes.Compare(validator.Address, voteSet.ValidatorAddresses[validatorIndex]) != 0 {
		return fmt.Errorf("fnConsensusReactor: unable to add vote as validatorAddress does not match with one in the vote set")
	}

	voteSet.TotalVotingPower += validator.VotingPower

	return nil
}

func RegisterFnConsensusTypes() {
	cdc.RegisterConcrete(&FnExecutionRequest{}, "tendermint/fnConsensusReactor/FnExecutionRequest", nil)
	cdc.RegisterConcrete(&FnExecutionResponse{}, "tendermint/fnConsensusReactor/FnExecutionResponse", nil)
	cdc.RegisterConcrete(&FnVoteSet{}, "tendermint/fnConsensusReactor/FnVoteSet", nil)
	cdc.RegisterConcrete(&FnVotePayload{}, "tendermint/fnConsensusReactor/FnVotePayload", nil)
	cdc.RegisterConcrete(&FnIndividualExecutionResponse{}, "tendermint/fnConsensusReactor/FnIndividualExecutionResponse", nil)
	cdc.RegisterConcrete(&ReactorState{}, "tendermint/fnConsensusReactor/ReactorState", nil)
	cdc.RegisterConcrete(&reactorSetMarshallable{}, "tendermint/fnConsensusReactor/reactorSetMarshallable", nil)
	cdc.RegisterConcrete(&fnIDToNonce{}, "tendermint/fnConsensusReactor/fnIDToNonce", nil)
}
