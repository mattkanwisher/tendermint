package fnConsensus

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/types"

	dbm "github.com/tendermint/tendermint/libs/db"

	"crypto/sha512"
)

const FnVoteSetChannel = byte(0x50)
const FnVoteSetMaj23Channel = byte(0x51)

const StartingNonce int64 = 1

// Max message size 1 MB
const maxMsgSize = 1000 * 1024

const ProgressIntervalInSeconds int64 = 120
const DefaultValidityPeriod = 119 * time.Second

// Max context size 1 KB
const MaxContextSize = 1024

type FnConsensusReactor struct {
	p2p.BaseReactor

	connectedPeers map[p2p.ID]p2p.Peer
	state          *ReactorState
	db             dbm.DB
	tmStateDB      dbm.DB
	chainID        string

	fnRegistry FnRegistry

	privValidator types.PrivValidator

	peerMapMtx sync.RWMutex

	stateMtx sync.Mutex
}

func NewFnConsensusReactor(chainID string, privValidator types.PrivValidator, fnRegistry FnRegistry, db dbm.DB, tmStateDB dbm.DB) *FnConsensusReactor {
	reactor := &FnConsensusReactor{
		connectedPeers: make(map[p2p.ID]p2p.Peer),
		db:             db,
		chainID:        chainID,
		tmStateDB:      tmStateDB,
		fnRegistry:     fnRegistry,
		privValidator:  privValidator,
	}

	reactor.BaseReactor = *p2p.NewBaseReactor("FnConsensusReactor", reactor)
	return reactor
}

func (f *FnConsensusReactor) String() string {
	return "FnConsensusReactor"
}

func (f *FnConsensusReactor) OnStart() error {
	reactorState, err := LoadReactorState(f.db)
	if err != nil {
		return err
	}
	f.state = reactorState
	go f.progressRoutine()
	return nil
}

// GetChannels returns the list of channel descriptors.
func (f *FnConsensusReactor) GetChannels() []*p2p.ChannelDescriptor {
	// Priorities are deliberately set to low, to prevent interfering with core TM
	return []*p2p.ChannelDescriptor{
		{
			ID:                  FnVoteSetChannel,
			Priority:            25,
			SendQueueCapacity:   100,
			RecvMessageCapacity: maxMsgSize,
		},
		{
			ID:                  FnVoteSetMaj23Channel,
			Priority:            26,
			SendQueueCapacity:   100,
			RecvMessageCapacity: maxMsgSize,
		},
	}
}

// AddPeer is called by the switch when a new peer is added.
func (f *FnConsensusReactor) AddPeer(peer p2p.Peer) {
	f.peerMapMtx.Lock()
	defer f.peerMapMtx.Unlock()
	f.connectedPeers[peer.ID()] = peer
}

// RemovePeer is called by the switch when the peer is stopped (due to error
// or other reason).
func (f *FnConsensusReactor) RemovePeer(peer p2p.Peer, reason interface{}) {
	f.peerMapMtx.Lock()
	defer f.peerMapMtx.Unlock()
	delete(f.connectedPeers, peer.ID())
}

func (f *FnConsensusReactor) areWeValidator(currentValidatorSet *types.ValidatorSet) (bool, int) {
	validatorIndex, _ := currentValidatorSet.GetByAddress(f.privValidator.GetPubKey().Address())
	return validatorIndex != -1, validatorIndex
}

func (f *FnConsensusReactor) calculateMessageHash(message []byte) ([]byte, error) {
	hash := sha512.New()
	_, err := hash.Write(message)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (f *FnConsensusReactor) progressRoutine() {

OUTER_LOOP:
	for {
		// Align to minutes, to make sure this routine runs at almost same time across all nodes
		// Not strictly required
		currentEpochTime := time.Now().Unix()
		timeToSleep := int64(ProgressIntervalInSeconds - currentEpochTime%ProgressIntervalInSeconds)
		timer := time.NewTimer(time.Duration(timeToSleep) * time.Second)

		select {
		case <-f.Quit():
			timer.Stop()
			break OUTER_LOOP
		case <-timer.C:
			var areWeAllowedToPropose bool

			currentState := state.LoadState(f.tmStateDB)
			areWeValidator, ownValidatorIndex := f.areWeValidator(currentState.Validators)

			proposer := currentState.Validators.GetProposer()
			if proposer == nil {
				f.Logger.Error("FnConsensusReactor: unable to get proposer from current validators")
				break
			}

			proposerIndex, _ := currentState.Validators.GetByAddress(proposer.Address)

			if areWeValidator && proposerIndex == ownValidatorIndex {
				areWeAllowedToPropose = true
			} else {
				areWeAllowedToPropose = false
			}

			f.stateMtx.Lock()

			fnIDs := f.fnRegistry.GetAll()
			sort.Strings(fnIDs)

			fnsEligibleForProposal := make([]string, 0, len(fnIDs))

			for _, fnID := range fnIDs {
				currentVoteState := f.state.CurrentVoteSets[fnID]
				if currentVoteState != nil {
					if currentVoteState.IsExpired(DefaultValidityPeriod) {
						f.state.PreviousTimedOutVoteSets[fnID] = f.state.CurrentVoteSets[fnID]
						delete(f.state.CurrentVoteSets, fnID)
						f.Logger.Error("FnConsensusReactor: unable to propose, archiving expired Fn execution", "FnID", fnID)
					} else {
						f.Logger.Error("FnConsensusReactor: unable to propose, previous execution is still pending", "FnID", fnID)
					}
					continue
				}
				fnsEligibleForProposal = append(fnsEligibleForProposal, fnID)
			}

			if err := SaveReactorState(f.db, f.state, true); err != nil {
				f.Logger.Error("FnConsensusReactor: unable to save reactor state")
				f.stateMtx.Unlock()
				break
			}

			f.stateMtx.Unlock()

			if !areWeAllowedToPropose {
				break
			}

			for _, fnID := range fnsEligibleForProposal {
				fn := f.fnRegistry.Get(fnID)
				f.propose(fnID, fn, currentState, ownValidatorIndex)
			}

		}
	}
}

func (f *FnConsensusReactor) propose(fnID string, fn Fn, currentState state.State, validatorIndex int) {
	ctx, err := fn.PrepareContext()
	if err != nil {
		f.Logger.Error("FnConsensusReactor: received error while executing fn.PrepareContext", "error", err)
		return
	}

	if len(ctx) > MaxContextSize {
		f.Logger.Error("FnConsensusReactor: context cannot be more than", "MaxContextSize", MaxContextSize)
		return
	}

	message, signature, err := fn.GetMessageAndSignature(safeCopyBytes(ctx))
	if err != nil {
		f.Logger.Error("FnConsensusReactor: received error while executing fn.GetMessageAndSignature", "fnID", fnID)
		return
	}

	hash, err := f.calculateMessageHash(message)
	if err != nil {
		f.Logger.Error("FnConsensusReactor: unable to calculate message hash", "fnID", fnID, "error", err)
		return
	}

	if err = fn.MapMessage(safeCopyBytes(ctx), safeCopyBytes(hash), safeCopyBytes(message)); err != nil {
		f.Logger.Error("FnConsensusReactor: received error while executing fn.MapMessage", "fnID", fnID, "error", err)
		return
	}

	executionRequest, err := NewFnExecutionRequest(fnID, f.fnRegistry)
	if err != nil {
		f.Logger.Error("FnConsensusReactor: unable to create Fn execution request as FnID is invalid", "fnID", fnID)
		return
	}

	executionResponse := NewFnExecutionResponse(&FnIndividualExecutionResponse{
		Error:           "",
		Hash:            hash,
		OracleSignature: signature,
		Status:          0,
	}, validatorIndex, currentState.Validators)

	votesetPayload := NewFnVotePayload(executionRequest, executionResponse)

	f.stateMtx.Lock()

	voteSet, err := NewVoteSet(f.chainID, DefaultValidityPeriod, validatorIndex, ctx,
		votesetPayload, f.privValidator, currentState.Validators)
	if err != nil {
		f.Logger.Error("FnConsensusReactor: unable to create new voteset", "fnID", fnID, "error", err)
		return
	}

	// It seems we are the only validator, so return the signature and close the case.
	if voteSet.IsMaj23(currentState.Validators) {
		fn.SubmitMultiSignedMessage(safeCopyBytes(ctx),
			safeCopyBytes(voteSet.Payload.Response.Hash),
			safeCopyDoubleArray(voteSet.Payload.Response.OracleSignatures))
		f.stateMtx.Unlock()
		return
	}

	f.state.CurrentVoteSets[fnID] = voteSet

	if err := SaveReactorState(f.db, f.state, true); err != nil {
		f.Logger.Error("FnConsensusReactor: unable to save state", "fnID", fnID, "error", err)
		f.stateMtx.Unlock()
		return
	}

	f.stateMtx.Unlock()

	marshalledBytes, err := voteSet.Marshal()
	if err != nil {
		f.Logger.Error(fmt.Sprintf("FnConsensusReactor: Unable to marshal currentVoteSet at FnID: %s", fnID))
		return
	}

	f.peerMapMtx.RLock()
	for _, peer := range f.connectedPeers {
		go func() {
			// TODO: Handle timeout
			peer.Send(FnVoteSetChannel, marshalledBytes)
		}()
	}
	f.peerMapMtx.RUnlock()
}

func (f *FnConsensusReactor) handleVoteSetChannelMessage(sender p2p.Peer, msgBytes []byte) {
	currentState := state.LoadState(f.tmStateDB)
	areWeValidator, validatorIndex := f.areWeValidator(currentState.Validators)
	var err error

	f.stateMtx.Lock()
	defer f.stateMtx.Unlock()

	remoteVoteSet := &FnVoteSet{}
	if err := remoteVoteSet.Unmarshal(msgBytes); err != nil {
		f.Logger.Error("FnConsensusReactor: Invalid Data passed, ignoring...")
		return
	}

	if !remoteVoteSet.IsValid(f.chainID, MaxContextSize, DefaultValidityPeriod, currentState.Validators, f.fnRegistry) {
		f.Logger.Error("FnConsensusReactor: Invalid VoteSet specified, ignoring...")
		return
	}

	if remoteVoteSet.IsMaj23(currentState.Validators) {
		f.Logger.Error("FnConsensusReactor: Protocol violation: Received VoteSet with majority of validators signed, Ignoring...")
		return
	}

	var didWeContribute, hasOurVoteSetChanged bool
	fnID := remoteVoteSet.GetFnID()
	fn := f.fnRegistry.Get(fnID)
	var currentVoteSet *FnVoteSet

	// TODO: Check nonce with mainnet before accepting remote vote set

	if f.state.CurrentVoteSets[fnID] == nil {
		f.state.CurrentVoteSets[fnID] = remoteVoteSet
		// We didnt contribute but, our voteset changed
		didWeContribute = false
		hasOurVoteSetChanged = true
	} else {
		if didWeContribute, err = f.state.CurrentVoteSets[fnID].Merge(remoteVoteSet); err != nil {
			f.Logger.Error("FnConsensusReactor: Unable to merge remote vote set into our own.", "error:", err)
			return
		}
		hasOurVoteSetChanged = didWeContribute
	}

	// Taking a pointer to current local vote set
	currentVoteSet = f.state.CurrentVoteSets[fnID]

	if areWeValidator {
		message, signature, err := fn.GetMessageAndSignature(safeCopyBytes(currentVoteSet.ExecutionContext))
		if err != nil {
			f.Logger.Error("FnConsensusReactor: fn.GetMessageAndSignature returned an error, ignoring..")
			return
		}

		hash, err := f.calculateMessageHash(message)
		if err != nil {
			f.Logger.Error("FnConsensusReactor: unable to calculate message hash", "fnID", fnID, "error", err)
			return
		}

		if err = fn.MapMessage(safeCopyBytes(currentVoteSet.ExecutionContext), safeCopyBytes(hash), safeCopyBytes(message)); err != nil {
			f.Logger.Error("FnConsensusReactor: received error while executing fn.MapMessage", "fnID", fnID, "error", err)
			return
		}

		err = currentVoteSet.AddVote(&FnIndividualExecutionResponse{
			Status:          0,
			Error:           "",
			Hash:            hash,
			OracleSignature: signature,
		}, currentState.Validators, validatorIndex, f.privValidator)
		if err != nil {
			f.Logger.Error("FnConsensusError: unable to add vote to current voteset, ignoring...")
			return
		}

		didWeContribute = true
		hasOurVoteSetChanged = true
	}

	haveWeAchievedMaj23 := currentVoteSet.IsMaj23(currentState.Validators)

	if haveWeAchievedMaj23 {
		fn.SubmitMultiSignedMessage(safeCopyBytes(currentVoteSet.ExecutionContext),
			safeCopyBytes(currentVoteSet.Payload.Response.Hash),
			safeCopyDoubleArray(currentVoteSet.Payload.Response.OracleSignatures))

		f.state.PreviousMaj23VoteSets[fnID] = currentVoteSet
		delete(f.state.CurrentVoteSets, fnID)
	}

	if err := SaveReactorState(f.db, f.state, true); err != nil {
		f.Logger.Error("FnConsensusReactor: unable to save state", "fnID", fnID, "error", err)
		return
	}

	// If our vote havent't changed, no need to annonce it, as
	// we would have already annonunced it last time it changed
	// This could mean no new additions happened on our existing voteset, and
	// by logic other flags also will be false
	if !hasOurVoteSetChanged {
		return
	}

	marshalledBytes, err := currentVoteSet.Marshal()
	if err != nil {
		f.Logger.Error(fmt.Sprintf("FnConsensusReactor: Unable to marshal currentVoteSet at FnID: %s", fnID))
		return
	}

	f.peerMapMtx.RLock()
	for peerID, peer := range f.connectedPeers {

		// If we didnt contribute to remote vote, no need to pass it to sender
		// If this is false, then we must not have achieved Maj23
		if !didWeContribute {
			if peerID == sender.ID() {
				continue
			}
		}

		go func() {
			// TODO: Handle timeout
			if haveWeAchievedMaj23 {
				peer.Send(FnVoteSetMaj23Channel, marshalledBytes)
			} else {
				peer.Send(FnVoteSetChannel, marshalledBytes)
			}
		}()
	}
	f.peerMapMtx.RUnlock()
}

func (f *FnConsensusReactor) handleVoteSetMaj23UpdateMessage(sender p2p.Peer, msgBytes []byte) {
	currentState := state.LoadState(f.tmStateDB)

	remoteMaj23VoteSet := &FnVoteSet{}
	if err := remoteMaj23VoteSet.Unmarshal(msgBytes); err != nil {
		f.Logger.Error("FnConsensusReactor: Invalid Data passed, ignoring...")
		return
	}

	if !remoteMaj23VoteSet.IsValid(f.chainID, MaxContextSize, DefaultValidityPeriod, currentState.Validators, f.fnRegistry) {
		f.Logger.Error("FnConsensusReactor: Invalid Maj23 voteset passed, Ignoring...")
		return
	}

	if !remoteMaj23VoteSet.IsMaj23(currentState.Validators) {
		f.Logger.Error("FnConsensusReactor: Protocol violation, expected Maj23 voteset")
		return
	}

	f.stateMtx.Lock()
	defer f.stateMtx.Unlock()

	remoteFnID := remoteMaj23VoteSet.GetFnID()

	// What we have here is probably either invalid or subset of remote voteset
	delete(f.state.CurrentVoteSets, remoteFnID)

	// File away Previous Maj23 voteset to help our fellow peers
	f.state.PreviousMaj23VoteSets[remoteFnID] = remoteMaj23VoteSet

	if err := SaveReactorState(f.db, f.state, true); err != nil {
		f.Logger.Error("FnConsensusReactor: unable to save state", "error", err)
	}

	// Can't use msgBytes outside of this function without copying it
	copiedMsgBytes := make([]byte, len(msgBytes))
	copy(copiedMsgBytes, msgBytes)

	f.peerMapMtx.RLock()
	for peerID, peer := range f.connectedPeers {

		if peerID == sender.ID() {
			continue
		}

		go func() {
			// TODO: Handle timeout
			peer.Send(FnVoteSetMaj23Channel, copiedMsgBytes)
		}()
	}
	f.peerMapMtx.RUnlock()

}

// Receive is called when msgBytes is received from peer.
//
// NOTE reactor can not keep msgBytes around after Receive completes without
// copying.
//
// CONTRACT: msgBytes are not nil.
func (f *FnConsensusReactor) Receive(chID byte, sender p2p.Peer, msgBytes []byte) {

	switch chID {
	case FnVoteSetChannel:
		f.handleVoteSetChannelMessage(sender, msgBytes)
		break
	case FnVoteSetMaj23Channel:
		f.handleVoteSetMaj23UpdateMessage(sender, msgBytes)
		break
	default:
		f.Logger.Error("FnConsensusReactor: Unknown channel: %v", chID)
	}
}
