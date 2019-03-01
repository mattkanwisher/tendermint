package mempool

import (
	"github.com/tendermint/tendermint/types"
)

type MempoolTxInfo struct {
	types.Tx `json:"tx"`
	Height   int64 `json:"height"`
}
