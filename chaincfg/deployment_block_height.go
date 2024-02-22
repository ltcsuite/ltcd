package chaincfg

import (
	"github.com/ltcsuite/ltcd/wire"
)

// BlockHeightDeploymentStarter is a ConsensusDeploymentStarter
// that uses block height to determine if a deployment has started.
type BlockHeightDeploymentStarter struct {
	startHeight int32
}

// NewBlockHeightDeploymentStarter returns a new instance of a
// BlockHeightDeploymentStarter for a given block height.
func NewBlockHeightDeploymentStarter(startHeight int32) *BlockHeightDeploymentStarter {
	return &BlockHeightDeploymentStarter{
		startHeight: startHeight,
	}
}

// HasStarted returns true if the consensus deployment has started.
func (b *BlockHeightDeploymentStarter) HasStarted(
	blkHeader *wire.BlockHeader, blkHeight int32) (bool, error) {

	return b.startHeight <= blkHeight, nil
}

// StartHeight returns the raw start block height of the deployment.
func (b *BlockHeightDeploymentStarter) StartHeight() int32 {
	return b.startHeight
}

// A compile-time assertion to ensure BlockHeightDeploymentStarter
// implements the ConsensusDeploymentStarter interface.
var _ ConsensusDeploymentStarter = (*BlockHeightDeploymentStarter)(nil)

// BlockHeightDeploymentEnder is a ConsensusDeploymentEnder that uses
// block height to determine if a deployment has ended.
type BlockHeightDeploymentEnder struct {
	endHeight int32
}

// NewBlockHeightDeploymentEnder returns a new instance of the
// BlockHeightDeploymentEnder for a given block height.
func NewBlockHeightDeploymentEnder(endHeight int32) *BlockHeightDeploymentEnder {
	return &BlockHeightDeploymentEnder{
		endHeight: endHeight,
	}
}

// HasEnded returns true if the deployment has ended.
func (b *BlockHeightDeploymentEnder) HasEnded(
	blkHeader *wire.BlockHeader, blkHeight int32) (bool, error) {

	return b.endHeight <= blkHeight, nil
}

// EndHeight returns the raw end block height of the deployment.
func (b *BlockHeightDeploymentEnder) EndHeight() int32 {
	return b.endHeight
}

// A compile-time assertion to ensure BlockHeightDeploymentEnder
// implements the ConsensusDeploymentEnder interface.
var _ ConsensusDeploymentEnder = (*BlockHeightDeploymentEnder)(nil)
