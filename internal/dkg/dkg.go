package dkg

import (
	"encoding/hex"
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/bytemare/frost"
	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
)

type Participant struct {
	ID         uint16
	Threshold  int
	MaxSigners int
	group      ecc.Group
	polynomial secretsharing.Polynomial
}

type Commitment struct {
	ParticipantID uint16   `json:"participant_id"`
	Commitments   []string `json:"commitments"`
}

type SharePackage struct {
	FromID uint16 `json:"from_id"`
	ToID   uint16 `json:"to_id"`
	Share  string `json:"share"`
}

func NewParticipant(id uint16, threshold, maxSigners int) *Participant {
	cs := frost.Default
	g := cs.Group()
	return &Participant{
		ID:         id,
		Threshold:  threshold,
		MaxSigners: maxSigners,
		group:      g,
	}
}

func (p *Participant) Round1() (*Commitment, error) {
	coeffs := make([]*ecc.Scalar, p.Threshold)
	for i := 0; i < p.Threshold; i++ {
		c := p.group.NewScalar().Random()
		coeffs[i] = c
	}

	p.polynomial = secretsharing.Polynomial(coeffs)

	commitments := make([]string, p.Threshold)
	for i, coeff := range coeffs {
		point := p.group.Base().Multiply(coeff)
		encoded, err := point.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal point: %w", err)
		}
		commitments[i] = hex.EncodeToString(encoded)
	}

	return &Commitment{
		ParticipantID: p.ID,
		Commitments:   commitments,
	}, nil
}

func (p *Participant) Round2(toID uint16) (*SharePackage, error) {
	if p.polynomial == nil {
		return nil, fmt.Errorf("round1 not completed")
	}
	x := p.group.NewScalar().SetUInt64(uint64(toID))
	share := p.polynomial.Evaluate(x)
	encoded, err := share.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SharePackage{
		FromID: p.ID,
		ToID:   toID,
		Share:  hex.EncodeToString(encoded),
	}, nil
}

func (p *Participant) Finalize(
	receivedShares []*SharePackage,
	allCommitments []*Commitment,
	verificationKey *ecc.Element,
	_ interface{},
) (*keys.KeyShare, error) {
	finalSecret := p.group.NewScalar().Zero()

	x := p.group.NewScalar().SetUInt64(uint64(p.ID))
	ownShare := p.polynomial.Evaluate(x)
	finalSecret = finalSecret.Add(ownShare)

	for _, pkg := range receivedShares {
		if pkg.ToID != p.ID {
			continue
		}
		shareBytes, err := hex.DecodeString(pkg.Share)
		if err != nil {
			return nil, err
		}
		s := p.group.NewScalar()
		if err := s.UnmarshalBinary(shareBytes); err != nil {
			return nil, err
		}
		finalSecret = finalSecret.Add(s)
	}

	return &keys.KeyShare{
		Secret:          finalSecret,
		VerificationKey: verificationKey,
		PublicKeyShare: keys.PublicKeyShare{
			PublicKey: p.group.Base().Multiply(finalSecret),
			ID:        p.ID,
			Group:     p.group,
		},
	}, nil
}

func ComputeGroupPublicKey(group ecc.Group, allCommitments []*Commitment) (*ecc.Element, error) {
	groupKey := group.NewElement().Identity()
	for _, c := range allCommitments {
		if len(c.Commitments) == 0 {
			return nil, fmt.Errorf("empty commitments from participant %d", c.ParticipantID)
		}
		pointBytes, err := hex.DecodeString(c.Commitments[0])
		if err != nil {
			return nil, err
		}
		point := group.NewElement()
		if err := point.UnmarshalBinary(pointBytes); err != nil {
			return nil, err
		}
		groupKey = groupKey.Add(point)
	}
	return groupKey, nil
}
