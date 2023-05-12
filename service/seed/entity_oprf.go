package seed

/*
   run oprf
*/

import (
	"fmt"

	"github.com/bytemare/voprf"
)

type Oprf struct {
	key    []byte
	client *voprf.Client
}

func NewOprf(key []byte) *Oprf {
	return &Oprf{
		key:    key,
		client: voprf.Ristretto255Sha512.Client(voprf.OPRF, nil),
	}
}

func (m *Oprf) EvalOprf(input string) ([]byte, error) {
	var blinded = m.client.Blind(input, nil)
	var ev, err = m.evaluate(blinded)
	if err != nil {
		return nil, err
	}

	var eval = new(voprf.Evaluation)
	if err = eval.Deserialize(ev); err != nil {
		return nil, err
	}

	return m.client.Finalize(eval, nil)
}

func (m *Oprf) evaluate(blinded []byte) ([]byte, error) {
	if m.key == nil {
		return nil, fmt.Errorf("server key error")
	}

	var server, err = voprf.Ristretto255Sha512.Server(voprf.OPRF, m.key)
	if err != nil {
		return nil, err
	}

	evaluation, err := server.Evaluate(blinded, nil)
	if err != nil {
		return nil, err
	}

	ev := evaluation.Serialize()
	return ev, nil
}
