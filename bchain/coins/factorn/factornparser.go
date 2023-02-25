package factorn

import (
	"bytes"
	"io"

	"github.com/martinboehm/btcd/wire"
	"github.com/martinboehm/btcutil/chaincfg"
	"github.com/trezor/blockbook/bchain"
	"github.com/trezor/blockbook/bchain/coins/btc"
	"github.com/trezor/blockbook/bchain/coins/utils"
)

// magic numbers
const (
	MainnetMagic wire.BitcoinNet = 0xcafecafe
	TestnetMagic wire.BitcoinNet = 0xfac70288
)

// chain parameters
var (
	MainNetParams chaincfg.Params
	TestNetParams chaincfg.Params
)

func init() {
	MainNetParams = chaincfg.MainNetParams
	MainNetParams.Net = MainnetMagic
	MainNetParams.PubKeyHashAddrID = []byte{0}
	MainNetParams.ScriptHashAddrID = []byte{5}
	MainNetParams.Bech32HRPSegwit = "fact"

	TestNetParams = chaincfg.TestNet3Params
	TestNetParams.Net = TestnetMagic
	TestNetParams.PubKeyHashAddrID = []byte{111}
	TestNetParams.ScriptHashAddrID = []byte{196}
  TestNetParams.Bech32HRPSegwit = "tfact"
}

type FactornParser struct {
	*btc.BitcoinLikeParser
}

func NewFactornParser(params *chaincfg.Params, c *btc.Configuration) *FactornParser {
	return &FactornParser{BitcoinLikeParser: btc.NewBitcoinLikeParser(params, c)}
}

func GetChainParams(chain string) *chaincfg.Params {
	if !chaincfg.IsRegistered(&MainNetParams) {
		err := chaincfg.Register(&MainNetParams)
		if err == nil {
			err = chaincfg.Register(&TestNetParams)
		}
		if err != nil {
			panic(err)
		}
	}
	switch chain {
	case "test":
		return &TestNetParams
	default:
		return &MainNetParams
	}
}

// Custom reader for FactorN header into a Bitcoin compatible header
func readFactornHeader(r io.ReadSeeker, bh *wire.BlockHeader) error {
	bch := make([]byte, 80)

	_, err := r.Seek(128, io.SeekCurrent) // nP1: skip it
	if err != nil {
		return err
	}
	_, err = io.ReadFull(r, bch[4:36]) // prevHash
	if err != nil {
		return err
	}
	_, err = io.ReadFull(r, bch[36:68]) // merkleRoot
	if err != nil {
		return err
	}
	_, err = r.Seek(4, io.SeekCurrent) // skip to least significant 4 bytes of nNonce
	if err != nil {
		return err
	}
	_, err = io.ReadFull(r, bch[76:80]) // nNonce[4:8]
	if err != nil {
		return err
	}
	_, err = r.Seek(8, io.SeekCurrent) // wOffset: skip it
	if err != nil {
		return err
	}
	_, err = io.ReadFull(r, bch[0:4]) // nVersion
	if err != nil {
		return err
	}
	_, err = io.ReadFull(r, bch[68:72]) // nTime
	if err != nil {
		return err
	}
	_, err = io.ReadFull(r, bch[72:74]) // nBits as most 2 significant bytes
	if err != nil {
		return err
	}

  bchr := bytes.NewReader(bch)
	return bh.Deserialize(bchr)
}

// ParseBlock parses raw blocks to blockbook structs
//
// Because of the modified header order, this needs to use a
// custom struct for Fact0rN. All data gets discarded, except
// the timestamp
func (p *FactornParser) ParseBlock(b []byte) (*bchain.Block, error) {
	r := bytes.NewReader(b)
	w := wire.MsgBlock{}
	h := wire.BlockHeader{}
	err := readFactornHeader(r, &h)
	if err != nil {
		return nil, err
	}

	err = utils.DecodeTransactions(r, 0, wire.WitnessEncoding, &w)
	if err != nil {
		return nil, err
	}

	txs := make([]bchain.Tx, len(w.Transactions))
	for ti, t := range w.Transactions {
		txs[ti] = p.TxFromMsgTx(t, false)
	}

	return &bchain.Block{
		BlockHeader: bchain.BlockHeader{
			Size: len(b),
			Time: h.Timestamp.Unix(),
		},
		Txs: txs,
	}, nil
}
