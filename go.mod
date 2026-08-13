module github.com/cypherium/cypher

go 1.25.6

replace github.com/dedis/protobuf => go.dedis.ch/protobuf v1.0.11

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/VictoriaMetrics/fastcache v1.13.3
	github.com/aristanetworks/goarista v0.0.0-20251201112602-a373d7c9f0d9
	github.com/aws/aws-sdk-go v1.34.0
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/cespare/cp v1.1.1
	github.com/cloudflare/cloudflare-go v0.117.0
	github.com/consensys/gnark-crypto v0.16.0
	github.com/crate-crypto/go-eth-kzg v1.5.0
	github.com/cypherium/cypherBFT v0.0.0-20211013080530-9fbb1458f709
	github.com/davecgh/go-spew v1.1.1
	github.com/deckarep/golang-set v1.8.0
	github.com/dedis/protobuf v0.0.0-00010101000000-000000000000
	github.com/docker/docker v28.5.2+incompatible
	github.com/dop251/goja v0.0.0-20260607120635-348e6bea910d
	github.com/edsrzf/mmap-go v1.2.0
	github.com/ethereum/c-kzg-4844/v2 v2.1.7
	github.com/fatih/color v1.19.0
	github.com/gballet/go-libpcsclite v0.0.0-20250918194357-1ec6f2e601c6
	github.com/go-stack/stack v1.8.1
	github.com/golang/snappy v1.0.0
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/golang-lru v1.0.2
	github.com/holiman/uint256 v1.3.2
	github.com/huin/goupnp v1.3.0
	github.com/influxdata/influxdb1-client v0.0.0-20220302092344-a9ab5670611c
	github.com/jackc/pgx/v5 v5.7.6
	github.com/jackpal/go-nat-pmp v1.0.2
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mattn/go-colorable v0.1.15
	github.com/mattn/go-isatty v0.0.22
	github.com/naoina/toml v0.1.1
	github.com/olekukonko/tablewriter v1.1.4
	github.com/pborman/uuid v1.2.1
	github.com/peterh/liner v1.2.2
	github.com/pkg/errors v0.9.1
	github.com/prometheus/tsdb v0.10.0
	github.com/quic-go/quic-go v0.60.0
	github.com/rjeczalik/notify v0.9.3
	github.com/rs/cors v1.11.1
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/steakknife/bloomfilter v0.0.0-20180922174646-6819c0d2a570
	github.com/stretchr/testify v1.11.1
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d
	github.com/tv42/httpunix v0.0.0-20191220191345-2ba4b9c3382c
	github.com/xtaci/kcp-go v5.4.20+incompatible
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.53.0
	golang.org/x/sys v0.46.0
	golang.org/x/text v0.38.0
	golang.org/x/time v0.15.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gopkg.in/olebedev/go-duktape.v3 v3.0.0-20210326210528-650f7c854440
	gopkg.in/oleiade/lane.v1 v1.0.0
	gopkg.in/satori/go.uuid.v1 v1.2.0
	gopkg.in/urfave/cli.v1 v1.20.0
	rsc.io/goversion v1.2.0
)

require (
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.10.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.6.0 // indirect
	github.com/consensys/bavard v0.1.27 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/dlclark/regexp2/v2 v2.2.1 // indirect
	github.com/go-kit/kit v0.10.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kevinburke/go-bindata/v4 v4.0.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.12.6 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/moby/sys/reexec v0.1.0 // indirect
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.2.0 // indirect
	github.com/olekukonko/ll v0.1.6 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/steakknife/hamming v0.0.0-20180906055917-c99c65617cd3 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	github.com/templexxx/cpufeat v0.0.0-20180724012125-cef66df7f161 // indirect
	github.com/templexxx/xor v0.0.0-20191217153810-f85b25db303b // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	gopkg.in/fatih/set.v0 v0.1.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

tool github.com/kevinburke/go-bindata/v4/go-bindata
