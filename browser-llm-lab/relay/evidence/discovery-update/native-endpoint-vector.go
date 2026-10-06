package main
import("encoding/base64";"encoding/hex";"encoding/json";"fmt";"github.com/cypherium/cypher/crypto")
func main(){
 key,err:=crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001");if err!=nil{panic(err)}
 pub:=crypto.FromECDSAPub(&key.PublicKey)[1:];enode:="enode://"+hex.EncodeToString(pub)+"@127.0.0.1:30445?discport=0"
 raw:=[]byte(fmt.Sprintf(`{"version":1,"network":{"chainId":10101919,"genesisHash":"0x2222222222222222222222222222222222222222222222222222222222222222"},"enode":"%s","sourceId":"common-a","gatewayOrigin":"https://gateway.example.org","bootId":"66666666666666666666666666666666","sequence":1,"issuedAt":1700000000000,"expiresAt":1700000120000}`,enode))
 digest:=crypto.Keccak256([]byte("cypher-browser-mesh-endpoint-v1\x00"),raw);sig,err:=crypto.Sign(digest,key);if err!=nil{panic(err)}
 if !crypto.VerifySignature(crypto.FromECDSAPub(&key.PublicKey),digest,sig[:64]){panic("Go verification failed")}
 out:=map[string]any{"envelope":map[string]string{"payloadBase64":base64.StdEncoding.EncodeToString(raw),"signatureHex":hex.EncodeToString(sig)},"payloadUTF8":string(raw),"nodeId":hex.EncodeToString(crypto.Keccak256(pub)),"digest":hex.EncodeToString(digest),"domain":"cypher-browser-mesh-endpoint-v1\x00","testPrivateScalar":"0000000000000000000000000000000000000000000000000000000000000001"}
 b,_:=json.MarshalIndent(out,"","  ");fmt.Println(string(b))
}
