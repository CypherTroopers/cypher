package main
import (
 "encoding/json"
 "fmt"
 "os"
 "reflect"
 "github.com/cypherium/cypher/core"
)
func main() {
 a,err:=os.ReadFile(os.Args[1]); if err!=nil {panic(err)}
 b,err:=os.ReadFile(os.Args[2]); if err!=nil {panic(err)}
 var old,next core.Genesis
 if err=json.Unmarshal(a,&old);err!=nil {panic(err)}
 if err=json.Unmarshal(b,&next);err!=nil {panic(err)}
 if !reflect.DeepEqual(old,next) {panic("decoded genesis differs")}
 ob,nb:=old.ToBlock(nil),next.ToBlock(nil)
 if ob.Hash()!=nb.Hash() || ob.Root()!=nb.Root() {panic("genesis hash/root differs")}
 if nb.Hash().Hex()!="0xa4a61fa952509cde79c14e152702a1d7dea1cc0320b4552566b2efb9e4a575de" {panic("unexpected generation")}
 fmt.Printf("PASS: same decoded genesis; chainID=%s genesis=%s root=%s\n",next.Config.ChainID,nb.Hash().Hex(),nb.Root().Hex())
}
