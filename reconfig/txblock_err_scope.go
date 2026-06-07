package reconfig

// err is used by verifyTxBlock before that function introduces its later local
// err via short declaration. This keeps the existing txblock.go assignment style
// compiling without changing runtime behavior.
var err error
