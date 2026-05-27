# Restart_windows.ps1

$ErrorActionPreference = "Stop"

$DATADIR = "chaindbname"

$BOOTNODES = @(
  "enode://e10a90e9c7d077002d4d56b88943b8dfbca1d6490bb92c8202e6acb68ef23b521bf187fb40c07eed2f453f3782e8c53ca5a4ec1d34a4454960143501df8c4b95@158.220.101.48:6000",
  "enode://0c8a37a7803c358d8ae68784ef247a0c8b4df542d925b23491dd92f4c2172a146a124171ec5bbdcc2e5932e4cead917505ce3b5dbd72155a78e830ebd8e37b07@158.220.101.48:6001",
  "enode://65ebdea1e99c440bb5463b68565e7422ab332ef8d1472daa956d23b70245ef9703c23ea110291eeb6fe0b60c7e55fed08f76e71fb980ae9b3e2fe583a115e7f3@158.220.101.48:6002",
  "enode://c7a724e53dc21ff034e628bb4e50d720e6bbc276bd17cc15cc9a28149a5f0a6bd90c0e50f862f5546fa9bc153c7ea818cdf3d133d06356e76b99726754a6b3da@158.220.101.48:6003",
  "enode://a99ba2027de40c50220e45af60698d7e04237c128258065261fae82cef723837f00ce8611c3164b9efdfc15f0480a308ac65058db9a3abdf83aae05604c9a495@158.220.101.48:6004",
  "enode://8a3aad9282f773ddd38b05516c2c5847ef168b8b5095f57312a458e0a5b358655cb971d1ba193999b0454fc4ae5642f31c6f6bce311a8da11b0a6d9940719a5e@158.220.101.48:6005",
  "enode://7eb6bd844e05f64114ea6e6f06ae04e075df0a8a6d783620344f3535df2f2115ad2ad09dab69cf3515ee2d0ac50379c0825a0abfa5a50216d8e4b97823acbd67@158.220.101.48:6006"
) -join ","

Write-Host "==> Get public IP"
$PUBLIC_IP = (Invoke-RestMethod -Uri "https://api4.ipify.org").Trim()

Write-Host "==> Restart Cypher node"
.\build\bin\cypher.exe `
  --verbosity 1 `
  --rnetport 7200 `
  --syncmode full `
  --nat "extip:$PUBLIC_IP" `
  --ws `
  --ws.addr 0.0.0.0 `
  --ws.port 9251 `
  --ws.origins "*" `
  --metrics `
  --http `
  --http.addr 0.0.0.0 `
  --http.port 8000 `
  --http.api eth,web3,net,txpool `
  --http.corsdomain "*" `
  --port 6000 `
  --datadir ".\$DATADIR" `
  --networkid 1236789 `
  --gcmode archive `
  --bootnodes "$BOOTNODES" `
  console
