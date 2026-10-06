"""Read-only native endpoints and canonical hash evidence; never opens chain DBs or starts bridges."""
import argparse, http.client, json, os, socket, time
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / '.runtime'
ORIGIN = 'https://ai-test.make-cph-great-again.community'
GENESIS = '0x001c8239f25a697933e2a54511a576205fb21cbb80dc974adb29894dc80250ad'
DEFAULT_REFERENCE = Path('/root/cypher/chaindbmine/cypher.ipc')
FALLBACK_REFERENCE = Path('/root/cypher/chaindb0/cypher.ipc')

def ipc(path, method, params=None):
    conn = socket.socket(socket.AF_UNIX)
    conn.settimeout(8)
    try:
        conn.connect(str(path))
        conn.sendall((json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}) + '\n').encode())
        data = b''
        while b'\n' not in data:
            chunk = conn.recv(65536)
            if not chunk:
                raise RuntimeError('IPC closed before response')
            data += chunk
            if len(data) > 4 * 1024 * 1024:
                raise RuntimeError('IPC response bound exceeded')
        reply = json.loads(data.split(b'\n', 1)[0])
        if reply.get('error'):
            raise RuntimeError('Read-only IPC method failed: ' + method)
        return reply['result']
    finally:
        conn.close()

def mesh_status(path):
    conn = http.client.HTTPConnection('localhost', timeout=5)
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.settimeout(5)
    try:
        conn.sock.connect(str(path))
        conn.request('GET', '/relay/v1/mesh/status', headers={'Origin': ORIGIN})
        reply = conn.getresponse()
        data = reply.read(65537)
        if reply.status != 200 or len(data) > 65536:
            raise RuntimeError('Native mesh status unavailable or oversized')
        return json.loads(data)
    finally:
        conn.close()

def reference():
    """Choose only an owner IPC for hash reads; never add it to any peer route."""
    explicit = os.environ.get('MESH_REFERENCE_IPC')
    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            raise ValueError('MESH_REFERENCE_IPC must be an absolute local Unix socket path')
        head = int(ipc(path, 'eth_blockNumber'), 16)
        return path, head, {'path': str(path), 'selection': 'explicit', 'fallbackReason': None}
    try:
        head = int(ipc(DEFAULT_REFERENCE, 'eth_blockNumber'), 16)
        return DEFAULT_REFERENCE, head, {'path': str(DEFAULT_REFERENCE), 'selection': 'default', 'fallbackReason': None}
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        # This one known, existing reference is used only for canonical hashes.
        # Report the fallback explicitly; never discover arbitrary sockets.
        head = int(ipc(FALLBACK_REFERENCE, 'eth_blockNumber'), 16)
        return FALLBACK_REFERENCE, head, {
            'path': str(FALLBACK_REFERENCE), 'selection': 'fallback',
            'fallbackReason': f'Default reference {DEFAULT_REFERENCE} unavailable ({type(error).__name__})',
        }

def inspect(require_transfer=False):
    paths = {name: BASE / ('mesh-' + name) / 'node.ipc' for name in ['a', 'b']}
    paths['reference'], reference_head, selected_reference = reference()
    selected_reference['role'] = 'canonical-hash-reference-only'
    report = {'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'nodes': {}, 'hashes': {}, 'reference': selected_reference, 'verification': 'native-owner-rpc-canonical-hashes'}
    for name, path in paths.items():
        row = {'head': reference_head if name == 'reference' else int(ipc(path, 'eth_blockNumber'), 16)}
        if name != 'reference':
            row['peers'] = ipc(path, 'admin_peers')
            row['meshStatus'] = mesh_status(BASE / ('mesh-' + name) / 'source.sock')
            row['mining'] = ipc(path, 'eth_mining')
            row['accountsCount'] = len(ipc(path, 'eth_accounts'))
            assert row['mining'] is False and row['accountsCount'] == 0
        report['nodes'][name] = row
    common_head = min(row['head'] for row in report['nodes'].values())
    for height in sorted({0, min(1, common_head), min(1000, common_head), common_head}):
        hashes = {name: ipc(path, 'eth_getBlockByNumber', [hex(height), False])['hash'] for name, path in paths.items()}
        assert len(set(hashes.values())) == 1, 'Canonical hash disagreement at height ' + str(height)
        if height == 0:
            assert hashes['a'] == GENESIS
        report['hashes'][str(height)] = hashes
    b = report['nodes']['b']
    report['bOnlyMeshPeers'] = all(peer['network'].get('transport') == 'browser-mesh' for peer in b['peers'])
    assert report['bOnlyMeshPeers'], 'Isolated Common B unexpectedly has non-mesh native peer'
    report['bHasTransferredNativeStream'] = any(peer['network'].get('browserMesh', {}).get('bytesReceived', 0) > 1000 for peer in b['peers'])
    if require_transfer:
        assert b['head'] > 0 and b['peers'] and report['bHasTransferredNativeStream'], 'No completed browser-mesh native transfer yet'
    report['pass'] = True
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-transfer', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = inspect(args.require_transfer)
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')
