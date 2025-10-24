const rootDir = __dirname;

const rankingEnv = {
  PORT: 4300
};

if (process.env.CYPHER_IPC_PATH) {
  rankingEnv.CYPHER_IPC_PATH = process.env.CYPHER_IPC_PATH;
} else if (process.env.CYPHER_DATA_DIR) {
  rankingEnv.CYPHER_DATA_DIR = process.env.CYPHER_DATA_DIR;
}

module.exports = {
  apps: [
    {
      name: 'funoncypherium-freetoken',
      script: 'go',
      args: 'run ./freetoken/cmd/server',
      cwd: rootDir,
      interpreter: 'none',
      env: {
        PORT: 4200
      }
    },
    {
      name: 'funoncypherium-ranking',
      script: 'go',
      args: 'run ./ranking',
      cwd: rootDir,
      interpreter: 'none',
      env: rankingEnv
    },
    {
      name: 'funoncypherium-secret-wallet',
      script: 'go',
      args: 'run ./secret-wallet',
      cwd: rootDir,
      interpreter: 'none',
      env: {
        PORT: 4400
      }
    }
  ]
};
