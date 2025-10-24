const { spawn } = require('child_process');

const processes = [
  { name: 'freetoken', command: 'npm', args: ['run', 'start:freetoken'] },
  { name: 'ranking', command: 'go', args: ['run', './ranking'] },
  { name: 'secret-wallet', command: 'go', args: ['run', './secret-wallet'] },
];

let shuttingDown = false;

const running = processes.map(({ name, command, args }) => {
  const child = spawn(command, args, { stdio: 'inherit', shell: process.platform === 'win32' });

  child.on('exit', (code, signal) => {
    if (shuttingDown) {
      return;
    }

    if (code !== null && code !== 0) {
      console.error(`\n${name} exited with code ${code}`);
      shutdown(code);
    } else if (signal) {
      console.warn(`\n${name} terminated via signal ${signal}`);
      shutdown(0);
    } else {
      console.log(`\n${name} finished running.`);
      shutdown(code ?? 0);
    }
  });

  return child;
});

const shutdown = (exitCode = 0) => {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  for (const child of running) {
    if (!child.killed) {
      child.kill('SIGINT');
    }
  }
  const numericExitCode = typeof exitCode === 'number' ? exitCode : 0;
  process.exit(numericExitCode);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
