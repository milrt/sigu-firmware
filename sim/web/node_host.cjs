// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// Runs the web build in node with the same stdin protocol as `sigu-sim --headless`, so the
// tests in tests/ can drive both. The wallet is in memory, the card is a host folder.
//
//   node sim/web/node_host.cjs <build-web dir> [--card DIR]

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const readline = require('readline');

const js = path.resolve(process.argv[2] || 'build-web', 'sigu-sim.js');
const cardArg = process.argv.indexOf('--card');
const card = cardArg > 0 ? path.resolve(process.argv[cardArg + 1]) : null;

globalThis.Module = {
  preRun: [() => {
    FS.mkdirTree('/sigu/card');
    if (card) {
      FS.mount(NODEFS, { root: card }, '/sigu/card');
    }
  }],
  print: (line) => {
    if (line === 'ready') {
      start();
    } else {
      console.log(line);
    }
  },
  printErr: (line) => console.error(line),
};

function start() {
  const rl = readline.createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    if (line.trim() === 'quit') {
      process.exit(0);
    }
    Module.ccall('sim_web_command', 'number', ['string'], [line]);
  });
  rl.on('close', () => process.exit(0));
}

// Run it as a page script would, so it sees the global Module and not a CommonJS local.
Object.assign(globalThis, { require, __dirname: path.dirname(js), __filename: js });
vm.runInThisContext(fs.readFileSync(js, 'utf8'), { filename: js });
