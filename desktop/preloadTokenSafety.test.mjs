// CTRL-65: the renderer preload exposes no path to READ the credential.
//
// This loads the real preload.cjs with a stubbed `electron`, captures the
// exact API it exposes to the renderer (nhSetup / nhDesktop) and every IPC
// channel each method touches, and asserts none of them can read the token —
// the credential only ever travels IN (nh:save-token / import), never back
// out. A future getter would surface here as a new channel or bridge method.
import test from "node:test";
import assert from "node:assert";
import Module from "node:module";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadPreloadUnderStub() {
  const bridges = {};
  const channels = [];
  const fakeElectron = {
    contextBridge: {
      exposeInMainWorld: (name, api) => { bridges[name] = api; },
    },
    ipcRenderer: {
      invoke: (channel) => { channels.push(channel); return Promise.resolve({ ok: true }); },
      on: (channel) => { channels.push(channel); },
      removeListener: () => {},
    },
  };
  const orig = Module._load;
  Module._load = function (request, ...rest) {
    if (request === "electron") return fakeElectron;
    return orig.call(this, request, ...rest);
  };
  try {
    const require = createRequire(import.meta.url);
    delete require.cache[require.resolve("./preload.cjs")];
    require("./preload.cjs");
  } finally {
    Module._load = orig;
  }
  // Exercise every exposed method so its IPC channel is recorded. Args are
  // dummies — the channel name is what matters, not the call succeeding.
  for (const api of Object.values(bridges)) {
    for (const fn of Object.values(api)) {
      if (typeof fn === "function") { try { fn(() => {}); } catch { /* channel already captured */ } }
    }
  }
  return { bridges, channels };
}

test("the renderer preload exposes no token-read path", () => {
  const { bridges, channels } = loadPreloadUnderStub();

  // Exactly the two known bridges — nothing else is handed to the renderer.
  assert.deepEqual(Object.keys(bridges).sort(), ["nhDesktop", "nhSetup"]);

  // No exposed method touches a channel that reads/returns a credential.
  for (const ch of channels) {
    assert.ok(
      !/get.?token|read.?token|get.?credential|reveal|export.?token/i.test(ch),
      `preload exposes a token-read-shaped channel: ${ch}`,
    );
  }

  // The only credential-named channels are WRITES/imports (they return a
  // status object, never the value): save-token and claude-import-token.
  const tokenChannels = channels.filter((c) => /token/i.test(c));
  assert.deepEqual(
    tokenChannels.sort(),
    ["nh:claude-import-token", "nh:save-token"],
    `unexpected token-related channel exposed to the renderer: ${tokenChannels}`,
  );
});
