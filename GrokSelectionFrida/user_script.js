'use strict';

/**
 * Default user_script — CLI style (same shape as frida -l xxx.js)
 * ----------------------------------------------------------------
 * Replace this file on device with your own script, e.g. Grok_700_3mo.js:
 *
 *   /var/jb/Library/MobileSubstrate/DynamicLibraries/user_script.js
 *
 * This default is a light read-only demo (selection hit detector).
 * It does not patch memory or intercept network.
 */

const SOURCE = 'grok.pro.monthly.30';
const TARGET = 'grok.pro.monthly.30.legacy';

function decode(aPtr, bPtr) {
  try {
    const a = BigInt(aPtr.toString());
    const b = BigInt(bPtr.toString());
    const top = a >> 56n;

    if (top === 0xd0n || top === 0xc0n) {
      const length = Number(a & 0x00ffffffffffffffn);
      const object = ptr('0x' + (b & 0x0000ffffffffffffn).toString(16));
      return object.add(top === 0xd0n ? 0x20 : 0x11).readUtf8String(length);
    }

    if (top === 0xe0n || top === 0xa0n) {
      const bytes = [];
      let x = a;
      for (let i = 0; i < 8; i++) {
        bytes.push(Number(x & 0xffn));
        x >>= 8n;
      }
      x = b;
      for (let i = 0; i < 7; i++) {
        bytes.push(Number(x & 0xffn));
        x >>= 8n;
      }
      const length = Number(b >> 56n) & 0x0f;
      return String.fromCharCode.apply(null, bytes.slice(0, length));
    }
  } catch (_) {}
  return null;
}

function install(app, offset, wantedA, wantedB, hookName) {
  Interceptor.attach(app.base.add(offset), {
    onEnter() {
      const wanted = decode(this.context[wantedA], this.context[wantedB]);
      const actual = decode(this.context.x0, this.context.x1);
      if (wanted !== SOURCE || actual !== TARGET) return;
      console.log(
        '[user_script] HIT ' +
          hookName +
          ' ' +
          SOURCE +
          ' -> ' +
          TARGET +
          ' @0x' +
          offset.toString(16)
      );
    }
  });
  console.log(
    '[user_script] hooked ' + hookName + ' @ GrokApp+0x' + offset.toString(16)
  );
}

function main() {
  const app = Process.getModuleByName('GrokApp');
  install(app, 0x22f6c38, 'x24', 'x27', 'Hook1');
  install(app, 0x22fc3e8, 'x25', 'x28', 'Hook2');
  console.log('[user_script] ready (CLI-style default demo)');
}

function boot() {
  try {
    if (!Process.findModuleByName('GrokApp')) {
      setTimeout(boot, 100);
      return;
    }
    main();
  } catch (e) {
    console.log('[user_script] FATAL ' + e + (e.stack ? '\n' + e.stack : ''));
  }
}

// Same pattern as Grok_700_3mo.js / typical frida -l scripts
setTimeout(boot, 300);
