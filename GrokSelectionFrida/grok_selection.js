'use strict';

const SOURCE = 'grok.pro.monthly.30';
const TARGET = 'grok.pro.monthly.30.legacy';
const diagnosticEvents = new Set();
let showDiagnostic = () => {};

function configureDiagnostics() {
  const loader = Process.getModuleByName(
    'GrokSelectionLoader.dylib'
  );
  const showAddress = loader.getExportByName(
    'GrokSelectionDiagnosticShow'
  );
  const nativeShow = new NativeFunction(
    showAddress,
    'void',
    ['pointer']
  );

  showDiagnostic = message => {
    nativeShow(Memory.allocUtf8String(message));
  };
}

function showOnce(event, message) {
  if (diagnosticEvents.has(event)) {
    return;
  }

  diagnosticEvents.add(event);
  showDiagnostic(message);
}

function decode(aPtr, bPtr) {
  try {
    const a = BigInt(aPtr.toString());
    const b = BigInt(bPtr.toString());
    const top = a >> 56n;

    if (top === 0xd0n || top === 0xc0n) {
      const length = Number(a & 0x00ffffffffffffffn);
      const object = ptr(
        '0x' + (b & 0x0000ffffffffffffn).toString(16)
      );
      return object
        .add(top === 0xd0n ? 0x20 : 0x11)
        .readUtf8String(length);
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
      return String.fromCharCode.apply(
        null,
        bytes.slice(0, length)
      );
    }
  } catch (_) {}

  return null;
}

function install(app, offset, wantedA, wantedB, hookName) {
  Interceptor.attach(app.base.add(offset), {
    onEnter() {
      showOnce(
        hookName + '-entered',
        hookName + ' 已首次进入，偏移 Hook 正常。'
      );

      const actualA = this.context.x0;
      const actualB = this.context.x1;
      const wanted = decode(
        this.context[wantedA],
        this.context[wantedB]
      );
      const actual = decode(actualA, actualB);

      if (wanted !== SOURCE || actual !== TARGET) {
        return;
      }

      showOnce(
        hookName + '-matched',
        hookName + ' 判断条件已首次命中。'
      );

      //这里是判断---不要删除注释
      send({
        type: 'legacy-selection-substitution',
        offset: '0x' + offset.toString(16),
        from: SOURCE,
        to: TARGET,
        mode: 'register-only-current-process'
      });
    }
  });
}

rpc.exports = {
  init() {
    configureDiagnostics();

    try {
      const app = Process.getModuleByName('GrokApp');

      install(
        app,
        0x22f6c38,
        'x24',
        'x27',
        'Hook 1'
      );
      install(
        app,
        0x22fc3e8,
        'x25',
        'x28',
        'Hook 2'
      );

      showOnce(
        'ready',
        '第 2 层成功：Frida JS 已初始化，两个 Hook 已安装。'
      );

      send({
        type: 'ready',
        mode: 'temporary-legacy-selection',
        source: SOURCE,
        target: TARGET,
        noMemoryWrite: true,
        noNetworkInterception: true,
        cancelAtAppleSheet: true
      });
    } catch (error) {
      showOnce(
        'init-error',
        'Frida JS 初始化失败：' + error.message
      );
      throw error;
    }
  },

  dispose() {}
};
