'use strict';

/**
 * GrokSelectionBootstrap — generic Frida Gadget host
 * --------------------------------------------------
 * Gadget always loads THIS file. Your real logic lives in user_script.js
 * (path overridable via shell_config.json).
 *
 * Supports:
 *   1) CLI-style scripts (top-level code / setTimeout(boot) / main())
 *      e.g. scripts written for: frida -U -f App -l script.js
 *   2) Gadget-style scripts that only define rpc.exports.init()
 *
 * Design goal: finish rpc.exports.init quickly so Gadget resumes the app,
 * then load the user script after a short delay (configurable).
 */

const INSTALL_DIR =
  '/var/jb/Library/MobileSubstrate/DynamicLibraries';

const DEFAULTS = {
  userScript: INSTALL_DIR + '/user_script.js',
  configPath: INSTALL_DIR + '/shell_config.json',
  logPath: '/var/jb/var/mobile/Library/Logs/GrokSelectionFrida.log',
  bootDelayMs: 400,
  waitModule: '',
  waitModuleTimeoutMs: 20000,
  waitModulePollMs: 100,
  bridgeConsole: true,
  alertOnError: true,
  alertOnReady: false,
  alertOnLoad: false,
  maxAlertLength: 350
};

let CFG = Object.assign({}, DEFAULTS);
let showDiagnostic = null;
let loadStarted = false;
let loadFinished = false;

function nowIso() {
  try {
    return new Date().toISOString();
  } catch (_) {
    return String(Date.now());
  }
}

function safeString(value) {
  try {
    if (value == null) return String(value);
    if (typeof value === 'string') return value;
    if (value instanceof Error) {
      return value.message + (value.stack ? '\n' + value.stack : '');
    }
    return String(value);
  } catch (_) {
    return '[unprintable]';
  }
}

function appendLog(line) {
  const text = '[' + nowIso() + '] ' + safeString(line);
  try {
    const f = new File(CFG.logPath, 'a');
    f.write(text + '\n');
    f.flush();
    f.close();
  } catch (_) {}
}

function tryBindDiagnostic() {
  if (showDiagnostic) return;
  try {
    const loader = Process.findModuleByName('GrokSelectionLoader.dylib');
    if (!loader) return;
    const addr = loader.findExportByName
      ? loader.findExportByName('GrokSelectionDiagnosticShow')
      : loader.getExportByName('GrokSelectionDiagnosticShow');
    if (!addr || addr.isNull()) return;
    const nativeShow = new NativeFunction(addr, 'void', ['pointer']);
    showDiagnostic = function (message) {
      try {
        const s = safeString(message).slice(0, CFG.maxAlertLength);
        nativeShow(Memory.allocUtf8String(s));
      } catch (_) {}
    };
  } catch (_) {}
}

function alert(message) {
  tryBindDiagnostic();
  if (showDiagnostic) {
    showDiagnostic(message);
  }
}

function bridgeConsole() {
  if (!CFG.bridgeConsole) return;

  function wrap(level) {
    return function () {
      const parts = [];
      for (let i = 0; i < arguments.length; i++) {
        parts.push(safeString(arguments[i]));
      }
      const line = '[' + level + '] ' + parts.join(' ');
      appendLog(line);
    };
  }

  try {
    console.log = wrap('LOG');
    console.warn = wrap('WARN');
    console.error = wrap('ERR');
    console.info = wrap('INFO');
    console.debug = wrap('DBG');
  } catch (_) {}
}

function readTextFile(path) {
  try {
    let text = File.readAllText(path);
    if (text && text.charCodeAt(0) === 0xfeff) {
      text = text.slice(1);
    }
    return text;
  } catch (e) {
    throw new Error('read failed: ' + path + ' — ' + safeString(e));
  }
}

function loadConfig() {
  CFG = Object.assign({}, DEFAULTS);
  try {
    const raw = readTextFile(DEFAULTS.configPath);
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      Object.keys(DEFAULTS).forEach(function (key) {
        if (parsed[key] !== undefined && parsed[key] !== null) {
          CFG[key] = parsed[key];
        }
      });
    }
  } catch (e) {
    // Config is optional; keep defaults.
    appendLog('config: using defaults (' + safeString(e) + ')');
  }

  if (typeof CFG.bootDelayMs !== 'number' || CFG.bootDelayMs < 0) {
    CFG.bootDelayMs = DEFAULTS.bootDelayMs;
  }
  if (typeof CFG.waitModuleTimeoutMs !== 'number' || CFG.waitModuleTimeoutMs < 0) {
    CFG.waitModuleTimeoutMs = DEFAULTS.waitModuleTimeoutMs;
  }
  if (typeof CFG.waitModulePollMs !== 'number' || CFG.waitModulePollMs < 20) {
    CFG.waitModulePollMs = DEFAULTS.waitModulePollMs;
  }
  if (!CFG.userScript) {
    CFG.userScript = DEFAULTS.userScript;
  }
  if (!CFG.logPath) {
    CFG.logPath = DEFAULTS.logPath;
  }
}

function waitForModule(name, timeoutMs, pollMs, done) {
  if (!name) {
    done(null);
    return;
  }

  const start = Date.now();

  function tick() {
    try {
      const mod = Process.findModuleByName(name);
      if (mod) {
        done(mod);
        return;
      }
    } catch (_) {}

    if (Date.now() - start >= timeoutMs) {
      done(null);
      return;
    }
    setTimeout(tick, pollMs);
  }

  tick();
}

function runUserScriptSource(source) {
  // Capture rpc.exports before user code runs.
  const bootstrapExports = rpc.exports;
  let thrown = null;

  try {
    // eslint-disable-next-line no-eval
    eval(source);
  } catch (e) {
    thrown = e;
  }

  // If the user script is Gadget-style (only defines init), call it.
  try {
    const userExports = rpc.exports;
    const hasUserInit =
      userExports &&
      userExports !== bootstrapExports &&
      typeof userExports.init === 'function';

    if (hasUserInit) {
      appendLog('user_script: calling rpc.exports.init()');
      const ret = userExports.init();
      // Best-effort: if init returns a Promise-like, ignore (QJS may not have Promise).
      if (ret && typeof ret.then === 'function') {
        ret.then(
          function () {
            appendLog('user_script: rpc.exports.init() promise resolved');
          },
          function (err) {
            appendLog('user_script: rpc.exports.init() promise rejected: ' + safeString(err));
            if (CFG.alertOnError) {
              alert('user_script init 失败：' + safeString(err));
            }
          }
        );
      }
    } else {
      appendLog('user_script: top-level / CLI-style evaluation finished');
    }
  } catch (e) {
    if (!thrown) thrown = e;
  }

  // Restore bootstrap dispose so Gadget teardown still works; merge if needed.
  try {
    const userDispose =
      rpc.exports && typeof rpc.exports.dispose === 'function'
        ? rpc.exports.dispose
        : null;
    rpc.exports = {
      init: bootstrapExports.init,
      dispose: function () {
        try {
          if (userDispose) userDispose();
        } catch (e) {
          appendLog('user dispose error: ' + safeString(e));
        }
      }
    };
  } catch (_) {}

  if (thrown) {
    throw thrown;
  }
}

function loadUserScript() {
  if (loadStarted) return;
  loadStarted = true;

  appendLog('loadUserScript: begin path=' + CFG.userScript);

  waitForModule(
    CFG.waitModule || '',
    CFG.waitModuleTimeoutMs,
    CFG.waitModulePollMs,
    function (mod) {
      try {
        if (CFG.waitModule) {
          if (mod) {
            appendLog('waitModule: ready ' + CFG.waitModule);
          } else {
            appendLog(
              'waitModule: timeout waiting for ' +
                CFG.waitModule +
                ' — loading anyway'
            );
          }
        }

        const source = readTextFile(CFG.userScript);
        if (!source || !String(source).trim()) {
          throw new Error('user_script is empty: ' + CFG.userScript);
        }

        appendLog('user_script: bytes≈' + source.length);
        runUserScriptSource(source);
        loadFinished = true;
        appendLog('loadUserScript: ok');

        if (CFG.alertOnReady || CFG.alertOnLoad) {
          alert('通用壳：user_script 已加载\n' + CFG.userScript);
        }
      } catch (e) {
        const msg = 'user_script 加载失败：' + safeString(e);
        appendLog(msg);
        if (CFG.alertOnError) {
          alert(msg);
        }
      }
    }
  );
}

rpc.exports = {
  /**
   * Gadget calls this. Return ASAP so the target process is resumed.
   * Real payload runs on a timer (CLI-script friendly).
   */
  init: function () {
    try {
      loadConfig();
      bridgeConsole();
      tryBindDiagnostic();
      appendLog('bootstrap init: delay=' + CFG.bootDelayMs + 'ms');

      if (CFG.alertOnLoad) {
        alert('通用壳 bootstrap 已启动\n' + CFG.userScript);
      }

      const delay = CFG.bootDelayMs;
      if (delay <= 0) {
        loadUserScript();
      } else {
        setTimeout(loadUserScript, delay);
      }
    } catch (e) {
      appendLog('bootstrap init fatal: ' + safeString(e));
      if (CFG.alertOnError) {
        alert('bootstrap 失败：' + safeString(e));
      }
    }
  },

  dispose: function () {
    appendLog('bootstrap dispose');
  }
};
