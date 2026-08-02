# GrokSelectionFrida — 通用 Gadget 壳（3.0.3+）

Rootless + ElleKit + Frida Gadget。  
**Gadget 只加载 bootstrap**；你的业务逻辑放在可替换的 `user_script.js`。

## 安装后文件

```
/var/jb/Library/MobileSubstrate/DynamicLibraries/
  GrokSelectionLoader.dylib      # ElleKit 注入入口（dlopen Gadget）
  GrokSelectionLoader.plist      # 只注入 ai.x.GrokApp
  GrokSelectionFrida.dylib       # Frida Gadget
  GrokSelectionFrida.config      # 指向 Bootstrap
  GrokSelectionBootstrap.js      # 通用壳（一般别改）
  user_script.js                 # ★ 你的脚本：可整份替换
  shell_config.json              # 延迟 / 日志 / 等待模块等
```

## 换脚本（适配 Grok_700_3mo 这类写法）

1. 把电脑上的脚本复制到设备上的 `user_script.js`（覆盖即可）
2. **彻底杀掉 Grok 再开**（不要依赖热重载）
3. 看日志：

```
/var/jb/var/mobile/Library/Logs/GrokSelectionFrida.log
```

支持的脚本形态：

| 形态 | 示例 | 壳如何处理 |
|------|------|------------|
| CLI 顶层 / `setTimeout(boot)` | `Grok_700_3mo.js` | `eval` 后自动跑顶层逻辑 |
| 仅 `rpc.exports.init` | 旧 3.0.1 只读脚本 | `eval` 后主动调用 `init()` |

## shell_config.json

| 字段 | 默认 | 含义 |
|------|------|------|
| `userScript` | `.../user_script.js` | 用户脚本路径 |
| `bootDelayMs` | `400` | Gadget `init` 返回后延迟多久再加载脚本（先让 App 恢复） |
| `waitModule` | `GrokApp` | 加载前等待该模块；空字符串=不等待 |
| `waitModuleTimeoutMs` | `20000` | 等待超时后仍加载 |
| `bridgeConsole` | `true` | `console.log` 写到 log 文件 |
| `alertOnError` | `true` | 加载失败弹诊断窗 |
| `alertOnReady` | `false` | 加载成功也弹窗 |

### 若脚本很重 / 仍觉得启动怪

- 把 `bootDelayMs` 调到 `800`～`1500`
- 保持 `waitModule` 为 `GrokApp`
- **不要在脚本里一上来 hook 全站 `NSURLSession` / 全局字符串 bridge**（容易表现为“没网”）——这是脚本逻辑问题，不是壳没加载

## 和旧 3.0.1 的区别

| | 3.0.1 | 3.0.3 通用壳 |
|--|--------|----------------|
| Gadget 入口脚本 | `grok_selection.js`（业务+壳混在一起） | `GrokSelectionBootstrap.js` |
| 换逻辑 | 必须符合 `rpc.exports.init` | 覆盖 `user_script.js` 即可 |
| CLI 脚本 | 基本不兼容 | 兼容 `setTimeout(boot)` 写法 |
| 日志 | 基本没有 | 文件日志 + 可选弹窗 |

## 打包

需要已编译的 `GrokSelectionLoader.dylib` 与 Frida Gadget：

```powershell
py .\build_deb.py `
  --gadget <path-to-frida-gadget.dylib> `
  --loader <path-to-GrokSelectionLoader.dylib> `
  --output .\output
```

可选：`--repo-root ..` 更新同级源站索引。

## 注意

- Offset / `Memory.patchCode` 必须匹配当前 Grok 版本，壳不会校验版本。
- 改的是 `user_script.js`，不要覆盖 `GrokSelectionBootstrap.js`（除非你在改壳本身）。
- 设备上用编辑器保存时请用 **UTF-8 无 BOM**，避免智能引号。
