# Sleep player / 睡眠守护

睡前放 B 站 / YouTube / 抖音，睡着后手机自动把音量淡出并暂停播放。

手机直连手环（BLE），不经过小米云、不依赖 Mi Fitness，所以**没有云往返延迟**。

---

## 一、怎么拿到 APK

代码在这个环境里没有 JDK / Android SDK，**没法在本地编译**。所以构建交给 GitHub Actions：

**推一次代码，就会自动出一个可安装的 APK。**

```bash
git push -u origin main
```

然后：

1. 打开 `https://github.com/ngjingtao/sleepplayer/actions`
2. 点最新一次 **build-apk** 运行
3. 页面底部 **Artifacts** → 下载 `sleepplayer-apk`

想要**不用登录就能下载**的链接：打一个 tag，APK 会挂到 Release 上。

```bash
git tag v0.1
git push origin v0.1
```

然后 `https://github.com/ngjingtao/sleepplayer/releases` 里直接下载。

> Debug 构建用标准 debug key 签名：能装、能用，不能上架应用商店。

## 二、装到手机

1. 把 APK 传到手机（微信文件传输 / USB / 网盘都行）
2. 点开它；系统提示"未知来源"时，允许你的文件管理器或浏览器「安装未知应用」
3. 安装完成后桌面出现 **Sleep guard**

## 三、第一次运行：两件必做的事

不做这两件，数据和控制都会失效。

**1. 通知使用权** —— 设置 → 通知使用权 → 开启 **Sleep guard**

App 一个通知都不读。这只是 Android 允许"暂停别的 App 播放"的闸门。不开的话只能用媒体键兜底，而部分播放器会忽略媒体键。

**2. 关闭电池优化** —— 设置 → 电池 → 无限制 / 允许后台运行

否则厂商调度器会在视频播到一半时杀掉服务。小米 / 华为 / OPPO 上尤其重要——而这些恰恰是你要用的机器。

## 四、用法

界面从上到下：

| 字段 | 含义 |
|---|---|
| **playback min** | 真正**在播放**的分钟数达到这个值就暂停（暂停中不计数） |
| **fade sec** | 暂停前多久开始淡出音量（默认 20 秒） |
| **Start watching** | 开始守护 |
| **Grant notification access** | 跳到通知使用权设置页 |
| **BLE probe** | 探针界面：扫描、连接、打印全部 GATT 特征、原始收发 |

点 **Start watching** 之后，状态行会实时显示检测器在想什么，比如
`quiet 9m, HR 56/62, confirmed 2/4m`。

## 五、"直接从蓝牙取数"到底意味着什么

**没有的延迟（已经做到）：** 手环 → 手机是 BLE 通知推送，手机不轮询、不经过云端、不依赖小米账号。手环一发包，App 立刻收到。

**有的延迟（改不掉，也不该改）：**

1. **手环自己的上报间隔**。心率多久发一次是手环固件决定的，通常 1 秒到几十秒。我们无法让它更快——那是设备侧的行为。
2. **故意等的 4 分钟**。检测器要求"心率降下来 + 不再动"持续 4 分钟才认定睡着。这不是性能问题，是**防误暂停**：看视频时你本来就不动，一秒判定会把清醒的你按停。

一句话：链路是实时的，判定是刻意的稳。

## 六、现在的限制（重要，别跳过）

**小米手环 10 的协议还没破解**，所以"用手环判断睡着"这条路目前走不通。

原因很具体：经典协议里心率在特征 `ff12`，而你这一代手环很可能根本没有这个特征。App 不会瞎猜，它会：

1. 找不到 `ff12` → **进入学习模式**，订阅**所有**通知特征
2. 把每个通知的 UUID + 原始字节打进日志
3. 你在日志里找出哪个 UUID 的数值在跟着你的脉搏变
4. 把那个 UUID 和"心跳数值在第几个字节"填进设置

即使填好了，能不能真正驱动检测，还取决于那一代协议有没有额外的加密层。**在此之前，计时器仍然保护你**——视频不会播到天亮。

配套的 Python 工具（仓库根目录 `remiband/`）就是用来破解这一步的：给它一份 `btsnoop` 抓包，它能解析出服务、特征、认证握手，并识别传输协议。

## 七、本地构建（有 Android Studio 的话）

```bash
cd android
./gradlew :app:testDebugUnitTest    # 20 个测试：8 个检测器场景 + 12 个协议
./gradlew :app:assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk
```

没有依赖包袱：除测试用 JUnit 外只用 `android.*`，不用 AndroidX / Compose / 协程。

## 八、这个判定的核心设计

| 问题 | 用的信号 | 为什么 |
|---|---|---|
| 睡着了没？ | 3 分钟心率**中位数** | 这是"要动手"的决定，必须慢而稳 |
| 醒了没？ | 最近 90 秒心率**最大值** | 这是"先别动手"的决定，必须快 |

这个不对称是修 bug 修出来的：两边都用中位数时，中位数滞后会造成一段空档——你已经醒了，中位数还显示睡着的值，确认计时器正好在空档到期，把视频暂停在正盯着屏幕的你身上。

**没暂停只是小烦，误暂停是会让人卸载 App 的 bug。**

## 九、目录

```
android/           Android App（Kotlin）
  sleep/SleepDetector.kt   判定逻辑，纯 Kotlin，可在 JVM 上测
  sleep/MediaGate.kt       暂停任意播放器 + 音量淡出
  sleep/SleepWatchService.kt  前台服务
  probe/ProbeActivity.kt   协议无关的探针（破解手环 10 的工具）
.github/workflows/build-apk.yml   出 APK 的 CI
remiband/          抓包解析工具（Python）
docs/protocol.md   协议笔记，带可信度标注
```
