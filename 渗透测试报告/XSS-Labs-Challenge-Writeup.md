# XSS-Labs 靶场 (1-18关) 核心关卡实战报告

## 🎯 测试概况
- **靶场名称**：XSS-Labs
- **测试目标**：完成核心可复现关卡，深入理解XSS触发与绕过技巧（Flash相关关卡因环境停用未测试）
- **测试时间**：2026年X月X日
- **测试环境**：本地虚拟机 (Kali Linux/Docker，靶场地址：`192.168.59.135`)
- **主要工具**：浏览器、Burp Suite
- **报告说明**：所有截图均托管于GitHub。Level 19/20因Flash插件已全面停用、无实际测试价值，故未开展测试。

---

## 📚 关卡详细记录

### Level 1-5: 基础注入点
| 关卡 | 注入点与绕过分析 | 有效Payload | 关键步骤与截图 |
| :--- | :--- | :--- | :--- |
| **Level 1** | 参数`name`无过滤，直接回显于页面。 | `<script>alert(1)</script>` | 输入Payload后页面直接执行并弹窗。<br>![L1成功弹窗](https://github.com/user-attachments/assets/a982d4dc-03bf-4e7b-b2cd-c17e63e50b10) |
| **Level 2** | 输入被放入`<input>`标签的`value`属性，需闭合以注入新标签。 | `"><script>alert(1)</script>` | 使用`">`闭合原属性与标签，插入新的`<script>`标签。<br>![L2源码查看](https://github.com/user-attachments/assets/c4cb8c57-d5db-474c-b41f-0622da93d135) |
| **Level 3** | 单/双引号被转义，无法闭合属性，但可利用事件属性。 | `' onclick='alert(1)` | 在`value`属性值内构造`onclick`事件，点击输入框触发。<br>![L3事件触发](https://github.com/user-attachments/assets/4b3130c0-cb12-4e97-ad25-548a46c3aa8e) |
| **Level 4** | 双引号未被转义，可直接闭合属性并添加事件。 | `" onclick="alert(1)` | 闭合`value`属性，插入`onclick`事件。<br>![L4注入成功](https://github.com/user-attachments/assets/f7386121-85aa-4376-a2f5-507d22165665) |
| **Level 5** | 过滤`<script>`与`on`事件前缀，需使用其他标签和协议。 | `"><a href="javascript:alert(1)">click</a>` | 闭合标签后插入`<a>`标签，利用`javascript:`伪协议。<br>![L5链接触发](https://github.com/user-attachments/assets/db60c1aa-789f-436f-8aa0-5fed8735a2f1) |

### Level 6-10: 基础过滤与绕过
| 关卡 | 过滤规则（分析） | 有效Payload | 关键步骤与截图 |
| :--- | :--- | :--- | :--- |
| **Level 6** | 过滤小写`script`，不区分大小写。 | `"><a HRef="javascript:alert(1)">click</a>` | 使用大小写混淆（`HRef`）绕过关键词检测。<br>![L6大小写绕过](https://github.com/user-attachments/assets/64cd778a-ef67-413e-909a-f5dd2b8a7443) |
| **Level 7** | 直接删除`script`、`on`等关键词。 | `"><a hrhrefef="javascrscriptipt:alert(1)">click</a>` | 采用双写关键词（如`hrhrefef`），服务器删除中间字符后剩余部分重组为有效关键词。<br>![L7双写绕过](https://github.com/user-attachments/assets/25eaf862-ec96-43d8-9fa8-11b8888b6109) |
| **Level 8** | 对输入进行HTML实体编码，仅`<a>`标签的`href`属性可执行。 | `javascript:alert(1)` | 输入未编码的`javascript:`伪协议，直接利用`href`属性执行。<br>![L8伪协议](https://github.com/user-attachments/assets/1a8b7951-34b9-4e12-b23f-e78e49e94e85) |
| **Level 9** | 校验输入必须包含`http://`。 | `javascript:alert(1)//http://` | 在`javascript:`代码后添加注释`//`，再拼接`http://`以满足校验。<br>![L9注释绕过](https://github.com/user-attachments/assets/4de76f87-c0f6-450c-8ef0-77b6313afd5c) |
| **Level 10** | 注入点隐藏在表单的隐藏参数`t_sort`中。 | `" onmouseover=alert(1) type="text` | 通过查看页面源码或Burp抓包发现`t_sort`参数，构造事件属性进行注入。<br>![L10隐藏参数](https://github.com/user-attachments/assets/b4c0b8fa-2939-4858-91fc-1c1eab4eff93) |

### Level 11-18: 进阶过滤与环境绕过
| 关卡 | 过滤规则（分析） | 有效Payload | 关键步骤与截图 |
| :--- | :--- | :--- | :--- |
| **Level 11** | 基于HTTP `Referer`请求头进行注入。 | `" onclick=alert(1) type="text` | 使用Burp Suite拦截请求，修改`Referer`头为Payload，页面解析后点击触发。<br>![L11 Referer注入](https://github.com/user-attachments/assets/6213e333-f3c6-485a-9ae2-9f47ff41ff52) |
| **Level 12** | 基于HTTP `User-Agent`请求头进行注入。 | `" onclick=alert(1) type="text` | 使用Burp Suite修改`User-Agent`头，页面回显后点击触发。<br>![L12 UA注入](https://github.com/user-attachments/assets/d0471f9f-ab26-4a58-846d-708f150d6dfe) |
| **Level 13** | 基于HTTP `Cookie`请求头进行注入。 | `" onclick=alert(1) type="text` | 使用Burp Suite修改Cookie值，页面解析后点击触发。<br>![L13 Cookie注入](https://github.com/user-attachments/assets/5524ef60-224c-4a69-92b0-2a2e5d60d30e) |
| **Level 14** | **（本靶场环境中常缺失或不可用，此处保留位置）** | - | - |
| **Level 15** | 利用AngularJS `ng-include`指令包含外部文件。 | `?src='level1.php?name=<img src=x onerror=alert(1)>'` | 通过参数控制`ng-include`加载一个包含XSS Payload的页面，触发`onerror`事件。<br>![L15 ng-include利用](https://github.com/user-attachments/assets/efd96a23-8e9a-4990-a139-6502d19fdc15) |
| **Level 16** | 过滤空格、`script`、`/`等字符。 | `<img%0asrc=x%0aonerror=alert(1)>` | 使用URL编码的换行符`%0a`替代空格，绕过过滤。<br>![L16 空格绕过](https://github.com/user-attachments/assets/c1570e51-41e9-4696-8c79-da92a0635339) |
| **Level 17** | 对`embed`标签的`src`参数进行拼接，未过滤关键字符。 | `?arg01=a&arg02= onmouseover=alert(1)` | 参数值被拼接进`embed`标签属性，构造事件属性触发。<br>![L17 embed标签注入](https://github.com/user-attachments/assets/bc604386-da08-42db-ba80-4d1eb44133ee) |
| **Level 18** | 与Level 17原理完全相同，仅参数名和默认值有差异。 | `?arg01=grammar&arg02= onmouseover=alert(1)` | 复用Level 17的绕过思路，调整参数名即可。<br>*(截图与原理同Level 17)* |
| **Level 19/20** | **Flash文件注入 (SWF XSS)** | - | **说明**：因Adobe Flash Player已全面停用，此类漏洞在现代浏览器中已无测试环境和实际危害，故未进行测试。 |

---

## 🧠 技术总结与分类

### 1. 常见过滤与防护类型
- **关键词黑名单**：过滤`<script>`、`on`、`javascript`等。
- **字符转义/删除**：对引号、尖括号进行HTML实体转义，或直接删除敏感字符串。
- **输入校验**：强制要求输入内容包含特定格式（如`http://`）。
- **上下文限制**：将用户输入严格限制在HTML文本节点，但可能疏忽了标签属性、URL、CSS或脚本上下文。
- **来源限制**：仅信任页面表单输入，忽略了HTTP请求头（Referer, User-Agent, Cookie）作为输入源的风险。

### 2. 核心绕过技巧总结
| 技巧 | 原理 | 典型关卡 |
| :--- | :--- | :--- |
| **标签与属性变换** | 当`<script>`和`on`事件被禁时，使用`<img>`、`<a>`等标签及`href`、`src`等属性。 | Level 5, 17, 18 |
| **大小写/双写混淆** | 利用过滤逻辑不严谨，通过大小写变异或双写关键词（如`scrscriptipt`）绕过删除。 | Level 6, 7 |
| **伪协议利用** | 在允许的URL属性（如`href`）中使用`javascript:`伪协议执行代码。 | Level 5, 8, 9 |
| **字符编码与替代** | 使用URL编码（`%0a`）、HTML实体或注释（`//`）绕过对空格、特定字符串的过滤。 | Level 9, 16 |
| **输入源拓展** | 从常规表单输入拓展至HTTP请求头、隐藏表单域等“非常规”输入源。 | Level 10, 11, 12, 13 |
| **客户端框架利用** | 利用如AngularJS `ng-include`等客户端功能动态加载恶意内容。 | Level 15 |

### 3. 漏洞挖掘与利用思维流程
1.  **信息收集**：分析所有可能的输入点（表单、URL参数、HTTP头、客户端代码）。
2.  **规则探针**：提交简单测试载荷（如`<>``"` `'`），观察过滤、转义或删除行为。
3.  **上下文判断**：确定输入被插入的位置（HTML文本、标签属性、JavaScript字符串等）。
4.  **载荷构造**：根据上下文和过滤规则，组合匹配的绕过技巧，构造最终Payload。
5.  **触发验证**：确认执行方式（自动触发、事件触发、交互触发）并完成利用。

### 4. 关键启示与防御建议
- **勿依赖黑名单**：如Level 6/7所示，黑名单极易被绕过。应采用**白名单**过滤，或对输入进行严格的**上下文相关输出编码**。
- **最小化攻击面**：如Level 11-13所示，应严格校验所有用户可控数据，包括HTTP头部。设置严格的**Content Security Policy (CSP)** 可以有效遏制XSS。
- **废弃技术风险**：如Level 19/20所代表的Flash XSS，随着技术淘汰，相关漏洞威胁降低，但启示我们应及时**淘汰存在固有安全风险的旧技术**。

## 💡 个人学习感悟
通过这18个关卡的实战，我深刻体会到XSS的本质是“**数据被误执行为代码**”。实战中，比记住Payload更重要的是掌握**分析过滤逻辑、判断输出上下文、灵活组合绕过技巧**的系统性思维。同时，作为防御者视角，也深刻理解了“**默认拒绝，最小权限**”安全原则的重要性，单纯依赖过滤绝非正道，必须采用编码、CSP等纵深防御措施。

---
*本报告仅用于合法安全学习与研究，所有测试均在本地授权靶场环境中完成。请严格遵守《网络安全法》，切勿对未授权目标进行任何测试。*
