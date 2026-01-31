# Upload-Lab 文件上传漏洞完整实战报告（21关全）

## 🎯 测试概况
- **靶场名称**：Upload-Lab
- **测试目标**：掌握文件上传漏洞的各类防护机制与绕过方法，深入理解服务端校验逻辑、中间件解析特性、系统底层特性及综合过滤绕过思路
- **测试环境**：本地虚拟机 (Kali Linux/Docker)，靶场地址：`http://192.168.59.136/upload/`
- **核心工具**：浏览器F12开发者工具、Burp Suite、CMD（图片马制作）、AntSword、二进制编辑器、十六进制编辑器
- **报告说明**：全关卡可复现，无环境依赖；所有测试截图已上传至仓库 `./assets_upload/` 目录，占位符链接直接替换为实际截图地址即可，图片语法均为GitHub标准渲染格式

## 📚 全关卡实战记录
### Level 1-5：基础校验绕过（前端/简单服务端过滤）
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :---- | :---- | :---- | :---- | :---- |
| **Level 1** | 仅前端JavaScript校验扩展名（仅允许jpg/png/gif），服务端无任何校验 | `webshell.php`（内容：`<?php @eval($_POST['pass']);?>`） | 绕过前端JS限制（服务端无兜底校验） | 1. 直接上传`webshell.php`，触发前端弹窗拦截；<br>2. F12开发者工具禁用JavaScript；<br>3. 重新上传，服务端无校验，上传成功；<br>![L1 前端JS拦截](https://github.com/user-attachments/assets/02403eee-e2b6-4ddb-8110-9fd02dbdbc03)<br>![L1 禁用前端JS](https://github.com/user-attachments/assets/0ef86f49-521a-4bad-a0ec-742c723b6d3f)<br>![L1 上传成功](https://github.com/user-attachments/assets/c595b9cd-5e8d-4e2d-af28-de39d50e4897) |
| **Level 2** | 取消前端校验，服务端仅校验HTTP请求的Content-Type（MIME类型） | `webshell.php` + Burp抓包修改`Content-Type: image/jpeg` | 伪造合法图片MIME类型，绕过服务端类型校验 | 1. 选择`webshell.php`上传，Burp Suite拦截请求；<br>2. 将请求头中`Content-Type`改为`image/jpeg`后转发；<br>3. 服务端校验MIME通过，上传成功；<br>![L2 拦截上传请求](https://github.com/user-attachments/assets/57b64772-1563-4d89-b57a-1ac661a4d4af)<br>![L2 修改MIME成功](https://github.com/user-attachments/assets/ff1f5f2d-d310-47c1-8857-6295565f572c) |
| **Level 3** | 服务端黑名单过滤.php/.asp/.jsp等常见脚本扩展名，Apache默认支持非主流PHP扩展名解析 | `webshell.phtml` / `webshell.php5` / `webshell.php3` | 利用Apache可解析的非主流PHP扩展名，绕过黑名单限制 | 1. 将恶意文件重命名为`webshell.phtml`；<br>2. 直接上传，服务端黑名单无该扩展名，校验通过；<br>3. 访问文件路径，Apache解析为PHP执行；<br>![L3 重命名非主流扩展名](https://github.com/user-attachments/assets/86976ec6-f642-4bf8-802a-730fcfba355d)<br>![L3 非主流扩展名生效](https://github.com/user-attachments/assets/9e87fabc-ef73-4e95-8bcc-6587c7ab617f)<br>![L3 非主流扩展名列表](https://github.com/user-attachments/assets/95f535ec-5c53-444d-a98a-3c69726ba635) |
| **Level 4** | 服务端黑名单拦截所有PHP相关扩展名（含非主流），未严格拦截Apache配置文件.htaccess | `.htaccess`（内容：`AddType application/x-httpd-php .jpg`）+ 图片马`webshell.jpg` | 上传.htaccess配置文件，强制服务器将.jpg文件解析为PHP代码 | 1. 编写`.htaccess`配置文件并保存；<br>2. 先上传`.htaccess`，服务端未拦截；<br>3. 上传jpg格式图片马`webshell.jpg`；<br>4. 访问`webshell.jpg`，Apache按配置解析为PHP执行；<br>![L4 编写.htaccess](https://github.com/user-attachments/assets/ad419606-cd8b-4885-8c55-8bc20f9a28db)<br>![L4 .htaccess解析图片马](https://github.com/user-attachments/assets/d127aa63-6e10-4765-9258-4f65979b1700) |
| **Level 5** | 服务端黑名单过滤常规/非主流脚本扩展名，但未对扩展名进行大小写统一处理 | `webshell.pHP` / `webshell.PHTML` | 利用Windows系统文件名大小写不敏感的特性，绕过黑名单字符匹配 | 1. 将恶意文件命名为`webshell.pHP`（大小写混合）；<br>2. 直接上传，服务端黑名单仅匹配小写，校验通过；<br>3. Windows服务器自动将文件名转为小写`webshell.php`，正常解析执行；<br>![L5 大小写混淆命名](https://github.com/user-attachments/assets/873389ce-5b21-4251-859c-296d9cd6ef10)<br>![L5 大小写绕过成功](https://github.com/user-attachments/assets/4b8efcb2-cbd6-453f-a00a-a25be6380c3a) |

### Level 6-10：Windows系统特性与逻辑过滤绕过
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :---- | :---- | :---- | :---- | :---- |
| **Level 6** | 修复扩展名大小写过滤，未处理Windows文件名末尾的**英文半角空格** | `webshell.php `（末尾带1个英文半角空格） | 利用Windows自动去除文件名末尾空格的系统特性 | 1. 重命名恶意文件为`webshell.php `（手动添加末尾空格）；<br>2. 直接上传，服务端未识别畸形扩展名，校验通过；<br>3. Windows服务器保存时自动剔除末尾空格，还原为`webshell.php`；<br>![L6 末尾空格命名](https://github.com/user-attachments/assets/49c633a0-5c63-4170-9fdb-c0cfab90097f)<br>![L6 末尾空格绕过成功](https://github.com/user-attachments/assets/814f1db9-bae2-4c08-bff9-062a931d535f) |
| **Level 7** | 修复末尾空格过滤，未处理Windows文件名末尾的**英文半角点** | `webshell.php.`（末尾带1个英文半角点） | 利用Windows自动去除文件名末尾点的系统特性 | 1. 重命名恶意文件为`webshell.php.`（手动添加末尾点）；<br>2. 直接上传，服务端未拦截该命名；<br>3. Windows服务器保存时自动删除末尾点，还原为`webshell.php`；<br>![L7 末尾点绕过成功](https://github.com/user-attachments/assets/814f1db9-bae2-4c08-bff9-062a931d535f) |
| **Level 8** | 修复末尾空格/点过滤，未处理Windows `::$DATA` 文件流标识特性 | `webshell.php::$DATA` | 利用Windows`::$DATA`特性，服务器忽略该标识仅保留前置合法文件名 | 1. 重命名恶意文件为`webshell.php::$DATA`；<br>2. 直接上传，服务端无相关过滤规则；<br>3. Windows服务器解析时忽略`::$DATA`，文件实际保存为`webshell.php`；<br>![L8 ::$DATA命名](https://github.com/user-attachments/assets/145be784-4139-4f24-a84e-99216b0005e7)<br>![L8 ::$DATA特性绕过](https://github.com/user-attachments/assets/679c4321-9a8d-4fa7-9581-9dfdd4f55cbf) |
| **Level 9** | 修复单一系统特性过滤，未处理文件名末尾"点+英文半角空格"组合 | `webshell.php. `（末尾带"点+1个英文半角空格"） | 利用Windows自动去除文件名末尾点与空格的组合特性 | 1. 重命名恶意文件为`webshell.php. `（末尾加"点+空格"）；<br>2. 直接上传，服务端未拦截该畸形命名；<br>3. Windows服务器保存时自动剔除末尾点与空格，还原为`webshell.php`；<br>![L9 点+空格命名](https://github.com/user-attachments/assets/86a35db7-3ad0-46bd-88ca-a98b404b051a)<br>![L9 点+空格绕过成功](https://github.com/user-attachments/assets/placeholder) |
| **Level 10** | 服务端对扩展名关键词仅执行**单次删除**过滤 | `webshell.pphphp` | 双写关键词绕过单次过滤，剩余字符重组为合法的.php扩展名 | 1. 将恶意文件命名为`webshell.pphphp`；<br>2. 上传后服务端过滤"php"关键词，结果为`webshell.php`；<br>3. 访问文件路径，正常执行PHP代码；<br>![L10 双写关键词命名](https://github.com/user-attachments/assets/b6cbf351-7efc-4705-b630-1a4922e7d10b)<br>![L10 双写绕过成功](https://github.com/user-attachments/assets/c1b630ec-dc11-4cdd-9e19-78ae5962f67e) |

### Level 11-15：请求头/文件内容/路径截断绕过
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :---- | :---- | :---- | :---- | :---- |
| **Level 11** | 服务端通过GET参数指定文件保存路径，存在%00空字节截断漏洞（PHP<5.3.4） | GET参数：`save_path=upload/webshell.php%00` + 文件名`webshell.jpg` | 利用PHP空字节截断特性，解析时遇%00停止，忽略后续字符 | 1. 上传正常jpg文件，Burp Suite拦截请求；<br>2. 修改GET参数`save_path`为`upload/webshell.php%00`；<br>3. 将%00转为原始空字节（Burp中按`Ctrl+U`）后转发；<br>![L11 路径%00截断](https://github.com/user-attachments/assets/b922c896-bf7e-4a3e-9f31-ef8e7aa7a89c)<br>![L11 空字节转换](https://github.com/user-attachments/assets/a1a15708-7cf2-4c0c-a276-4b69ee501886) |
| **Level 12** | 服务端通过POST参数指定文件保存路径，存在%00空字节截断漏洞 | POST参数：`save_path=upload/webshell.php%00` + 文件名`webshell.jpg` | POST参数不会自动URL解码，手动插入原始空字节实现路径截断 | 1. Burp拦截上传请求，找到POST参数`save_path`；<br>2. 修改为`upload/webshell.php`并将空格的十六进制20替换为00原始空字节；<br>3. 转发请求，服务端按截断路径保存为`webshell.php`；<br>![L12 找到POST参数](https://github.com/user-attachments/assets/67b20455-93e6-42be-91f6-a290a8b8b1dd)<br>![L12 替换十六进制00](https://github.com/user-attachments/assets/5a60a973-9f4c-41aa-ad08-7dc07ea51657)<br>![L12 上传成功](https://github.com/user-attachments/assets/d034b1a9-8496-4f1e-aa36-f7508a316a24) |
| **Level 13** | 服务端校验文件头幻数（仅识别真实图片文件），无其他严格过滤 | 图片马`webshell.jpg`（CMD命令：`copy 1.jpg/b + webshell.php/a webshell.jpg`） | 制作带合法图片文件头的图片马，绕过服务端文件内容校验 | 1. 用CMD命令合成图片与恶意脚本为图片马（/b为二进制，/a为文本）；<br>2. 直接上传图片马，配合.htaccess解析执行或利用靶场include目录文件包含；<br>![L13 制作图片马](https://github.com/user-attachments/assets/c4c62ff0-b144-4e87-90b3-4f192847a102)<br>![L13 图片马上传成功](https://github.com/user-attachments/assets/b1cc854d-c96e-4618-ba15-ddcc02454c34) |
| **Level 14** | 服务端通过`getimagesize()`函数校验图片头，仅验证是否为真实图片 | 同Level13的图片马`webshell.jpg` | `getimagesize()`仅检测图片头字节是否合法，不会校验文件后续内容，可嵌入恶意代码 | 1. 上传Level13制作的合法图片马；<br>2. 服务端`getimagesize()`校验图片头通过，上传成功；<br>3. 配合.htaccess配置文件解析执行；<br>![L14 绕过getimagesize校验](https://github.com/user-attachments/assets/1598f309-352f-44e5-9aa7-955490cdf3f9) |
| **Level 15** | 服务端通过`exif_imagetype()`函数校验图片头，仅识别真实图片文件 | 无损坏合法图片马`webshell.jpg` | `exif_imagetype()`检测图片头前几个字节的幻数，制作无损坏图片马可通过校验 | 1. 制作未损坏的jpg/png格式图片马（避免破坏图片头幻数）；<br>2. 上传后`exif_imagetype()`校验图片头通过；<br>3. 配合.htaccess解析执行；<br>![L15 绕过exif校验](https://github.com/user-attachments/assets/91c791e9-28ea-4768-afbc-102ef5920a11) |

### Level 16-21：高级过滤与综合利用绕过
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :---- | :---- | :---- | :---- | :---- |
| **Level 16** | 服务端对上传图片进行二次渲染压缩，普通图片马代码会被清除 | 嵌入EXIF信息的免压缩图片马 | 将PHP恶意代码嵌入图片的EXIF属性中，服务端二次渲染仅处理图片像素，保留EXIF信息 | 1. 用PS/美图秀秀/ExifTool将PHP代码写入图片的EXIF备注/作者属性；<br>2. 上传渲染后的图片马，配合.htaccess解析执行；<br>![L16 写入EXIF信息]<img width="1680" height="684" alt="image" src="https://github.com/user-attachments/assets/21c01734-e847-4e2f-997d-ab0e31fc0129" />
 |
| **Level 17** | 服务端对图片进行深度二次渲染，清除所有嵌入的恶意代码 | 抗渲染图片马（对比渲染前后二进制，在未修改位置嵌入代码） | 分析图片渲染前后的二进制差异，找到服务器未修改的字节区域嵌入PHP代码 | 1. 上传正常图片，保存服务端渲染后的图片；<br>2. 用二进制编辑器对比原始图片与渲染后图片的差异；<br>3. 在未被修改的字节区域嵌入恶意代码制作抗渲染图片马；<br>![L17 对比二进制差异]<img width="1785" height="1295" alt="image" src="https://github.com/user-attachments/assets/92811e18-4810-4a06-bee7-88e6e5b9493f" /><br>![L17 抗渲染图片马成功](https://github.com/user-attachments/assets/placeholder) |
| **Level 18** | 服务端先保存文件到服务器再进行校验，校验失败则删除文件（条件竞争漏洞） | `webshell.php` + Python多线程访问脚本 | 利用服务端"保存-校验-删除"的时间差，在文件被删除前快速访问执行恶意代码 | 1. Burp Suite开启重放器，持续发送上传`webshell.php`的请求；<br>2. 运行Python多线程脚本，持续访问文件上传后的预期路径；<br>3. 成功在文件被删前访问并执行PHP代码；<br>![L18 条件竞争脚本](https://github.com/user-attachments/assets/placeholder)<br>![L18 条件竞争成功](https://github.com/user-attachments/assets/placeholder) |
| **Level 19** | 结合路径%00截断+图片头校验，服务端对保存路径处理存在漏洞 | POST参数`save_path=upload/webshell.php%00` + 图片马`webshell.jpg` | 手动构造POST参数原始空字节实现路径截断，同时合法图片马绕过服务端内容校验 | 1. 上传图片马并通过Burp拦截请求；<br>2. 找到POST参数`save_path`，修改为`upload/webshell.php%00`并插入原始空字节；<br>3. 转发请求，服务端截断路径并将图片马保存为`webshell.php`；<br>![L19 路径截断+图片马](https://github.com/user-attachments/assets/placeholder) |
| **Level 20** | 文件名+路径多规则过滤，存在系统特性组合漏洞 | `webshell.php.::$DATA`（多特性组合） | 叠加Windows系统特性（末尾点+::$DATA），绕过多规则文件名过滤 | 1. 重命名恶意文件为`webshell.php.::$DATA`（组合畸形命名）；<br>2. 直接上传，服务端未拦截该组合命名规则；<br>3. Windows服务器解析时自动剔除末尾点和::$DATA，还原为`webshell.php`；<br>![L20 多特性组合命名](https://github.com/user-attachments/assets/placeholder)<br>![L20 多特性组合绕过成功](https://github.com/user-attachments/assets/placeholder) |
| **Level 21** | 综合多规则过滤（修复所有系统特性/双写/大小写）+图片头幻数校验+路径固定（无截断）+扩展名白名单 | 合法图片马`webshell.jpg`（同Level13）+ 靶场`include`目录文件包含漏洞 | 绕开综合文件名过滤，图片头校验通过实现上传，结合文件包含漏洞执行恶意代码 | 1. 用CMD制作合法jpg格式图片马，确保图片头幻数无损坏；<br>2. 直接上传图片马，服务端综合过滤校验通过，上传成功并返回文件路径；<br>3. 访问靶场`include`目录的文件包含页面，传入图片马路径实现代码执行；<br>![L21 图片马上传](https://github.com/user-attachments/assets/placeholder)<br>![L21 文件包含执行](https://github.com/user-attachments/assets/placeholder) |

## 🧠 防御最佳实践
| 防御维度 | 具体措施 |
| :---- | :---- |
| 扩展名校验 | 强制使用**严格白名单**（仅允许业务必需的静态文件扩展名：jpg/png/gif/css/js/pdf等），拒绝任何脚本类扩展名 |
| 文件类型校验 | 结合**文件头幻数校验+二进制内容检测+专业恶意代码扫描**三重验证，避免仅校验MIME类型或单一函数检测 |
| 服务器配置 | 1. 上传目录禁止脚本执行权限（Apache设置AllowOverride None，Nginx设置location禁止php解析）；<br>2. 关闭中间件危险解析规则（禁用Apache的.htaccess、关闭Nginx畸形扩展名解析）；<br>3. 及时更新中间件/PHP版本，修复空字节截断、解析漏洞等已知问题 |
| 存储策略 | 1. 文件上传后进行**随机重命名**（采用UUID+哈希后缀，避免原文件名泄露和路径猜测）；<br>2. 上传文件存储到**非Web可访问目录**，通过后端接口做权限校验后间接调用；<br>3. 禁止上传目录作为文件包含/解析的根目录 |
| 代码逻辑防护 | 1. 校验与保存**原子性执行**，避免先保存后校验的条件竞争问题；<br>2. 对文件名做严格清洗（过滤空格、点、::$DATA等特殊字符，统一转为小写）；<br>3. 图片上传后二次渲染时**清除所有EXIF信息**，仅保留图片像素数据 |
| 额外防护 | 1. 接入WAF对文件上传请求进行深度过滤（检测畸形命名、恶意代码、空字节等）；<br>2. 开启文件上传**全量审计日志**，记录上传者IP、文件名、保存路径、上传时间等；<br>3. 限制文件上传大小和上传频率，防止恶意文件批量上传 |

## 🗺️ Upload-Lab21关文件上传漏洞绕过思路（Mermaid思维导图，GitHub直接渲染）
```mermaid
graph TD
    A[Upload-Lab21关全流程绕过] --> B[基础校验绕过<br/>Level1-5]
    A --> C[Windows系统特性绕过<br/>Level6-10]
    A --> D[内容/路径截断绕过<br/>Level11-15]
    A --> E[高级综合过滤绕过<br/>Level16-21]

    %% 基础校验绕过 Level1-5
    B --> B1[Level1：前端JS校验]
    B --> B2[Level2：MIME类型校验]
    B --> B3[Level3：黑名单扩展名]
    B --> B4[Level4：全PHP扩展名黑名单]
    B --> B5[Level5：大小写未过滤]
    B1 --> B11[禁用JS / Burp抓包改包]
    B2 --> B21[抓包修改Content-Type为image/jpeg]
    B3 --> B31[Apache非主流扩展名：phtml/php5/php3]
    B4 --> B41[.htaccess+图片马组合]
    B5 --> B51[混合大小写：pHP/PHTML]

    %% Windows系统特性绕过 Level6-10
    C --> C1[Level6：末尾空格未过滤]
    C --> C2[Level7：末尾点未过滤]
    C --> C3[Level8：::$DATA未过滤]
    C --> C4[Level9：点+空格组合]
    C --> C5[Level10：单次关键词过滤]
    C1 --> C11[文件名后加英文半角空格：php ]
    C2 --> C21[文件名后加英文半角点：php.]
    C3 --> C31[文件名后加::$DATA：php::$DATA]
    C4 --> C41[点+空格组合：php. ]
    C5 --> C51[双写关键词：pphphp]

    %% 内容/路径截断绕过 Level11-15
    D --> D1[Level11：GET参数%00截断]
    D --> D2[Level12：POST参数%00截断]
    D --> D3[Level13：文件头幻数校验]
    D --> D4[Level14：getimagesize校验]
    D --> D5[Level15：exif_imagetype校验]
    D1 --> D11[%00转原始空字节（Ctrl+U）]
    D2 --> D21[手动替换十六进制00原始空字节]
    D3 --> D31[CMD制作图片马：copy 1.jpg/b+php/a]
    D4 --> D41[合法图片头+恶意代码图片马]
    D5 --> D51[无损坏完整图片马（保留幻数）]

    %% 高级综合过滤绕过 Level16-21
    E --> E1[Level16：图片二次渲染]
    E --> E2[Level17：深度二次渲染]
    E --> E3[Level18：条件竞争漏洞]
    E --> E4[Level19：路径截断+图片头]
    E --> E5[Level20：多特性组合过滤]
    E --> E6[Level21：全规则综合过滤]
    E1 --> E11[EXIF信息嵌入恶意代码]
    E2 --> E21[对比二进制差异+抗渲染图片马]
    E3 --> E31[持续上传+多线程访问（时间差）]
    E4 --> E41[POST参数%00截断+合法图片马]
    E5 --> E51[系统特性叠加：php.::$DATA]
    E6 --> E61[合法图片马+include目录文件包含]

    %% 通用辅助手段
    F[通用利用手段] --> F1[.htaccess配置文件解析]
    F[通用利用手段] --> F2[CMD/二进制编辑器制作图片马]
    F[通用利用手段] --> F3[Burp Suite抓包/改包/重放]
    F[通用利用手段] --> F4[AntSword连接WebShell验证]
    B --> F
    C --> F
    D --> F
    E --> F
