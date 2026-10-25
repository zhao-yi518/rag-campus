# 部署与环境配置说明

本项目为 Node.js 单服务应用（Express + node:sqlite），无外部数据库依赖，一台 2 核 2G 云服务器即可运行。

## 一、环境要求

| 组件 | 版本要求 | 说明 |
|---|---|---|
| Node.js | ≥ 22.0 | 使用内置 `node:sqlite`，低版本需改用 better-sqlite3 |
| npm | 随 Node 附带 | 依赖安装 |
| 内存 | ≥ 512MB | 检索为纯内存计算，无向量库 |

## 二、安装与启动

```bash
# 1. 安装依赖
npm install

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，填入你的 DASHSCOPE_API_KEY（获取：https://bailian.console.aliyun.com/）

# 3. 启动
npm start
# 或开发模式（需 node --watch）：
node --watch server.js

# 4. 访问
# http://localhost:3000
```

首次启动会自动：
- 创建 SQLite 数据库 `data.db`（账号表/会话表/知识表/日志表）
- 把 `knowledge.txt` 初始知识导入知识库（91 条）
- 按 `ADMIN_PASSWORD` 创建开发者账号 `developer`

## 三、环境变量清单

完整说明见 [.env.example](../.env.example)：

| 变量 | 必填 | 说明 |
|---|---|---|
| `DASHSCOPE_API_KEY` | ✅ | 阿里云百炼 API Key，驱动大模型回答 |
| `LLM_BASE_URL` | 否 | 默认百炼 OpenAI 兼容地址 |
| `LLM_MODEL` | 否 | 默认 `qwen-plus` |
| `PORT` | 否 | 默认 `3000` |
| `ADMIN_PASSWORD` | 否 | 首次启动创建开发者账号用 |

## 四、默认账号

| 角色 | 账号 | 初始密码 | 说明 |
|---|---|---|---|
| 开发者 | `developer` | 见部署时设置的 `ADMIN_PASSWORD` | 全部权限 |
| 学生 | 学号 | 姓名拼音+学号后两位 | 由 Excel 批量导入生成 |
| 教师 | 工号 | 姓名拼音+工号后两位 | 同上 |

> 首次登录后请立即在「账号管理」中修改密码。

## 五、效果评测（可选，验证检索质量）

登录开发者账号 → 数据看板 → 「运行效果评测」，即对 `eval-questions.json` 中 30 题
（15 库内 + 15 库外）执行基准测试，输出 Top1/Top3 命中率、拒识率与平均耗时。
参考结果：Top1 86.7%，Top3 93.3%，拒识 73.3%，平均检索耗时 ~1.6ms。

## 六、生产部署要点

1. **反向代理**：建议 Nginx 转发 80/443 → 3000，并开启 gzip
2. **进程守护**：`pm2 start server.js --name rag-campus`
3. **数据备份**：定期备份 `data.db` 与 `uploads/`
4. **安全**：`.env` 不入 Git；生产环境修改所有默认密码；建议开启 HTTPS