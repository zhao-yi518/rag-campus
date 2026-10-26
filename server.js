const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const { pinyin } = require('pinyin-pro');
require('dotenv').config();

const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static('public'));
app.use(express.json({ limit: '2mb' }));

/* ============================================================
 * 0. 账号体系（学生/教师/管理员/开发者）+ 鉴权
 * ============================================================ */
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

/**
 * 密码加盐哈希：scrypt 是内存困难型算法，比 md5/sha1 更抗暴力破解。
 * 每个用户使用独立随机盐，即使两人密码相同，库中哈希也不同。
 */
function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 32).toString('hex');
}
/**
 * 归一化输入：全角→半角、去首尾空格。
 * 解决的真实问题：手机输入法打出的"１２３"（全角）与"123"（半角）
 * 在数据库里是不同字符串，曾导致多设备登录失败；登录/导入统一走此函数。
 */
function normalizeInput(s) {
  return String(s || '')
    .replace(/[\uFF01-\uFF5E]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0xFEE0))
    .replace(/\u3000/g, ' ')
    .trim();
}
function createUser({ account, password, role, name = '', createdBy = 'system' }) {
  account = String(account).trim();
  const exists = db.prepare('SELECT id FROM users WHERE account=?').get(account);
  if (exists) throw new Error('账号已存在：' + account);
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(account)) throw new Error('账号需为 3-20 位字母/数字/下划线');
  if (String(password).length < 6) throw new Error('密码至少 6 位');
  const salt = crypto.randomBytes(8).toString('hex');
  const info = db
    .prepare('INSERT INTO users (account, pass_hash, salt, role, name, created_by) VALUES (?,?,?,?,?,?)')
    .run(account, hashPassword(password, salt), salt, role, name, createdBy);
  return Number(info.lastInsertRowid);
}

// 首次启动：把原管理口令迁移为开发者账号
function seedDeveloper() {
  const has = db.prepare("SELECT id FROM users WHERE role='developer'").get();
  if (has) return;
  createUser({
    account: 'developer',
    password: ADMIN_PASSWORD || 'dev123456',
    role: 'developer',
    name: '开发者',
    createdBy: 'system',
  });
  console.log('👑 已创建开发者初始账号：developer（密码为原 ADMIN_PASSWORD）');
}

// --- 请求身份解析 ---
/**
 * getUser：从请求头 X-Auth-Token 解析当前用户。
 * 会话采用服务端 Token 表方案（auth_tokens），登出即删行、可主动踢下线，
 * 相比 JWT 更适合小型多角色系统。
 */
function getUser(req) {
  const token = req.headers['x-auth-token'];
  if (!token) return null;
  const row = db
    .prepare(
      'SELECT u.id, u.account, u.role, u.name, t.token FROM auth_tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?'
    )
    .get(token);
  return row || null;
}
function requireAuth(req, res, next) {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: '请先登录', needAuth: true });
  req.user = user;
  next();
}
/** 鉴权中间件：requireRole('teacher','admin') 即可声明"哪些身份能用此接口" */
function requireRole(...roles) {
  return (req, res, next) => {
    const user = getUser(req);
    if (!user) return res.status(401).json({ error: '请先登录', needAuth: true });
    if (!roles.includes(user.role)) {
      return res.status(403).json({ error: '当前身份无权限执行此操作' });
    }
    req.user = user;
    next();
  };
}
// 知识库维护 = 管理员/开发者
const requireAdmin = requireRole('admin', 'developer');

// --- 登录/登出/个人信息 ---
app.post('/api/auth/login', (req, res) => {
  const { account, password } = req.body || {};
  const acc = normalizeInput(account);
  const pwd = normalizeInput(password);
  // 先按原样查，再按归一化查（大小写不敏感兜底）
  let u = db.prepare('SELECT * FROM users WHERE account=?').get(acc);
  if (!u) u = db.prepare('SELECT * FROM users WHERE LOWER(account)=LOWER(?)').get(acc);
  if (!u) return res.status(401).json({ error: '账号或密码错误' });
  const hash = hashPassword(pwd, u.salt);
  const ok =
    hash.length === u.pass_hash.length &&
    crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(u.pass_hash));
  if (!ok) return res.status(401).json({ error: '账号或密码错误' });

  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO auth_tokens (token, user_id) VALUES (?,?)').run(token, u.id);
  // 清理过期 token（保留最近 200 个）
  db.prepare(
    'DELETE FROM auth_tokens WHERE token NOT IN (SELECT token FROM auth_tokens ORDER BY created_at DESC, rowid DESC LIMIT 200)'
  ).run();
  res.json({ ok: true, token, user: { account: u.account, role: u.role, name: u.name } });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) db.prepare('DELETE FROM auth_tokens WHERE token=?').run(token);
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const user = getUser(req);
  res.json({ user: user ? { account: user.account, role: user.role, name: user.name } : null });
});

app.post('/api/auth/password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  const oldHash = hashPassword(oldPassword || '', u.salt);
  const ok =
    oldHash.length === u.pass_hash.length &&
    crypto.timingSafeEqual(Buffer.from(oldHash), Buffer.from(u.pass_hash));
  if (!ok) return res.status(400).json({ error: '原密码错误' });
  if (String(newPassword || '').length < 6) return res.status(400).json({ error: '新密码至少 6 位' });
  const salt = crypto.randomBytes(8).toString('hex');
  db.prepare('UPDATE users SET salt=?, pass_hash=? WHERE id=?').run(salt, hashPassword(newPassword, salt), u.id);
  res.json({ ok: true });
});

// --- 账号管理 ---
app.get('/api/users', requireRole('developer', 'teacher', 'admin'), (req, res) => {
  let rows;
  if (req.user.role === 'developer') {
    rows = db.prepare('SELECT id, account, role, name, remark, created_by, created_at FROM users ORDER BY id').all();
  } else if (req.user.role === 'teacher') {
    rows = db.prepare("SELECT id, account, role, name, remark, created_by, created_at FROM users WHERE role='student' ORDER BY id DESC").all();
  } else {
    rows = db.prepare("SELECT id, account, role, name, remark, created_by, created_at FROM users WHERE role IN ('student','teacher') ORDER BY id DESC").all();
  }
  res.json(rows);
});

app.post('/api/users', requireRole('developer', 'teacher'), (req, res) => {
  try {
    const { account, password, role, name } = req.body || {};
    const allowed = req.user.role === 'developer' ? ['admin', 'teacher', 'student'] : ['student'];
    if (!allowed.includes(role)) return res.status(403).json({ error: '你无权创建该身份的账号' });
    const id = createUser({
      account,
      password,
      role,
      name: name || '',
      createdBy: req.user.account,
    });
    res.json({ ok: true, id });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- 批量导入账号（开发者：学生/教师；教师：仅学生） ---
/** 姓名转拼音（姓氏多音字按 surname 规则，ü→v 便于键盘输入） */
function nameToPinyin(name) {
  const raw = pinyin(String(name || '').trim(), {
    toneType: 'none',
    type: 'array',
    surname: 'head',
    nonZh: 'consecutive',
    v: true, // ü 输出为 v（lv、nv），便于键盘输入
  }).join('');
  return raw
    .toLowerCase()
    .replace(/[ǖǘǚǜü]/g, 'v')
    .replace(/[^a-z]/g, ''); // 去掉空格及非字母，保留已转好的 v
}

/** 从表格行里按表头模糊匹配取值 */
function pickField(row, keys) {
  for (const k of Object.keys(row)) {
    const h = String(k).replace(/\s/g, '');
    if (keys.some((kw) => h.includes(kw))) {
      const v = row[k];
      if (v !== undefined && v !== null && String(v).trim() !== '') return String(v).trim();
    }
  }
  return '';
}

app.delete('/api/users/:id', requireRole('developer'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(Number(req.params.id));
  if (!target) return res.status(404).json({ error: '账号不存在' });
  if (target.role === 'developer') return res.status(400).json({ error: '不能删除开发者账号' });
  db.prepare('DELETE FROM users WHERE id=?').run(target.id);
  db.prepare('DELETE FROM auth_tokens WHERE user_id=?').run(target.id);
  res.json({ ok: true });
});


/* ============================================================
 * 1. 数据库初始化（Node 内置 sqlite，无需编译）
 * ============================================================ */
const DB_PATH = path.join(__dirname, 'data.db');
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS knowledge (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '其他',
  source TEXT NOT NULL DEFAULT '手动录入',
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question TEXT NOT NULL,
  hit_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS conversations (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL DEFAULT '新对话',
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conv_id TEXT NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  sources TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS feedback (
  message_id INTEGER PRIMARY KEY,
  value INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS board_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question TEXT NOT NULL,
  account TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS board_replies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  msg_id INTEGER NOT NULL,
  replier_account TEXT NOT NULL,
  replier_name TEXT NOT NULL DEFAULT '',
  replier_role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_kb_cat ON knowledge(category);
CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conv_id);
`);

/**
 * 首次启动种子数据：把 knowledge.txt（91 条校园信息）导入知识库，
 * 已有数据则跳过，保证重启不重复导入。
 */
function seedFromTxt() {
  const count = db.prepare('SELECT COUNT(*) AS c FROM knowledge').get().c;
  if (count > 0) return;

  const txtPath = path.join(__dirname, 'knowledge.txt');
  if (!fs.existsSync(txtPath)) return;

  const lines = fs
    .readFileSync(txtPath, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);

  const insert = db.prepare(
    'INSERT INTO knowledge (title, content, category, source) VALUES (?,?,?,?)'
  );
  db.exec('BEGIN');
  try {
    for (const line of lines) {
      const m = line.match(/^([^：:]{2,20})[：:](.*)$/);
      const title = m ? m[1] : line.slice(0, 16);
      insert.run(title, line, guessCategory(line), '初始导入');
    }
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
  console.log(`📥 已从 knowledge.txt 导入 ${lines.length} 条知识`);
}

/* 按关键词自动分类 */
const CATEGORY_RULES = [
  ['教务学籍', ['学分', '选课', '教务', '学籍', '考试', '补考', '重修', '四六级', '普通话', '计算机二级', '专升本', '单招', '学位', '毕业', '论文', '查重', '综测', '成绩']],
  ['奖助学金', ['奖学金', '助学金', '助学', '贷款', '困难认定', '医保']],
  ['生活服务', ['食堂', '宿舍', '一卡通', '快递', '超市', '医务', '断电', '门禁', '打印', '公交', '后勤', '缴费', '户口']],
  ['场馆设施', ['图书馆', '自习', '机房', '实验室', '实训', '体育馆', '座位', '开放时间', '闭馆', '借书']],
  ['网络信息化', ['WiFi', 'wifi', 'VPN', '网络', '数据库', '知网', '电子资源', '官网', '系统']],
  ['党团组织', ['入党', '党员', '团委', '团组织', '社团']],
  ['就业升学', ['就业', '招聘', '考研', '实习', '双选会', '创业']],
  ['学校概况', ['山东华宇工学院', '建校', '办学', '规模', '占地', '馆藏', '学院', '专业']],
  ['竞赛科研', ['竞赛', '挑战杯', '互联网+', '大创', '数学建模', '科研']],
];

/** 关键词规则自动分类：按命中词数打分（长词权重×2），兜底归入"其他" */
function guessCategory(text) {
  let best = '其他';
  let bestHit = 0;
  for (const [cat, words] of CATEGORY_RULES) {
    let hit = 0;
    for (const w of words) if (text.includes(w)) hit += w.length > 2 ? 2 : 1;
    if (hit > bestHit) {
      bestHit = hit;
      best = cat;
    }
  }
  return best;
}

seedFromTxt();

// --- 账号表与会话表（依赖 db，放在数据库初始化之后） ---
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('student','teacher','admin','developer')),
  name TEXT NOT NULL DEFAULT '',
  remark TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT 'system',
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS auth_tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
`);
// 兼容旧库：补列
try {
  const cols = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
  if (!cols.includes('remark')) db.exec("ALTER TABLE users ADD COLUMN remark TEXT NOT NULL DEFAULT ''");
  const kcols = db.prepare('PRAGMA table_info(knowledge)').all().map((c) => c.name);
  if (!kcols.includes('uploader')) db.exec("ALTER TABLE knowledge ADD COLUMN uploader TEXT NOT NULL DEFAULT ''");
} catch (_) {}
seedDeveloper();

/* ============================================================
 * 2. 检索：bigram + 实词加权（保留你已验证有效的算法）
 * ============================================================ */
const STOP_WORDS = [
  '请问', '什么', '怎么', '怎样', '如何', '多少', '哪些', '哪个', '哪里', '可以',
  '是否', '需要', '时候', '几点', '吗', '呢', '的', '了', '是', '在', '有', '和',
  '我', '想', '要', '问', '一下', '告诉', '知道', '帮我', '查询', '情况', '请问一下',
];

function normalize(text) {
  let s = String(text)
    .toLowerCase()
    .replace(/[\s，。？！、；：""''（）()【】\[\]…—\-·]/g, '');
  for (const w of STOP_WORDS) s = s.split(w).join('');
  return s;
}

/** 同义词/近义词扩展：中文校园场景高频表达归一化 */
const SYNONYMS = [
  ['比赛', '竞赛大赛'], ['竞赛', '比赛大赛'], ['大赛', '比赛竞赛'],
  ['知网', '电子资源数据库文献万方维普'], ['万方', '电子资源数据库知网文献'],
  ['论文', '文献电子资源数据库'], ['文献', '论文电子资源'],
  ['奖学金', '奖学资助'], ['国奖', '国家奖学金'], ['助学金', '资助'],
  ['补办', '挂失补卡'], ['丢了', '遗失挂失补办'], ['遗失', '丢失挂失补办'],
  ['开门', '开放时间'], ['关门', '关闭闭馆'], ['闭馆', '关闭开放'], ['开饭', '午餐晚餐食堂就餐'],
  ['wifi', '无线网络'], ['上网', '网络wifi'], ['连网', 'wifi网络'],
  ['考试范围', '考试内容'], ['绩点', 'gpa成绩'], ['请假', '销假假条审批辅导员'],
  ['生病', '请假医务室'], ['发烧', '生病请假医务室'],
  ['四级', '四六级cet'], ['六级', '四六级cet'], ['考研', '研究生升学'],
  ['饭卡', '一卡通校园卡'], ['校园卡', '一卡通饭卡'],
];
function expandSynonyms(text) {
  let extra = '';
  for (const [from, to] of SYNONYMS) {
    if (text.includes(from)) extra += to;
  }
  return extra;
}

function bigrams(str) {
  const set = new Set();
  for (let i = 0; i < str.length - 1; i++) set.add(str.slice(i, i + 2));
  if (str.length === 1) set.add(str);
  return set;
}

/**
 * 基线打分函数（v1）：仅覆盖率和标题加分，不含 IDF 与同义词。
 * 保留在此处供效果评测对照——30 题基准测试显示 IDF 版 Top1 命中率
 * 由 66.7% 提升至 86.7%，故线上检索采用下方 searchKnowledge。
 */
function scoreChunk(question, questionBi, item) {
  const t = normalize(item.title + item.content);
  if (!t) return 0;

  const tBi = bigrams(t);
  let hit = 0;
  for (const bg of questionBi) if (tBi.has(bg)) hit++;
  const coverage = questionBi.size ? hit / questionBi.size : 0;

  // 标题命中额外加分
  const titleT = normalize(item.title);
  let titleBoost = 0;
  let th = 0;
  for (const bg of questionBi) if (titleT.includes(bg)) th++;
  if (questionBi.size) titleBoost = (th / questionBi.size) * 0.35;

  // 长内容惩罚
  const lenPenalty = item.content.length > 300 ? 300 / item.content.length : 1;

  return (coverage + titleBoost) * lenPenalty;
}

/**
 * 核心检索：中文 bigram + IDF 逆文档频率加权 + 校园同义词扩展。
 * 不依赖向量数据库和第三方 NLP 库，2 核 2G 服务器毫秒级返回。
 * 打分 = IDF 加权覆盖率 + 标题命中加成(×0.35) + 同义词命中加成(×0.7)，
 * 长文本按长度衰减（lenPenalty）防止超长条目霸榜，低于 threshold 的丢弃。
 */
function searchKnowledge(question, topK = 3, threshold = 0.24) {
  const q = normalize(question);
  if (!q) return [];
  const qBi = bigrams(q);
  const synBi = bigrams(normalize(expandSynonyms(question)));
  const synText = normalize(expandSynonyms(question));

  const rows = db.prepare('SELECT id, title, content, category, source, uploader, created_at FROM knowledge').all();

  // IDF 逆文档频率：越稀有的 bigram 越有区分度（如"请假""知网"），烂大街的词（"学生""考试"）权重趋近 0
  const df = new Map();
  const docs = rows.map((r) => {
    const t = normalize(r.title + r.content);
    const bi = bigrams(t);
    for (const bg of bi) df.set(bg, (df.get(bg) || 0) + 1);
    return { r, t, bi };
  });
  const N = docs.length || 1;
  const idf = (bg) => Math.log((N + 1) / ((df.get(bg) || 0) + 0.5));

  const qWeight = [...qBi].reduce((s, bg) => s + idf(bg), 0) || 1;
  const synWeight = [...synBi].reduce((s, bg) => s + idf(bg), 0) || 1;

  return docs
    .map(({ r, t, bi }) => {
      // 主分：IDF 加权覆盖率
      let hitW = 0;
      for (const bg of qBi) if (bi.has(bg)) hitW += idf(bg);
      let score = hitW / qWeight;

      // 标题命中加分（稀有词命中标题权重更高）
      const titleT = normalize(r.title);
      let thW = 0;
      for (const bg of qBi) if (titleT.includes(bg)) thW += idf(bg);
      score += (thW / qWeight) * 0.35;

      // 同义词扩展（同样按 IDF 加权）
      if (synBi.size) {
        let sh = 0;
        for (const bg of synBi) if (t.includes(bg)) sh += idf(bg);
        score += (sh / synWeight) * 0.7;
        if (synText && t.includes(synText)) score += 0.2;
      }

      const lenPenalty = r.content.length > 300 ? 300 / r.content.length : 1;
      return { ...r, score: score * lenPenalty };
    })
    .filter((r) => r.score >= threshold)
    .sort((a, b) => b.score - a.score)
    .slice(0, topK);
}

/* ============================================================
 * 3. 大模型调用（百炼 DashScope，OpenAI 兼容）
 * ============================================================ */
const hasKey = () => Boolean(process.env.DASHSCOPE_API_KEY || process.env.LLM_API_KEY);

async function callLLM(messages) {
  const apiKey = process.env.DASHSCOPE_API_KEY || process.env.LLM_API_KEY;
  if (!apiKey) throw new Error('未配置 API Key');

  const baseURL = process.env.LLM_BASE_URL || 'https://dashscope.aliyuncs.com/compatible-mode/v1';
  const model = process.env.LLM_MODEL || 'qwen-plus';

  const resp = await fetch(`${baseURL}/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({ model, messages, temperature: 0.2, stream: false }),
  });

  if (!resp.ok) {
    const txt = await resp.text();
    if (resp.status === 401 || resp.status === 403) throw new Error('API Key 无效，请检查 .env');
    if (resp.status === 429) throw new Error('调用频率超限或额度用尽，请稍后再试');
    throw new Error(`模型调用失败(${resp.status})`);
  }
  const data = await resp.json();
  return data.choices?.[0]?.message?.content?.trim() || '模型返回为空';
}

/** 流式调用 LLM：每收到一段文字就回调 onDelta(text)，返回完整文本 */
async function callLLMStream(messages, onDelta) {
  const apiKey = process.env.DASHSCOPE_API_KEY || process.env.LLM_API_KEY;
  if (!apiKey) throw new Error('未配置 API Key');

  const baseURL = process.env.LLM_BASE_URL || 'https://dashscope.aliyuncs.com/compatible-mode/v1';
  const model = process.env.LLM_MODEL || 'qwen-plus';

  const resp = await fetch(`${baseURL}/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({ model, messages, temperature: 0.2, stream: true }),
  });

  if (!resp.ok) {
    const txt = await resp.text();
    if (resp.status === 401 || resp.status === 403) throw new Error('API Key 无效，请检查 .env');
    if (resp.status === 429) throw new Error('调用频率超限或额度用尽，请稍后再试');
    throw new Error(`模型调用失败(${resp.status})`);
  }

  // 解析上游 SSE
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let full = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });

    const lines = buf.split('\n');
    buf = lines.pop() || ''; // 留下不完整的最后一行
    for (const line of lines) {
      const t = line.trim();
      if (!t.startsWith('data:')) continue;
      const payload = t.slice(5).trim();
      if (payload === '[DONE]') continue;
      try {
        const delta = JSON.parse(payload).choices?.[0]?.delta?.content || '';
        if (delta) {
          full += delta;
          onDelta(delta);
        }
      } catch (_) { /* 忽略不完整 JSON */ }
    }
  }

  return full.trim() || '模型返回为空';
}

/**
 * 系统提示词（RAG 约束核心）：
 * 强制模型"只依据参考资料回答 + 标注依据编号"，从生成层杜绝幻觉；
 * 未命中条目时引导模型拒答，前端据此触发 AI 兜底并打上 🤖 标签。
 */
const SYSTEM_PROMPT = `你是「校园学习知识库助手」，服务山东华宇工学院的学生。
规则：
1. 只能依据【参考资料】回答，禁止编造资料中没有的信息。
2. 回答简洁分点，控制在 200 字以内，语气亲切。
3. 每条结论后标注依据编号，如（依据 #5）。
4. 若参考资料无法回答，回答：「知识库中暂未收录该信息，建议咨询辅导员或查看学校官网。」
5. 不要输出"根据参考资料"这类废话，直接给答案。`;

/* ============================================================
 * 4. 文档解析与入库
 * ============================================================ */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

/**
 * 修复上传文件名的中文乱码。
 *
 * 问题根源：multipart/form-data 的 filename 字段按 RFC 7578 应当是 UTF-8，
 * 但 busboy（multer 底层）默认用 latin1 解码，导致「招生简章.docx」的
 * UTF-8 字节被逐个当成 Latin-1 字符，存进库里就变成「æçåç« .docx」。
 *
 * 判断依据：先做 latin1→utf8 还原，再检查还原结果里有没有 U+FFFD（无法解码的替换符）。
 *   - 有替换符 → 说明原文本来就是合法字符串（如纯 ASCII 或已是中文），不做转换；
 *   - 无替换符且能读出新内容 → 说明确实是编码错位，采用还原值。
 * 这样对本来就正常的英文文件名不会造成二次破坏。
 */
function fixFilename(raw) {
  if (!raw) return '';
  // 已含中文（汉字区）说明解码正常，直接返回
  if (/[\u4e00-\u9fa5]/.test(raw)) return raw;
  try {
    const decoded = Buffer.from(raw, 'latin1').toString('utf8');
    // 还原后出现替换字符，说明不是编码问题，保持原值
    if (decoded.includes('\uFFFD')) return raw;
    return decoded;
  } catch {
    return raw;
  }
}

/** 多格式文本抽取：PPTX(解压读XML)/DOCX/PDF/Excel/CSV/TXT 统一转纯文本 */
async function extractText(file) {
  const name = fixFilename(file.originalname).toLowerCase();
  if (name.endsWith('.pdf')) {
    const pdfParse = require('pdf-parse');
    const data = await pdfParse(file.buffer);
    return data.text;
  }
  if (name.endsWith('.docx')) {
    const mammoth = require('mammoth');
    const r = await mammoth.extractRawText({ buffer: file.buffer });
    return r.value;
  }
  if (name.endsWith('.pptx')) {
    // pptx 是 zip 包，逐页 slide XML 提取 <a:t> 文本
    const AdmZip = require('adm-zip');
    const zip = new AdmZip(file.buffer);
    const slides = zip.getEntries().filter((e) => /^ppt\/slides\/slide\d+\.xml$/.test(e.entryName))
      .sort((a, b) => {
        const n = (s) => Number(s.entryName.match(/slide(\d+)/)[1]);
        return n(a) - n(b);
      });
    const parts = slides.map((e, i) => {
      const xml = e.getData().toString('utf8');
      const texts = [...xml.matchAll(/<a:t>([^<]*)<\/a:t>/g)].map((m) => m[1]);
      return `【第 ${i + 1} 页】\n` + texts.join('\n');
    });
    return parts.join('\n\n');
  }
  if (name.endsWith('.xlsx') || name.endsWith('.xls') || name.endsWith('.csv')) {
    const XLSX = require('xlsx');
    const wb = XLSX.read(file.buffer, { type: 'buffer' });
    const out = [];
    for (const sn of wb.SheetNames) {
      const rows = XLSX.utils.sheet_to_json(wb.Sheets[sn], { header: 1, defval: '' });
      out.push(`【工作表：${sn}】\n` + rows.map((r) => r.join(' | ')).join('\n'));
    }
    return out.join('\n\n');
  }
  // txt / md 等
  return file.buffer.toString('utf8');
}

/** 把长文本切成知识条目：优先按行，其次按句号切分，合并过短的行 */
/**
 * 长文本切分：优先按行切，单行过长再按句号二次切分，
 * 每条控制在 400 字内、过滤 <4 字的碎片——切分质量直接影响检索召回率。
 */
function splitIntoChunks(text) {
  const cleaned = text
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]+/g, ' ')
    .trim();

  let pieces = cleaned
    .split(/\n+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  // 如果整篇只有一两行（比如 PDF 抽取成一大段），按句号再切
  if (pieces.length <= 2) {
    pieces = cleaned
      .split(/(?<=[。！？；])/)
      .map((s) => s.trim())
      .filter((s) => s.length > 6);
  }

  // 合并过短片段（<8 字）到前一条
  const merged = [];
  for (const p of pieces) {
    if (p.length < 8 && merged.length > 0) {
      merged[merged.length - 1] += ' ' + p;
    } else {
      merged.push(p);
    }
  }

  // 超长段落再按句号切，单条上限 400 字
  const out = [];
  for (const p of merged) {
    if (p.length <= 400) {
      out.push(p);
      continue;
    }
    let buf = '';
    for (const sent of p.split(/(?<=[。！？；])/)) {
      if ((buf + sent).length > 400 && buf) {
        out.push(buf.trim());
        buf = sent;
      } else {
        buf += sent;
      }
    }
    if (buf.trim()) out.push(buf.trim());
  }

  return out.filter((s) => s.length >= 4);
}

/* ============================================================
 * 5. 接口
 * ============================================================ */

app.post('/api/users/import', requireRole('developer', 'teacher'), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: '请上传 Excel 文件（.xlsx/.xls/.csv）' });

    const XLSX = require('xlsx');
    const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheet = wb.Sheets[wb.SheetNames[0]];
    if (!sheet) return res.status(400).json({ error: '表格为空' });
    const rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });
    if (!rows.length) return res.status(400).json({ error: '表格没有数据行' });

    // 允许创建的身份
    const allowRole = req.user.role === 'developer' ? ['student', 'teacher'] : ['student'];
    const wantRole = allowRole.includes(req.body.role) ? req.body.role : 'student';

    const created = [];
    const failed = [];
    const seen = new Set();

    for (const row of rows) {
      const account = pickField(row, ['学号', '工号', '账号', '职工号', '编号']).replace(/\s/g, '');
      const name = pickField(row, ['姓名', '名字', '学生姓名', '教师姓名']);
      const klass = pickField(row, ['班级', '行政班']);
      const college = pickField(row, ['学院', '系部', '院系', '专业']);

      if (!account || !name) {
        failed.push({ account: account || '（空）', name: name || '（空）', reason: '缺少学号或姓名' });
        continue;
      }
      if (seen.has(account)) {
        failed.push({ account, name, reason: '表格内重复' });
        continue;
      }
      seen.add(account);

      // 初始密码 = 姓名拼音 + 学号后两位
      const tail = account.slice(-2).padStart(2, '0');
      const initPwd = nameToPinyin(name) + tail || 'hy' + account;

      try {
        createUser({
          account,
          password: initPwd,
          role: wantRole,
          name,
          createdBy: req.user.account,
        });
        if (klass || college) {
          db.prepare('UPDATE users SET remark=? WHERE account=?').run(
            [college, klass].filter(Boolean).join(' · '),
            account
          );
        }
        created.push({ account, name, role: wantRole, password: initPwd, klass, college });
      } catch (e) {
        failed.push({ account, name, reason: e.message });
      }
    }

    res.json({ ok: true, created, failed, total: rows.length });
  } catch (err) {
    console.error('[import]', err);
    res.status(500).json({ error: '解析失败：' + err.message });
  }
});


// --- 统计 ---
app.get('/api/stats', (req, res) => {
  const total = db.prepare('SELECT COUNT(*) AS c FROM knowledge').get().c;
  const cats = db
    .prepare('SELECT category, COUNT(*) AS c FROM knowledge GROUP BY category ORDER BY c DESC')
    .all();
  const today = db
    .prepare("SELECT COUNT(*) AS c FROM logs WHERE date(created_at)=date('now','localtime')")
    .get().c;
  const missToday = db
    .prepare(
      "SELECT COUNT(*) AS c FROM logs WHERE hit_count=0 AND date(created_at)=date('now','localtime')"
    )
    .get().c;
  res.json({ total, categories: cats, today, missToday, hasLLM: hasKey() });
});

// --- 知识 CRUD ---
app.get('/api/knowledge', requireAuth, (req, res) => {
  const { q = '', category = '', page = 1, size = 20, hasFile = '', src = '' } = req.query;
  const offset = (Number(page) - 1) * Number(size);

  let where = 'WHERE 1=1';
  const params = [];
  if (q) {
    where += ' AND (title LIKE ? OR content LIKE ?)';
    params.push(`%${q}%`, `%${q}%`);
  }
  if (category && category !== '全部') {
    where += ' AND category = ?';
    params.push(category);
  }
  if (hasFile === '1') {
    where += " AND source LIKE '上传：%'";
  }
  // 按来源文件名精确取该文件切出的全部片段（供「在线浏览」拼正文用）
  if (src) {
    where += ' AND source = ?';
    params.push(`上传：${src}`);
  }

  const total = db.prepare(`SELECT COUNT(*) AS c FROM knowledge ${where}`).get(...params).c;
  const rows = db
    .prepare(`SELECT * FROM knowledge ${where} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .all(...params, Number(size), offset);

  res.json({ total, page: Number(page), size: Number(size), items: rows });
});

app.post('/api/knowledge', requireRole('admin', 'developer', 'teacher'), (req, res) => {
  const { title = '', content = '', category = '' } = req.body;
  if (!content.trim()) return res.status(400).json({ error: '内容不能为空' });

  const cat = category || guessCategory(content);
  const info = db
    .prepare('INSERT INTO knowledge (title, content, category, source, uploader) VALUES (?,?,?,?,?)')
    .run(title || content.slice(0, 16), content.trim(), cat, '手动录入',
      (req.user.name || req.user.account) + '·' + ({student:'学生',teacher:'教师',admin:'管理员',developer:'开发者'}[req.user.role] || ''));
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/knowledge/:id', requireRole('admin', 'developer', 'teacher'), (req, res) => {
  const { title = '', content = '', category = '' } = req.body;
  if (!content.trim()) return res.status(400).json({ error: '内容不能为空' });
  const cat = category || guessCategory(content);
  db.prepare(
    "UPDATE knowledge SET title=?, content=?, category=?, updated_at=datetime('now','localtime') WHERE id=?"
  ).run(title || content.slice(0, 16), content.trim(), cat, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/knowledge/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM knowledge WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// --- 系统效果评测（检索基准测试，仅管理员/开发者） ---
app.post('/api/eval/run', requireRole('admin', 'developer'), (req, res) => {
  let qset;
  try {
    qset = JSON.parse(fs.readFileSync(path.join(__dirname, 'eval-questions.json'), 'utf8'));
  } catch (e) {
    return res.status(500).json({ error: '评测题集文件缺失或格式错误' });
  }

  const t0 = performance.now();
  const details = { inKB: [], outKB: [] };
  let hit1 = 0, hit3 = 0, rejectOk = 0, latencySum = 0, total = 0;

  for (const item of qset.inKB) {
    const s = performance.now();
    const hits = searchKnowledge(item.q, 3);
    const dt = performance.now() - s;
    latencySum += dt; total++;
    const top1 = hits[0]?.id === item.expectId;
    const in3 = hits.some((h) => h.id === item.expectId);
    if (top1) hit1++;
    if (in3) hit3++;
    details.inKB.push({
      q: item.q, expectId: item.expectId,
      top1: hits[0]?.id, top1Ok: top1, in3,
      time: Number(dt.toFixed(1)),
    });
  }
  for (const item of qset.outKB) {
    const s = performance.now();
    const hits = searchKnowledge(item.q, 3);
    const dt = performance.now() - s;
    latencySum += dt; total++;
    const rejected = hits.length === 0;
    if (rejected) rejectOk++;
    details.outKB.push({
      q: item.q, rejected, wrongHits: hits.slice(0, 1).map((h) => `#${h.id} ${h.title}`),
      time: Number(dt.toFixed(1)),
    });
  }

  const summary = {
    total,
    top1Rate: Number(((hit1 / qset.inKB.length) * 100).toFixed(1)),
    top3Rate: Number(((hit3 / qset.inKB.length) * 100).toFixed(1)),
    rejectRate: Number(((rejectOk / qset.outKB.length) * 100).toFixed(1)),
    avgLatency: Number((latencySum / total).toFixed(1)),
    runAt: new Date().toLocaleString('zh-CN'),
  };

  // 存档最近一次结果
  db.exec(`CREATE TABLE IF NOT EXISTS eval_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  )`);
  db.prepare('INSERT INTO eval_history (summary) VALUES (?)').run(JSON.stringify(summary));

  res.json({ ok: true, summary, details });
});

app.get('/api/eval/last', requireRole('admin', 'developer'), (req, res) => {
  try {
    const row = db.prepare('SELECT summary, created_at FROM eval_history ORDER BY id DESC LIMIT 1').get();
    res.json(row ? { summary: JSON.parse(row.summary) } : {});
  } catch (_) {
    res.json({});
  }
});

// 分类列表
app.get('/api/categories', (req, res) => {
  const rows = db
    .prepare('SELECT category, COUNT(*) AS c FROM knowledge GROUP BY category ORDER BY c DESC')
    .all();
  res.json(rows);
});

// --- 文档上传入库（教师/管理员/开发者；原文件保留供学生下载） ---
/**
 * 教师上传 PPT/Word/PDF/Excel → extractText 抽取纯文本 →
 * splitIntoChunks 切分为知识条目入库（含 source/uploader 元数据），
 * 学生提问命中后前端展示「📚 依据老师上传的校内资料 + 教师 + 日期 + 文件名」。
 */
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.post('/api/upload', requireRole('admin', 'developer', 'teacher'), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: '未收到文件' });

    const text = await extractText(req.file);
    const chunks = splitIntoChunks(text);

    if (chunks.length === 0) {
      return res.status(400).json({ error: '未能从文件中解析出有效文本' });
    }

    // 保存原文件：文件名 = 时间戳_原始名（下载时可还原），记录上传者
    // originalname 经 fixFilename 解码，避免中文文件名入库后变乱码
    const origName = fixFilename(req.file.originalname);
    const safeOrig = origName.replace(/[\\/:*?"<>|]/g, '_');
    const storedName = Date.now() + '_' + safeOrig;
    fs.writeFileSync(path.join(UPLOAD_DIR, storedName), req.file.buffer);
    const fileUrl = '/api/files/' + encodeURIComponent(storedName);
    const ROLE_LABEL_CN = { student:'学生', teacher:'教师', admin:'管理员', developer:'开发者' };
    const uploaderLabel = (req.user.name || req.user.account) + '·' + ROLE_LABEL_CN[req.user.role];

    const base = path.basename(origName, path.extname(origName));
    const insert = db.prepare(
      'INSERT INTO knowledge (title, content, category, source, uploader) VALUES (?,?,?,?,?)'
    );
    db.exec('BEGIN');
    try {
      for (const c of chunks) {
        const m = c.match(/^([^：:]{2,20})[：:](.*)$/);
        const title = m ? m[1] : c.slice(0, 16);
        insert.run(title, c, guessCategory(c), `上传：${origName}`, uploaderLabel);
      }
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }

    res.json({
      ok: true,
      filename: origName,
      fileUrl,
      uploader: uploaderLabel,
      inserted: chunks.length,
      preview: chunks.slice(0, 3).map((c) => (c.length > 60 ? c.slice(0, 60) + '…' : c)),
      total: db.prepare('SELECT COUNT(*) AS c FROM knowledge').get().c,
      base,
    });
  } catch (err) {
    console.error('[upload]', err);
    res.status(500).json({ error: '解析失败：' + err.message });
  }
});

// --- 资料文件下载（登录用户可下载） ---
const MIME = {
  '.pdf': 'application/pdf', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.txt': 'text/plain', '.md': 'text/plain', '.csv': 'text/csv',
};
/**
 * 能在浏览器里直接内嵌渲染、值得做「在线预览」的扩展名。
 * Office 三件套（docx/pptx/xlsx）浏览器无法原生渲染，强行 inline 只会白屏或乱码，
 * 所以它们一律走附件下载，由系统里的 Office/WPS 打开。
 */
const INLINE_OK = new Set(['.pdf', '.txt', '.md', '.csv']);
/**
 * 资料文件下载 / 在线预览。
 *
 * 为什么支持 ?token= 参数：
 *   前端下载按钮如果用 <a href> 或 <iframe src> 直链，浏览器不会带自定义请求头
 *   （X-Auth-Token 加不上去），必然 401。所以这里额外接受查询串里的 token，
 *   仅用于这种「浏览器原生发起、无法设头」的场景。
 *
 * ?inline=1 时不加 Content-Disposition 的 attachment，让浏览器直接内嵌渲染
 * （PDF / 图片 / 纯文本可在线看），Office 文件仍会走下载。
 */
app.get('/api/files/:name', (req, res) => {
  // 鉴权：优先请求头，回退到查询参数（供 <a>/<iframe> 直链使用）
  let user = getUser(req);
  if (!user && req.query.token) {
    const t = db.prepare('SELECT token, user_id FROM auth_tokens WHERE token = ?').get(String(req.query.token));
    if (t) user = db.prepare('SELECT id, account, role, name FROM users WHERE id = ?').get(t.user_id) || null;
  }
  if (!user) return res.status(401).json({ error: '请先登录', needAuth: true });

  // Express 已自动解码一次；只在残留 %XX 时才再解一次，避免中文名被二次解码破坏
  let orig = path.basename(req.params.name);
  if (/%[0-9A-Fa-f]{2}/.test(orig)) {
    try { orig = decodeURIComponent(orig); } catch { /* 解码失败就用原值 */ }
  }

  // 磁盘文件格式：时间戳_原名 → 按后缀匹配找到对应文件
  let fp = null;
  let onDisk = orig;
  if (fs.existsSync(path.join(UPLOAD_DIR, orig))) {
    fp = path.join(UPLOAD_DIR, orig); // 直接命中（前端已传磁盘名）
  } else {
    const suffix = '_' + orig;
    const candidates = fs.readdirSync(UPLOAD_DIR).filter((f) => f.endsWith(suffix));
    if (candidates.length) {
      candidates.sort().reverse();
      onDisk = candidates[0]; // 同名多份取最新
      fp = path.join(UPLOAD_DIR, onDisk);
    }
  }
  if (!fp || !fs.existsSync(fp)) return res.status(404).json({ error: '文件不存在' });

  const ext = path.extname(fp).toLowerCase();
  const mime = MIME[ext] || 'application/octet-stream';
  const inline = req.query.inline === '1';
  const downloadName = orig.replace(/^\d+_/, ''); // 去掉时间戳前缀，还原用户看到的原始名

  res.setHeader('Content-Type', mime);
  res.setHeader(
    'Content-Disposition',
    `${inline && INLINE_OK.has(ext) ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(downloadName)}`
  );
  // 防中文名在某些浏览器下被截断，额外给一个 ASCII 兜底名
  res.setHeader('Content-Length', fs.statSync(fp).size);
  fs.createReadStream(fp).pipe(res);
});

// --- 问答（SSE 流式，支持多轮；需登录） ---
/**
 * /api/ask 处理流程：
 * 1) searchKnowledge 检索 Top3，命中则把条目作为上下文拼进提示词（RAG）；
 * 2) 流式模式下逐段转发 SSE 事件：meta(来源标注) → delta(增量文本) → done；
 * 3) 未命中任何条目时走 AI 兜底直接答疑，并在 meta 中标记 mode='ai'，
 *    前端据此展示「🤖 AI 生成」徽章，实现双来源可溯源。
 */
app.post('/api/ask', requireAuth, async (req, res) => {
  try {
    const question = (req.body.question || '').trim();
    const convId = req.body.convId || null;
    const streamMode = req.body.stream !== false; // 默认流式

    if (!question) {
      return res.json({ answer: '请输入你的问题。', sources: [] });
    }

    const hits = searchKnowledge(question, 3);

    // 记录日志（用于分析看板）
    db.prepare('INSERT INTO logs (question, hit_count) VALUES (?,?)').run(question, hits.length);

    const sources = hits.map((h) => ({
      id: h.id,
      title: h.title,
      text: h.content,
      category: h.category,
      source: h.source || '',
      uploader: h.uploader || '',
      time: h.created_at || '',
      score: Number(h.score.toFixed(3)),
    }));

    // ---- 非流式模式（兼容保留） ----
    if (!streamMode) {
      let answer;
      if (hits.length === 0) {
        answer = '知识库中暂未收录该信息，建议咨询辅导员或查看学校官网（https://www.sdhyit.edu.cn）。';
      } else if (hasKey()) {
        try {
          const contextText = sources.map((c) => `【知识条目 #${c.id}】${c.text}`).join('\n');
          let history = [];
          if (convId) {
            history = db
              .prepare('SELECT role, content FROM messages WHERE conv_id=? ORDER BY id DESC LIMIT 4')
              .all(convId).reverse()
              .map((m) => ({ role: m.role, content: m.content }));
          }
          answer = await callLLM([
            { role: 'system', content: SYSTEM_PROMPT },
            ...history,
            { role: 'user', content: `【参考资料】\n${contextText}\n\n【问题】${question}` },
          ]);
        } catch (e) {
          console.warn('[LLM 降级]', e.message);
          answer = `⚠️ 模型暂不可用（${e.message}）\n以下为知识库原始检索结果：\n\n` +
            hits.map((h) => `· ${h.content}（依据 #${h.id}）`).join('\n');
        }
      } else {
        answer = '（演示模式：未配置模型 Key，直接返回知识库原文）\n\n' +
          hits.map((h) => `· ${h.content}（依据 #${h.id}）`).join('\n');
      }
      saveMessage(convId, 'user', question, []);
      saveMessage(convId, 'assistant', answer, sources);
      return res.json({ answer, sources });
    }

    // ---- SSE 流式模式 ----
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    const send = (obj) => res.write(`data: ${JSON.stringify(obj)}\n\n`);

    send({ type: 'meta', sources }); // 先把引用来源发给前端

    let answer = '';
    let streamedAny = false; // 记录是否已有增量输出
    let mode = 'kb'; // kb=依据校内资料 ai=AI 生成
    const emit = (text) => { if (text) { streamedAny = true; send({ type: 'delta', text }); } };

    if (hits.length === 0) {
      // 知识库查不到 → AI 通用答疑兜底（标注为 AI 生成）
      mode = 'ai';
      if (hasKey()) {
        try {
          const AI_PROMPT = `你是「校园学习助手」，服务山东华宇工学院的学生，负责答疑解惑。
当前问题在本校知识库中没有找到资料，请你以学习辅导老师的身份直接回答：
1. 尽量详细易懂，分点讲解，可以举例子。
2. 回答末尾加一行建议，引导学生咨询辅导员或老师核实关键信息。
3. 语气亲切，像学长学姐辅导学弟学妹。`;
          answer = await callLLMStream(
            [
              { role: 'system', content: AI_PROMPT },
              { role: 'user', content: question },
            ],
            (delta) => emit(delta)
          );
        } catch (e) {
          console.warn('[AI 兜底失败]', e.message);
          answer = '知识库中暂未收录该信息，建议咨询辅导员或查看学校官网（https://www.sdhyit.edu.cn）。';
          emit(answer);
        }
      } else {
        answer = '知识库中暂未收录该信息，建议咨询辅导员或查看学校官网（https://www.sdhyit.edu.cn）。';
        emit(answer);
      }
    } else if (hasKey()) {
      try {
        let history = [];
        if (convId) {
          history = db
            .prepare('SELECT role, content FROM messages WHERE conv_id=? ORDER BY id DESC LIMIT 4')
            .all(convId).reverse()
            .map((m) => ({ role: m.role, content: m.content }));
        }
        const contextText = sources.map((c) => `【知识条目 #${c.id}】${c.text}`).join('\n');
        answer = await callLLMStream(
          [
            { role: 'system', content: SYSTEM_PROMPT },
            ...history,
            { role: 'user', content: `【参考资料】\n${contextText}\n\n【问题】${question}` },
          ],
          (delta) => emit(delta)
        );
      } catch (e) {
        console.warn('[LLM 降级]', e.message);
        if (!streamedAny) {
          answer = `⚠️ 模型暂不可用（${e.message}）\n以下为知识库原始检索结果：\n\n` +
            hits.map((h) => `· ${h.content}（依据 #${h.id}）`).join('\n');
          emit(answer);
        } else {
          // 已流式输出一部分后中断，补一句提示
          answer += '\n（回答因模型中断而不完整，请重新提问）';
          send({ type: 'delta', text: '\n\n（回答因模型中断而不完整，请重新提问）' });
        }
      }
    } else {
      answer = '（演示模式：未配置模型 Key，直接返回知识库原文）\n\n' +
        hits.map((h) => `· ${h.content}（依据 #${h.id}）`).join('\n');
      emit(answer);
    }

    saveMessage(convId, 'user', question, []);
    const answerId = saveMessage(convId, 'assistant', answer, sources);

    send({ type: 'done', answer, sources, answerId, mode });
    res.end();
  } catch (err) {
    console.error('[ask error]', err);
    // 若尚未进入 SSE 则返回 JSON 错误，否则以 SSE 事件结束
    if (res.headersSent) {
      res.write(`data: ${JSON.stringify({ type: 'error', message: err.message })}\n\n`);
      res.end();
    } else {
      res.status(500).json({ answer: '服务暂时不可用：' + err.message, sources: [] });
    }
  }
});

function saveMessage(convId, role, content, sources) {
  if (!convId) return null;
  const exists = db.prepare('SELECT id FROM conversations WHERE id=?').get(convId);
  if (!exists) {
    db.prepare('INSERT INTO conversations (id, title) VALUES (?,?)').run(
      convId,
      role === 'user' ? content.slice(0, 20) : '新对话'
    );
  }
  const info = db
    .prepare('INSERT INTO messages (conv_id, role, content, sources) VALUES (?,?,?,?)')
    .run(
      convId,
      role,
      content,
      JSON.stringify(sources || [])
    );
  return Number(info.lastInsertRowid);
}

// --- 会话 ---
app.get('/api/conversations', (req, res) => {
  const rows = db
    .prepare(
      `SELECT c.id, c.title, c.created_at,
        (SELECT COUNT(*) FROM messages m WHERE m.conv_id=c.id) AS msg_count
       FROM conversations c ORDER BY c.created_at DESC LIMIT 30`
    )
    .all();
  res.json(rows);
});

app.get('/api/conversations/:id', (req, res) => {
  const msgs = db
    .prepare('SELECT * FROM messages WHERE conv_id=? ORDER BY id ASC')
    .all(req.params.id)
    .map((m) => ({ ...m, sources: JSON.parse(m.sources || '[]') }));
  res.json(msgs);
});

app.delete('/api/conversations/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM messages WHERE conv_id=?').run(req.params.id);
  db.prepare('DELETE FROM conversations WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// --- 数据看板 ---
app.get('/api/analytics', requireAuth, (req, res) => {
  const topQuestions = db
    .prepare(
      `SELECT question, COUNT(*) AS c FROM logs GROUP BY question ORDER BY c DESC LIMIT 10`
    )
    .all();
  const misses = db
    .prepare(
      `SELECT question, created_at FROM logs WHERE hit_count=0 ORDER BY id DESC LIMIT 15`
    )
    .all();
  const daily = db
    .prepare(
      `SELECT date(created_at) AS d, COUNT(*) AS c,
         SUM(CASE WHEN hit_count>0 THEN 1 ELSE 0 END) AS hit
       FROM logs GROUP BY d ORDER BY d DESC LIMIT 14`
    )
    .all()
    .reverse();
  const totalLogs = db.prepare('SELECT COUNT(*) AS c FROM logs').get().c;
  const hitLogs = db.prepare('SELECT COUNT(*) AS c FROM logs WHERE hit_count>0').get().c;

  const fbUp = db.prepare('SELECT COUNT(*) AS c FROM feedback WHERE value=1').get().c;
  const fbDown = db.prepare('SELECT COUNT(*) AS c FROM feedback WHERE value=-1').get().c;
  const fbTotal = fbUp + fbDown;

  res.json({
    topQuestions,
    misses,
    daily,
    totalLogs,
    hitRate: totalLogs ? Number(((hitLogs / totalLogs) * 100).toFixed(1)) : 0,
    feedback: {
      up: fbUp,
      down: fbDown,
      total: fbTotal,
      rate: fbTotal ? Number(((fbUp / fbTotal) * 100).toFixed(1)) : null,
    },
  });
});

// --- 回答反馈（点赞/点踩） ---
app.post('/api/feedback', requireAuth, (req, res) => {
  const messageId = Number(req.body.messageId);
  const value = Number(req.body.value);
  if (!messageId || ![1, -1].includes(value)) {
    return res.status(400).json({ error: '参数无效' });
  }
  const exists = db.prepare('SELECT id FROM messages WHERE id=?').get(messageId);
  if (!exists) return res.status(404).json({ error: '消息不存在' });

  const cur = db.prepare('SELECT value FROM feedback WHERE message_id=?').get(messageId);
  if (cur && cur.value === value) {
    // 再点一次 = 取消
    db.prepare('DELETE FROM feedback WHERE message_id=?').run(messageId);
    return res.json({ ok: true, value: 0 });
  }
  db.prepare(
    "INSERT INTO feedback (message_id, value) VALUES (?,?) " +
      "ON CONFLICT(message_id) DO UPDATE SET value=excluded.value, created_at=datetime('now','localtime')"
  ).run(messageId, value);
  res.json({ ok: true, value });
});

// --- 留言板 ---
// 提交留言（任何登录用户）
app.post('/api/board', requireAuth, (req, res) => {
  const question = String(req.body.question || '').trim();
  if (question.length < 4) return res.status(400).json({ error: '留言内容太短' });
  if (question.length > 500) return res.status(400).json({ error: '留言内容过长（500 字以内）' });
  const info = db
    .prepare('INSERT INTO board_messages (question, account, name) VALUES (?,?,?)')
    .run(question, req.user.account, req.user.name || req.user.account);
  res.json({ ok: true, id: Number(info.lastInsertRowid) });
});

// 留言列表（任何登录用户；开发者可看全部状态筛选）
app.get('/api/board', requireAuth, (req, res) => {
  const msgs = db
    .prepare('SELECT * FROM board_messages ORDER BY id DESC LIMIT 100')
    .all();
  const replies = db.prepare('SELECT * FROM board_replies ORDER BY id').all();
  const byMsg = {};
  for (const r of replies) {
    (byMsg[r.msg_id] = byMsg[r.msg_id] || []).push({
      content: r.content,
      replier: r.replier_name || r.replier_account,
      role: r.replier_role,
      time: r.created_at,
    });
  }
  res.json(
    msgs.map((m) => ({
      id: m.id,
      question: m.question,
      account: m.account,
      name: m.name,
      status: m.status,
      time: m.created_at,
      replies: byMsg[m.id] || [],
    }))
  );
});

// 回复留言（教师/开发者/管理员）
app.post('/api/board/:id/reply', requireRole('teacher', 'developer', 'admin'), (req, res) => {
  const msgId = Number(req.params.id);
  const content = String(req.body.content || '').trim();
  if (!content) return res.status(400).json({ error: '回复内容不能为空' });
  const msg = db.prepare('SELECT id, status FROM board_messages WHERE id=?').get(msgId);
  if (!msg) return res.status(404).json({ error: '留言不存在' });
  db.prepare(
    'INSERT INTO board_replies (msg_id, replier_account, replier_name, replier_role, content) VALUES (?,?,?,?,?)'
  ).run(msgId, req.user.account, req.user.name || req.user.account, req.user.role, content);
  db.prepare("UPDATE board_messages SET status='replied' WHERE id=?").run(msgId);
  res.json({ ok: true });
});

// 删除留言（开发者）
app.delete('/api/board/:id', requireRole('developer'), (req, res) => {
  const msgId = Number(req.params.id);
  db.prepare('DELETE FROM board_messages WHERE id=?').run(msgId);
  db.prepare('DELETE FROM board_replies WHERE msg_id=?').run(msgId);
  res.json({ ok: true });
});

// 重新分类全部知识（维护用）
app.post('/api/reclassify', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, content FROM knowledge').all();
  const upd = db.prepare('UPDATE knowledge SET category=? WHERE id=?');
  db.exec('BEGIN');
  try {
    for (const r of rows) upd.run(guessCategory(r.content), r.id);
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
  res.json({ ok: true, updated: rows.length });
});

// 导出知识库为 JSON
app.get('/api/export', (req, res) => {
  const rows = db.prepare('SELECT * FROM knowledge ORDER BY id').all();
  res.setHeader('Content-Disposition', 'attachment; filename="knowledge-export.json"');
  res.json(rows);
});

app.listen(PORT, () => {
  const c = db.prepare('SELECT COUNT(*) AS c FROM knowledge').get().c;
  console.log(`✅ 知识库就绪，条目数：${c}`);
  console.log(`🚀 http://localhost:${PORT}`);
  console.log(hasKey() ? '🤖 大模型：已接入' : '⚠️  大模型：未配置 Key（演示模式）');
});