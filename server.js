const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
require('dotenv').config();

const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static('public'));
app.use(express.json({ limit: '2mb' }));

/* ============================================================
 * 0. 管理员鉴权（问答公开，知识库写操作需口令）
 * ============================================================ */
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const validTokens = new Set(); // 服务重启后需重新登录，可接受

function requireAdmin(req, res, next) {
  // 未设置口令时保持旧行为（本地开发零门槛）
  if (!ADMIN_PASSWORD) return next();

  const token = req.headers['x-admin-token'];
  if (token && validTokens.has(token)) return next();
  return res.status(401).json({ error: '需要管理员登录', needAuth: true });
}

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (!ADMIN_PASSWORD) return res.json({ ok: true, token: 'no-auth', mode: 'open' });

  // 时序安全的字符串比较
  const a = Buffer.from(String(password || ''));
  const b = Buffer.from(ADMIN_PASSWORD);
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
    const token = crypto.randomBytes(24).toString('hex');
    validTokens.add(token);
    // 最多保留 50 个会话，防止无限增长
    if (validTokens.size > 50) validTokens.delete(validTokens.values().next().value);
    return res.json({ ok: true, token });
  }
  res.status(401).json({ error: '口令错误' });
});

app.post('/api/admin/logout', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token) validTokens.delete(token);
  res.json({ ok: true });
});

app.get('/api/admin/status', (req, res) => {
  res.json({
    protected: Boolean(ADMIN_PASSWORD),
    loggedIn: req.headers['x-admin-token'] ? validTokens.has(req.headers['x-admin-token']) : false,
  });
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

CREATE INDEX IF NOT EXISTS idx_kb_cat ON knowledge(category);
CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conv_id);
`);

/* 首次启动：把 knowledge.txt 导入数据库 */
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

function bigrams(str) {
  const set = new Set();
  for (let i = 0; i < str.length - 1; i++) set.add(str.slice(i, i + 2));
  if (str.length === 1) set.add(str);
  return set;
}

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

function searchKnowledge(question, topK = 3, threshold = 0.16) {
  const q = normalize(question);
  if (!q) return [];
  const qBi = bigrams(q);

  const rows = db.prepare('SELECT id, title, content, category, source FROM knowledge').all();
  return rows
    .map((r) => ({ ...r, score: scoreChunk(question, qBi, r) }))
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

async function extractText(file) {
  const name = file.originalname.toLowerCase();
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
  // txt / md / csv 等
  return file.buffer.toString('utf8');
}

/** 把长文本切成知识条目：优先按行，其次按句号切分，合并过短的行 */
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
app.get('/api/knowledge', (req, res) => {
  const { q = '', category = '', page = 1, size = 20 } = req.query;
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

  const total = db.prepare(`SELECT COUNT(*) AS c FROM knowledge ${where}`).get(...params).c;
  const rows = db
    .prepare(`SELECT * FROM knowledge ${where} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .all(...params, Number(size), offset);

  res.json({ total, page: Number(page), size: Number(size), items: rows });
});

app.post('/api/knowledge', requireAdmin, (req, res) => {
  const { title = '', content = '', category = '' } = req.body;
  if (!content.trim()) return res.status(400).json({ error: '内容不能为空' });

  const cat = category || guessCategory(content);
  const info = db
    .prepare('INSERT INTO knowledge (title, content, category, source) VALUES (?,?,?,?)')
    .run(title || content.slice(0, 16), content.trim(), cat, '手动录入');
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/knowledge/:id', requireAdmin, (req, res) => {
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

// 分类列表
app.get('/api/categories', (req, res) => {
  const rows = db
    .prepare('SELECT category, COUNT(*) AS c FROM knowledge GROUP BY category ORDER BY c DESC')
    .all();
  res.json(rows);
});

// --- 文档上传入库 ---
app.post('/api/upload', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: '未收到文件' });

    const text = await extractText(req.file);
    const chunks = splitIntoChunks(text);

    if (chunks.length === 0) {
      return res.status(400).json({ error: '未能从文件中解析出有效文本' });
    }

    const base = path.basename(req.file.originalname, path.extname(req.file.originalname));
    const insert = db.prepare(
      'INSERT INTO knowledge (title, content, category, source) VALUES (?,?,?,?)'
    );
    db.exec('BEGIN');
    try {
      for (const c of chunks) {
        const m = c.match(/^([^：:]{2,20})[：:](.*)$/);
        const title = m ? m[1] : c.slice(0, 16);
        insert.run(title, c, guessCategory(c), `上传：${req.file.originalname}`);
      }
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }

    res.json({
      ok: true,
      filename: req.file.originalname,
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

// --- 问答（支持多轮） ---
app.post('/api/ask', async (req, res) => {
  try {
    const question = (req.body.question || '').trim();
    const convId = req.body.convId || null;
    if (!question) return res.json({ answer: '请输入你的问题。', sources: [] });

    const hits = searchKnowledge(question, 3);

    // 记录日志（用于分析看板）
    db.prepare('INSERT INTO logs (question, hit_count) VALUES (?,?)').run(question, hits.length);

    if (hits.length === 0) {
      const ans =
        '知识库中暂未收录该信息，建议咨询辅导员或查看学校官网（https://www.sdhyit.edu.cn）。';
      saveMessage(convId, 'user', question, []);
      saveMessage(convId, 'assistant', ans, []);
      return res.json({ answer: ans, sources: [] });
    }

    const contexts = hits.map((h) => ({ id: h.id, text: h.content }));
    let answer;

    if (hasKey()) {
      try {
        // 多轮上下文：取该会话最近 4 条消息
        let history = [];
        if (convId) {
          history = db
            .prepare(
              'SELECT role, content FROM messages WHERE conv_id=? ORDER BY id DESC LIMIT 4'
            )
            .all(convId)
            .reverse()
            .map((m) => ({ role: m.role, content: m.content }));
        }
        const contextText = contexts.map((c) => `【知识条目 #${c.id}】${c.text}`).join('\n');
        answer = await callLLM([
          { role: 'system', content: SYSTEM_PROMPT },
          ...history,
          {
            role: 'user',
            content: `【参考资料】\n${contextText}\n\n【问题】${question}`,
          },
        ]);
      } catch (e) {
        console.warn('[LLM 降级]', e.message);
        answer =
          `⚠️ 模型暂不可用（${e.message}）\n以下为知识库原始检索结果：\n\n` +
          hits.map((h) => `· ${h.content}（依据 #${h.id}）`).join('\n');
      }
    } else {
      answer =
        '（演示模式：未配置模型 Key，直接返回知识库原文）\n\n' +
        hits.map((h) => `· ${h.content}（依据 #${h.id}）`).join('\n');
    }

    const sources = hits.map((h) => ({
      id: h.id,
      title: h.title,
      text: h.content,
      category: h.category,
      score: Number(h.score.toFixed(3)),
    }));

    saveMessage(convId, 'user', question, []);
    saveMessage(convId, 'assistant', answer, sources);

    res.json({ answer, sources });
  } catch (err) {
    console.error('[ask error]', err);
    res.status(500).json({ answer: '服务暂时不可用：' + err.message, sources: [] });
  }
});

function saveMessage(convId, role, content, sources) {
  if (!convId) return;
  const exists = db.prepare('SELECT id FROM conversations WHERE id=?').get(convId);
  if (!exists) {
    db.prepare('INSERT INTO conversations (id, title) VALUES (?,?)').run(
      convId,
      role === 'user' ? content.slice(0, 20) : '新对话'
    );
  }
  db.prepare('INSERT INTO messages (conv_id, role, content, sources) VALUES (?,?,?,?)').run(
    convId,
    role,
    content,
    JSON.stringify(sources || [])
  );
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
app.get('/api/analytics', (req, res) => {
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

  res.json({
    topQuestions,
    misses,
    daily,
    totalLogs,
    hitRate: totalLogs ? Number(((hitLogs / totalLogs) * 100).toFixed(1)) : 0,
  });
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
