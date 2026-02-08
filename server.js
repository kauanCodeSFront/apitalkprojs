require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();

// ================== VERIFICAÇÃO DE AMBIENTE ==================
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('❌ ERRO CRÍTICO: JWT_SECRET não definido ou muito curto (mínimo 32 caracteres)');
  process.exit(1);
}

// ================== CONFIGURAÇÕES DE SEGURANÇA ==================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10kb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 tentativas
  message: { success: false, error: 'Muitas tentativas. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: 'Limite de requisições excedido. Tente novamente mais tarde.' },
});

const postLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 5, // 5 posts por minuto
  message: { success: false, error: 'Muitos posts em pouco tempo. Aguarde um minuto.' },
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/posts', postLimiter);
app.use('/api/', apiLimiter);

// ================== HELPER DE SANITIZAÇÃO ==================
function sanitizeInput(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;")
    .trim();
}

// ================== DATABASE ==================
const dbPath = path.join(__dirname, 'talkpro.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Erro ao conectar ao banco:', err.message);
    process.exit(1);
  }
  console.log('✅ Conectado ao SQLite');
  db.run('PRAGMA foreign_keys = ON');
  db.run('PRAGMA journal_mode = WAL');
  createTables();
});

// Promise wrapper
['run', 'get', 'all'].forEach(method => {
  db[method + 'Async'] = function (sql, params = []) {
    return new Promise((resolve, reject) => {
      this[method](sql, params, function (err, result) {
        if (err) reject(err);
        else resolve(method === 'run' ? { id: this.lastID, changes: this.changes } : result);
      });
    });
  };
});

// ================== CRIAÇÃO DE TABELAS ==================
async function createTables() {
  try {
    await db.runAsync(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin BOOLEAN DEFAULT 0,
      is_active BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    )`);

    await db.runAsync(`CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      user_name TEXT,
      text TEXT NOT NULL,
      category TEXT DEFAULT 'outros',
      anonymous BOOLEAN DEFAULT 0,
      likes INTEGER DEFAULT 0,
      is_flagged BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await db.runAsync(`CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      user_name TEXT,
      text TEXT NOT NULL,
      is_flagged BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await db.runAsync(`CREATE TABLE IF NOT EXISTS post_likes (
      user_id INTEGER NOT NULL,
      post_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, post_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
    )`);

    await db.runAsync(`CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      reporter_id INTEGER NOT NULL,
      reporter_name TEXT,
      reason TEXT NOT NULL,
      description TEXT,
      resolved BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      resolved_at DATETIME,
      FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
      FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await db.runAsync(`CREATE TABLE IF NOT EXISTS admin_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_id INTEGER,
      admin_name TEXT,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id INTEGER,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
    )`);

    // Índices
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_post_likes_post_id ON post_likes(post_id)');

    await createDefaultAdmin();
  } catch (err) {
    console.error('❌ Erro ao criar tabelas:', err);
    process.exit(1);
  }
}

// ================== ADMIN PADRÃO ==================
async function createDefaultAdmin() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  if (!email || !password) {
    console.warn('⚠️ ADMIN_EMAIL ou ADMIN_PASSWORD não definidos no .env');
    return;
  }

  try {
    const exists = await db.getAsync('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!exists) {
      const hash = await bcrypt.hash(password, 12);
      await db.runAsync(
        'INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)',
        ['Administrador', email.toLowerCase(), hash, 1]
      );
      console.log('👑 Admin criado:', email);
    }
  } catch (err) {
    console.error('❌ Erro ao criar admin:', err);
  }
}

// ================== HELPERS ==================
function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      is_admin: user.is_admin
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' } // Reduzido para 24h por segurança
  );
}

// ================== MIDDLEWARES ==================
function auth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Acesso não autorizado' });
    }

    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.userId = decoded.id;
    req.userIsAdmin = decoded.is_admin;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, error: 'Sessão expirada. Faça login novamente.' });
    }
    res.status(401).json({ success: false, error: 'Acesso não autorizado' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.userIsAdmin) {
    return res.status(403).json({ success: false, error: 'Acesso restrito' });
  }
  next();
}

async function logAdminAction(adminId, adminName, action, targetType = null, targetId = null, details = null) {
  try {
    await db.runAsync(
      'INSERT INTO admin_logs (admin_id, admin_name, action, target_type, target_id, details) VALUES (?, ?, ?, ?, ?, ?)',
      [adminId, adminName, action, targetType, targetId, details ? JSON.stringify(details) : null]
    );
  } catch (err) {
    console.error('Erro ao registrar log:', err);
  }
}

// ================== ROTAS ==================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ================== AUTH ==================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validações
    if (!name?.trim() || !email?.trim() || !password) {
      return res.status(400).json({ success: false, error: 'Preencha todos os campos' });
    }

    if (name.trim().length < 2 || name.trim().length > 50) {
      return res.status(400).json({ success: false, error: 'Nome deve ter 2-50 caracteres' });
    }

    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Senha mínima de 6 caracteres' });
    }

    const emailLower = email.toLowerCase().trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailLower)) {
      return res.status(400).json({ success: false, error: 'Email inválido' });
    }

    const exists = await db.getAsync('SELECT id FROM users WHERE email = ?', [emailLower]);
    if (exists) {
      return res.status(409).json({ success: false, error: 'Email já cadastrado' });
    }

    const hash = await bcrypt.hash(password, 12);
    const cleanName = sanitizeInput(name.trim());

    const result = await db.runAsync(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [cleanName, emailLower, hash]
    );

    const user = await db.getAsync(
      'SELECT id, name, email, is_admin FROM users WHERE id = ?',
      [result.id]
    );

    const token = generateToken(user);

    res.status(201).json({
      success: true,
      message: 'Conta criada!',
      token,
      user
    });
  } catch (err) {
    console.error('Erro no registro:', err);
    res.status(500).json({ success: false, error: 'Erro ao criar conta' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email?.trim() || !password) {
      return res.status(400).json({ success: false, error: 'Informe email e senha' });
    }

    const emailLower = email.toLowerCase().trim();
    const user = await db.getAsync('SELECT * FROM users WHERE email = ?', [emailLower]);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, error: 'Email ou senha incorretos' });
    }

    if (!user.is_active) {
      return res.status(403).json({ success: false, error: 'Conta desativada' });
    }

    await db.runAsync('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

    const token = generateToken(user);
    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      is_admin: user.is_admin
    };

    res.json({
      success: true,
      message: 'Login realizado!',
      token,
      user: safeUser
    });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ success: false, error: 'Erro ao realizar login' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await db.getAsync(
      'SELECT id, name, email, is_admin, created_at FROM users WHERE id = ?',
      [req.userId]
    );

    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
    }

    res.json({ success: true, user });
  } catch (err) {
    console.error('Erro ao buscar usuário:', err);
    res.status(500).json({ success: false, error: 'Erro ao buscar dados' });
  }
});

// ================== POSTS ==================

app.get('/api/posts', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 50); // Máximo 50
    const offset = (page - 1) * limit;

    const posts = await db.allAsync(`
      SELECT p.*, u.name as user_name 
      FROM posts p
      LEFT JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC 
      LIMIT ? OFFSET ?
    `, [limit, offset]);

    const postIds = posts.map(p => p.id);

    if (postIds.length > 0) {
      const placeholders = postIds.map(() => '?').join(',');
      const comments = await db.allAsync(`
        SELECT c.*, u.name as user_name
        FROM comments c
        LEFT JOIN users u ON c.user_id = u.id
        WHERE c.post_id IN (${placeholders})
        ORDER BY c.created_at ASC
      `, postIds);

      const commentsByPost = comments.reduce((acc, comment) => {
        if (!acc[comment.post_id]) acc[comment.post_id] = [];
        acc[comment.post_id].push(comment);
        return acc;
      }, {});

      posts.forEach(post => {
        post.comments = commentsByPost[post.id] || [];
        if (post.anonymous) {
          post.user_name = null;
        }
      });
    } else {
      posts.forEach(post => post.comments = []);
    }

    const { count } = await db.getAsync('SELECT COUNT(*) as count FROM posts');

    res.json({
      posts,
      pagination: {
        page,
        limit,
        total: count,
        totalPages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    console.error('Erro ao buscar posts:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar posts' });
  }
});

app.post('/api/posts', auth, async (req, res) => {
  try {
    const { text, category = 'outros', anonymous = false } = req.body;

    if (!text?.trim()) {
      return res.status(400).json({ success: false, error: 'Post não pode estar vazio' });
    }

    if (text.length > 1000) {
      return res.status(400).json({ success: false, error: 'Post muito longo (máx 1000 caracteres)' });
    }

    const validCategories = ['relacionamento', 'trabalho', 'familia', 'saude', 'amizade', 'estudos', 'outros'];
    const finalCategory = validCategories.includes(category) ? category : 'outros';

    const user = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);

    const cleanText = sanitizeInput(text);
    const cleanCategory = sanitizeInput(finalCategory);

    const result = await db.runAsync(
      'INSERT INTO posts (user_id, user_name, text, category, anonymous) VALUES (?, ?, ?, ?, ?)',
      [req.userId, user.name, cleanText, cleanCategory, anonymous ? 1 : 0]
    );

    const post = await db.getAsync(`
      SELECT p.*, u.name as user_name 
      FROM posts p
      LEFT JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `, [result.id]);

    post.comments = [];
    if (post.anonymous) post.user_name = null;

    res.status(201).json(post);
  } catch (err) {
    console.error('Erro ao criar post:', err);
    res.status(500).json({ success: false, error: 'Erro ao criar post' });
  }
});

app.post('/api/posts/:postId/like', auth, async (req, res) => {
  try {
    const { postId } = req.params;

    const post = await db.getAsync('SELECT id FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    const exists = await db.getAsync(
      'SELECT * FROM post_likes WHERE user_id = ? AND post_id = ?',
      [req.userId, postId]
    );

    if (exists) {
      await db.runAsync('DELETE FROM post_likes WHERE user_id = ? AND post_id = ?', [req.userId, postId]);
      await db.runAsync('UPDATE posts SET likes = MAX(0, likes - 1) WHERE id = ?', [postId]);
    } else {
      await db.runAsync('INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)', [req.userId, postId]);
      await db.runAsync('UPDATE posts SET likes = likes + 1 WHERE id = ?', [postId]);
    }

    const updatedPost = await db.getAsync('SELECT likes FROM posts WHERE id = ?', [postId]);

    res.json({
      success: true,
      liked: !exists,
      likes: updatedPost.likes
    });
  } catch (err) {
    console.error('Erro ao curtir:', err);
    res.status(500).json({ success: false, error: 'Erro ao curtir post' });
  }
});

app.delete('/api/posts/:postId', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    const post = await db.getAsync('SELECT user_id FROM posts WHERE id = ?', [postId]);

    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    if (post.user_id !== req.userId && !req.userIsAdmin) {
      return res.status(403).json({ success: false, error: 'Sem permissão' });
    }

    await db.runAsync('DELETE FROM posts WHERE id = ?', [postId]);
    res.json({ success: true, message: 'Post excluído' });
  } catch (err) {
    console.error('Erro ao deletar post:', err);
    res.status(500).json({ success: false, error: 'Erro ao excluir post' });
  }
});

// ================== COMMENTS ==================

app.post('/api/posts/:postId/comment', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    const { content } = req.body;

    if (!content?.trim()) {
      return res.status(400).json({ success: false, error: 'Comentário obrigatório' });
    }

    if (content.length > 500) {
      return res.status(400).json({ success: false, error: 'Comentário muito longo (máx 500)' });
    }

    const post = await db.getAsync('SELECT id FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    const user = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    const cleanContent = sanitizeInput(content);

    const result = await db.runAsync(
      'INSERT INTO comments (post_id, user_id, user_name, text) VALUES (?, ?, ?, ?)',
      [postId, req.userId, user.name, cleanContent]
    );

    const comment = await db.getAsync(`
      SELECT c.*, u.name as user_name
      FROM comments c
      LEFT JOIN users u ON c.user_id = u.id
      WHERE c.id = ?
    `, [result.id]);

    res.status(201).json({
      success: true,
      comment
    });
  } catch (err) {
    console.error('Erro ao comentar:', err);
    res.status(500).json({ success: false, error: 'Erro ao comentar' });
  }
});

app.delete('/api/comments/:commentId', auth, async (req, res) => {
  try {
    const { commentId } = req.params;
    const comment = await db.getAsync('SELECT user_id FROM comments WHERE id = ?', [commentId]);

    if (!comment) {
      return res.status(404).json({ success: false, error: 'Comentário não encontrado' });
    }

    if (comment.user_id !== req.userId && !req.userIsAdmin) {
      return res.status(403).json({ success: false, error: 'Sem permissão' });
    }

    await db.runAsync('DELETE FROM comments WHERE id = ?', [commentId]);
    res.json({ success: true, message: 'Comentário excluído' });
  } catch (err) {
    console.error('Erro ao deletar comentário:', err);
    res.status(500).json({ success: false, error: 'Erro ao excluir comentário' });
  }
});

// ================== ADMIN ROUTES ==================

app.get('/api/admin/stats', auth, requireAdmin, async (req, res) => {
  try {
    const totalUsers = await db.getAsync('SELECT COUNT(*) as count FROM users');
    const totalPosts = await db.getAsync('SELECT COUNT(*) as count FROM posts');
    const pendingReports = await db.getAsync('SELECT COUNT(*) as count FROM reports WHERE resolved = 0');

    const today = new Date().toISOString().split('T')[0];
    const todayPosts = await db.getAsync(
      "SELECT COUNT(*) as count FROM posts WHERE DATE(created_at) = ?",
      [today]
    );

    res.json({
      success: true,
      stats: {
        totalUsers: totalUsers.count,
        totalPosts: totalPosts.count,
        pendingReports: pendingReports.count,
        todayPosts: todayPosts.count
      }
    });
  } catch (err) {
    console.error('Erro nas estatísticas:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar estatísticas' });
  }
});

app.get('/api/admin/users', auth, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const offset = (page - 1) * limit;
    const search = req.query.search || '';

    let query = `
      SELECT u.id, u.name, u.email, u.is_admin, u.is_active, u.created_at, u.last_login,
        (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as posts_count,
        (SELECT COUNT(*) FROM comments WHERE user_id = u.id) as comments_count
      FROM users u
    `;

    let params = [];

    if (search) {
      query += ' WHERE u.name LIKE ? OR u.email LIKE ?';
      params.push(`%${sanitizeInput(search)}%`, `%${sanitizeInput(search)}%`);
    }

    query += ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const users = await db.allAsync(query, params);

    let countQuery = 'SELECT COUNT(*) as count FROM users';
    let countParams = [];
    if (search) {
      countQuery += ' WHERE name LIKE ? OR email LIKE ?';
      countParams.push(`%${sanitizeInput(search)}%`, `%${sanitizeInput(search)}%`);
    }
    const { count } = await db.getAsync(countQuery, countParams);

    res.json({
      success: true,
      users,
      pagination: {
        page,
        limit,
        total: count,
        totalPages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    console.error('Erro ao listar usuários:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar usuários' });
  }
});

app.put('/api/admin/users/:userId', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { name, email, is_admin, is_active } = req.body;

    const user = await db.getAsync('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
    }

    if (parseInt(userId) === req.userId && !is_active) {
      return res.status(400).json({ success: false, error: 'Não pode desativar a si mesmo' });
    }

    await db.runAsync(
      'UPDATE users SET name = ?, email = ?, is_admin = ?, is_active = ? WHERE id = ?',
      [sanitizeInput(name), email.toLowerCase(), is_admin ? 1 : 0, is_active ? 1 : 0, userId]
    );

    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, 'UPDATE_USER', 'user', parseInt(userId));

    res.json({ success: true, message: 'Usuário atualizado' });
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err);
    res.status(500).json({ success: false, error: 'Erro ao atualizar' });
  }
});

app.delete('/api/admin/users/:userId', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    if (parseInt(userId) === req.userId) {
      return res.status(400).json({ success: false, error: 'Não pode excluir a si mesmo' });
    }

    const user = await db.getAsync('SELECT name FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
    }

    await db.runAsync('DELETE FROM users WHERE id = ?', [userId]);

    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, 'DELETE_USER', 'user', parseInt(userId));

    res.json({ success: true, message: 'Usuário excluído' });
  } catch (err) {
    console.error('Erro ao excluir usuário:', err);
    res.status(500).json({ success: false, error: 'Erro ao excluir' });
  }
});

app.get('/api/admin/posts', auth, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const offset = (page - 1) * limit;
    const flagged = req.query.flagged;

    let query = `
      SELECT p.*, u.name as user_name,
        (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comments_count
      FROM posts p
      LEFT JOIN users u ON p.user_id = u.id
    `;

    let params = [];

    if (flagged === 'true') {
      query += ' WHERE p.is_flagged = 1';
    } else if (flagged === 'false') {
      query += ' WHERE p.is_flagged = 0';
    }

    query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const posts = await db.allAsync(query, params);

    let countQuery = 'SELECT COUNT(*) as count FROM posts';
    if (flagged === 'true') {
      countQuery += ' WHERE is_flagged = 1';
    } else if (flagged === 'false') {
      countQuery += ' WHERE is_flagged = 0';
    }
    const { count } = await db.getAsync(countQuery);

    res.json({
      success: true,
      posts,
      pagination: {
        page,
        limit,
        total: count,
        totalPages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    console.error('Erro ao listar posts:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar posts' });
  }
});

app.post('/api/admin/posts/:postId/flag', auth, requireAdmin, async (req, res) => {
  try {
    const { postId } = req.params;
    const { flag } = req.body;

    const post = await db.getAsync('SELECT id FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    await db.runAsync('UPDATE posts SET is_flagged = ? WHERE id = ?', [flag ? 1 : 0, postId]);

    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, flag ? 'FLAG_POST' : 'UNFLAG_POST', 'post', parseInt(postId));

    res.json({ success: true, message: `Post ${flag ? 'marcado' : 'desmarcado'}` });
  } catch (err) {
    console.error('Erro ao flagar post:', err);
    res.status(500).json({ success: false, error: 'Erro ao atualizar post' });
  }
});

app.delete('/api/admin/posts/:postId', auth, requireAdmin, async (req, res) => {
  try {
    const { postId } = req.params;

    const post = await db.getAsync('SELECT id FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    await db.runAsync('DELETE FROM posts WHERE id = ?', [postId]);

    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, 'DELETE_POST', 'post', parseInt(postId));

    res.json({ success: true, message: 'Post excluído' });
  } catch (err) {
    console.error('Erro ao excluir post:', err);
    res.status(500).json({ success: false, error: 'Erro ao excluir post' });
  }
});

app.get('/api/admin/reports', auth, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);
    const offset = (page - 1) * limit;
    const resolved = req.query.resolved === 'true';

    const reports = await db.allAsync(`
      SELECT r.*, p.text as post_text, p.user_name as post_author
      FROM reports r
      LEFT JOIN posts p ON r.post_id = p.id
      WHERE r.resolved = ?
      ORDER BY r.created_at DESC
      LIMIT ? OFFSET ?
    `, [resolved ? 1 : 0, limit, offset]);

    const { count } = await db.getAsync(
      'SELECT COUNT(*) as count FROM reports WHERE resolved = ?',
      [resolved ? 1 : 0]
    );

    res.json({
      success: true,
      reports,
      pagination: {
        page,
        limit,
        total: count,
        totalPages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    console.error('Erro ao listar reports:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar reports' });
  }
});

app.post('/api/reports', auth, async (req, res) => {
  try {
    const { post_id, reason, description } = req.body;

    if (!post_id || !reason) {
      return res.status(400).json({ success: false, error: 'Post e motivo obrigatórios' });
    }

    const post = await db.getAsync('SELECT id FROM posts WHERE id = ?', [post_id]);
    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    const user = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);

    const result = await db.runAsync(
      'INSERT INTO reports (post_id, reporter_id, reporter_name, reason, description) VALUES (?, ?, ?, ?, ?)',
      [post_id, req.userId, user.name, sanitizeInput(reason), description ? sanitizeInput(description) : null]
    );

    res.status(201).json({
      success: true,
      message: 'Report enviado',
      report_id: result.id
    });
  } catch (err) {
    console.error('Erro ao criar report:', err);
    res.status(500).json({ success: false, error: 'Erro ao enviar report' });
  }
});

app.post('/api/admin/reports/:reportId/resolve', auth, requireAdmin, async (req, res) => {
  try {
    const { reportId } = req.params;

    const report = await db.getAsync('SELECT * FROM reports WHERE id = ?', [reportId]);
    if (!report) {
      return res.status(404).json({ success: false, error: 'Report não encontrado' });
    }

    await db.runAsync(
      'UPDATE reports SET resolved = 1, resolved_at = CURRENT_TIMESTAMP WHERE id = ?',
      [reportId]
    );

    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, 'RESOLVE_REPORT', 'report', parseInt(reportId));

    res.json({ success: true, message: 'Report resolvido' });
  } catch (err) {
    console.error('Erro ao resolver report:', err);
    res.status(500).json({ success: false, error: 'Erro ao resolver' });
  }
});

app.get('/api/admin/logs', auth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);

    const logs = await db.allAsync(`
      SELECT * FROM admin_logs
      ORDER BY created_at DESC
      LIMIT ?
    `, [limit]);

    logs.forEach(log => {
      if (log.details) {
        try {
          log.details = JSON.parse(log.details);
        } catch (e) {
          log.details = null;
        }
      }
    });

    res.json({ success: true, logs });
  } catch (err) {
    console.error('Erro ao listar logs:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar logs' });
  }
});

// ================== ERROR HANDLING ==================
app.use((err, req, res, next) => {
  console.error('Erro:', err);

  // Não expor detalhes em produção
  const message = process.env.NODE_ENV === 'production'
    ? 'Erro interno do servidor'
    : err.message;

  res.status(500).json({
    success: false,
    error: message
  });
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Rota não encontrada' });
});

// ================== SERVER ==================
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`🚀 Server na porta ${PORT}`);
  console.log(`🔒 Ambiente: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM. Fechando...');
  server.close(() => {
    db.close(() => {
      console.log('💾 Banco fechado');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('👋 SIGINT. Fechando...');
  server.close(() => {
    db.close(() => {
      console.log('💾 Banco fechado');
      process.exit(0);
    });
  });
});