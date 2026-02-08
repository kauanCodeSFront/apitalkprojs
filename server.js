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
if (!process.env.JWT_SECRET) {
  console.error('❌ ERRO CRÍTICO: JWT_SECRET não definido no .env');
  console.error('⚠️  Para segurança, o servidor não pode iniciar sem uma chave secreta segura.');
  process.exit(1);
}

// ================== CONFIGURAÇÕES DE SEGURANÇA ==================
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10kb' }));

// Rate limiting específico por rota
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, error: 'Muitas tentativas de login. Tente novamente mais tarde.' },
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: 'Limite de requisições excedido. Tente novamente mais tarde.' }
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/', apiLimiter);

// ================== HELPER DE SANITIZAÇÃO (XSS) ==================
function sanitizeInput(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ================== DATABASE ==================
const dbPath = path.join(__dirname, 'talkpro.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) return console.error('❌ Erro ao conectar ao banco:', err.message);
  console.log('✅ Conectado ao SQLite (talkpro.db)');
  db.run('PRAGMA foreign_keys = ON');
  db.run('PRAGMA journal_mode = WAL');
  createTables();
});

// ================== PROMISE DBWRAPPER ==================
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
    // Tabela de usuários
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

    // Tabela de posts
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

    // Tabela de comentários
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

    // Tabela de likes
    await db.runAsync(`CREATE TABLE IF NOT EXISTS post_likes (
      user_id INTEGER NOT NULL,
      post_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, post_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
    )`);

    // Tabela de reports (denúncias)
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

    // Tabela de logs de admin
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

    // Criar índices para performance
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_posts_is_flagged ON posts(is_flagged)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_post_likes_post_id ON post_likes(post_id)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_reports_resolved ON reports(resolved)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at)');
    await db.runAsync('CREATE INDEX IF NOT EXISTS idx_admin_logs_created_at ON admin_logs(created_at)');

    await createDefaultAdmin();
  } catch (err) {
    console.error('❌ Erro ao criar tabelas:', err);
  }
}

// ================== USUÁRIO ADMIN PADRÃO ==================
async function createDefaultAdmin() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  try {
    const exists = await db.getAsync('SELECT id FROM users WHERE email = ?', [email]);
    if (!exists) {
      const hash = await bcrypt.hash(password, 12);
      await db.runAsync(
        'INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)',
        ['Administrador', email, hash, 1]
      );
      console.log('👑 Usuário admin criado:', email);
    }
  } catch (err) {
    console.error('❌ Erro ao criar admin:', err);
  }
}

// ================== HELPERS ==================
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, is_admin: user.is_admin },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ================== MIDDLEWARE ==================
function auth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Token não fornecido' });
    }
    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.userIsAdmin = decoded.is_admin;
    next();
  } catch (err) {
    res.status(401).json({ success: false, error: 'Sessão inválida ou expirada. Faça login novamente.' });
  }
}

// Middleware para verificar se é admin
function requireAdmin(req, res, next) {
  if (!req.userIsAdmin) {
    return res.status(403).json({ success: false, error: 'Acesso restrito a administradores' });
  }
  next();
}

// Helper para log de ações admin
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
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// ================== AUTH ROUTES ==================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: 'Preencha todos os campos' });
    }

    if (name.length < 2 || name.length > 50) {
      return res.status(400).json({ success: false, error: 'Nome deve ter entre 2 e 50 caracteres' });
    }

    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'A senha deve ter no mínimo 6 caracteres' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: 'Email inválido' });
    }

    const exists = await db.getAsync('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (exists) {
      return res.status(409).json({ success: false, error: 'Este email já está em uso' });
    }

    const hash = await bcrypt.hash(password, 12);
    const cleanName = sanitizeInput(name.trim());

    const result = await db.runAsync(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [cleanName, email.toLowerCase(), hash]
    );

    const user = await db.getAsync(
      'SELECT id, name, email, is_admin FROM users WHERE id = ?',
      [result.id]
    );

    const token = generateToken(user);

    res.status(201).json({
      success: true,
      message: 'Conta criada com sucesso!',
      token,
      user
    });
  } catch (err) {
    console.error('Erro no registro:', err);
    res.status(500).json({ success: false, error: 'Erro ao criar conta' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Informe email e senha' });
    }

    const user = await db.getAsync('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, error: 'Email ou senha incorretos' });
    }

    if (!user.is_active) {
      return res.status(403).json({ success: false, error: 'Conta desativada. Entre em contato com o suporte.' });
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
      message: 'Bem-vindo de volta!',
      token,
      user: safeUser
    });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ success: false, error: 'Erro ao realizar login' });
  }
});

// Get current user
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
    res.status(500).json({ success: false, error: 'Erro ao buscar dados do usuário' });
  }
});

// ================== POSTS ROUTES ==================

// Get all posts with comments (OTIMIZADO - uma query apenas)
app.get('/api/posts', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
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

// Create post
app.post('/api/posts', auth, async (req, res) => {
  try {
    const { text, category = 'outros', anonymous = false } = req.body;

    if (!text || typeof text !== 'string' || !text.trim()) {
      return res.status(400).json({ success: false, error: 'O conteúdo do post não pode estar vazio' });
    }

    if (text.length > 1000) {
      return res.status(400).json({ success: false, error: 'Post muito longo (máx 1000 caracteres)' });
    }

    const validCategories = ['relacionamento', 'trabalho', 'familia', 'saude', 'amizade', 'estudos', 'outros'];
    const finalCategory = validCategories.includes(category) ? category : 'outros';

    const user = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);

    const cleanText = sanitizeInput(text.trim());
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

    if (post.anonymous) {
      post.user_name = null;
    }

    res.status(201).json(post);
  } catch (err) {
    console.error('Erro ao criar post:', err);
    res.status(500).json({ success: false, error: 'Erro ao criar publicação' });
  }
});

// Like/Unlike post
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
    console.error('Erro ao curtir post:', err);
    res.status(500).json({ success: false, error: 'Erro ao curtir post' });
  }
});

// Delete post
app.delete('/api/posts/:postId', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    const post = await db.getAsync('SELECT user_id FROM posts WHERE id = ?', [postId]);

    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    if (post.user_id !== req.userId && !req.userIsAdmin) {
      return res.status(403).json({ success: false, error: 'Sem permissão para excluir este post' });
    }

    await db.runAsync('DELETE FROM posts WHERE id = ?', [postId]);
    res.json({ success: true, message: 'Post excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar post:', err);
    res.status(500).json({ success: false, error: 'Erro ao excluir post' });
  }
});

// ================== COMMENTS ROUTES ==================

// Create comment
app.post('/api/posts/:postId/comment', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    const { content } = req.body;

    if (!content || typeof content !== 'string' || !content.trim()) {
      return res.status(400).json({ success: false, error: 'Comentário obrigatório' });
    }

    if (content.length > 500) {
      return res.status(400).json({ success: false, error: 'Comentário muito longo (máx 500 caracteres)' });
    }

    const post = await db.getAsync('SELECT id FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    const user = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    const cleanContent = sanitizeInput(content.trim());

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
      message: 'Comentário criado com sucesso',
      comment
    });
  } catch (err) {
    console.error('Erro ao criar comentário:', err);
    res.status(500).json({ success: false, error: 'Erro ao criar comentário' });
  }
});

// Get comments for a specific post (paginado)
app.get('/api/posts/:postId/comments', auth, async (req, res) => {
  try {
    const { postId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const comments = await db.allAsync(`
      SELECT c.*, u.name as user_name
      FROM comments c
      LEFT JOIN users u ON c.user_id = u.id
      WHERE c.post_id = ?
      ORDER BY c.created_at ASC
      LIMIT ? OFFSET ?
    `, [postId, limit, offset]);

    const { count } = await db.getAsync(
      'SELECT COUNT(*) as count FROM comments WHERE post_id = ?',
      [postId]
    );

    res.json({
      comments,
      pagination: {
        page,
        limit,
        total: count,
        totalPages: Math.ceil(count / limit)
      }
    });
  } catch (err) {
    console.error('Erro ao buscar comentários:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar comentários' });
  }
});

// Delete comment
app.delete('/api/comments/:commentId', auth, async (req, res) => {
  try {
    const { commentId } = req.params;
    const comment = await db.getAsync('SELECT user_id FROM comments WHERE id = ?', [commentId]);

    if (!comment) {
      return res.status(404).json({ success: false, error: 'Comentário não encontrado' });
    }

    if (comment.user_id !== req.userId && !req.userIsAdmin) {
      return res.status(403).json({ success: false, error: 'Sem permissão para excluir este comentário' });
    }

    await db.runAsync('DELETE FROM comments WHERE id = ?', [commentId]);
    res.json({ success: true, message: 'Comentário excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao deletar comentário:', err);
    res.status(500).json({ success: false, error: 'Erro ao excluir comentário' });
  }
});

// ================== ADMIN ROUTES ==================

// Get dashboard stats
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
    console.error('Erro ao buscar estatísticas:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar estatísticas' });
  }
});

// List all users (admin only) - com paginação e busca
app.get('/api/admin/users', auth, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
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
      params.push(`%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const users = await db.allAsync(query, params);

    // Contar total para paginação
    let countQuery = 'SELECT COUNT(*) as count FROM users';
    let countParams = [];
    if (search) {
      countQuery += ' WHERE name LIKE ? OR email LIKE ?';
      countParams.push(`%${search}%`, `%${search}%`);
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

// Get single user details
app.get('/api/admin/users/:userId', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await db.getAsync(`
      SELECT u.*,
        (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as posts_count,
        (SELECT COUNT(*) FROM comments WHERE user_id = u.id) as comments_count
      FROM users u
      WHERE u.id = ?
    `, [userId]);

    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
    }

    res.json({ success: true, user });
  } catch (err) {
    console.error('Erro ao buscar usuário:', err);
    res.status(500).json({ success: false, error: 'Erro ao carregar dados do usuário' });
  }
});

// Update user (admin only)
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

    // Log da ação
    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, 'UPDATE_USER', 'user', parseInt(userId), { name, is_admin, is_active });

    res.json({
      success: true,
      message: 'Usuário atualizado com sucesso'
    });
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err);
    res.status(500).json({ success: false, error: 'Erro ao atualizar usuário' });
  }
});

// Delete user (admin only)
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

    // Log da ação
    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, 'DELETE_USER', 'user', parseInt(userId), { deletedUser: user.name });

    res.json({ success: true, message: 'Usuário excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir usuário:', err);
    res.status(500).json({ success: false, error: 'Erro ao excluir usuário' });
  }
});

// Toggle user active status (admin only)
app.put('/api/admin/users/:userId/toggle', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;

    if (parseInt(userId) === req.userId) {
      return res.status(400).json({ success: false, error: 'Não pode desativar a si mesmo' });
    }

    const user = await db.getAsync('SELECT is_active, name FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuário não encontrado' });
    }

    const newStatus = user.is_active ? 0 : 1;
    await db.runAsync('UPDATE users SET is_active = ? WHERE id = ?', [newStatus, userId]);

    // Log da ação
    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, newStatus ? 'ACTIVATE_USER' : 'DEACTIVATE_USER', 'user', parseInt(userId));

    res.json({
      success: true,
      message: `Usuário ${newStatus ? 'ativado' : 'desativado'} com sucesso`,
      is_active: newStatus
    });
  } catch (err) {
    console.error('Erro ao alterar status do usuário:', err);
    res.status(500).json({ success: false, error: 'Erro ao alterar status' });
  }
});

// List all posts (admin only) - com paginação e filtros
app.get('/api/admin/posts', auth, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
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

    // Contar total
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

// Flag/Unflag post (admin only)
app.post('/api/admin/posts/:postId/flag', auth, requireAdmin, async (req, res) => {
  try {
    const { postId } = req.params;
    const { flag } = req.body;

    const post = await db.getAsync('SELECT text FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    await db.runAsync('UPDATE posts SET is_flagged = ? WHERE id = ?', [flag ? 1 : 0, postId]);

    // Log da ação
    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, flag ? 'FLAG_POST' : 'UNFLAG_POST', 'post', parseInt(postId));

    res.json({
      success: true,
      message: `Post ${flag ? 'marcado' : 'desmarcado'} com sucesso`
    });
  } catch (err) {
    console.error('Erro ao flagar post:', err);
    res.status(500).json({ success: false, error: 'Erro ao atualizar post' });
  }
});

// Delete post (admin only)
app.delete('/api/admin/posts/:postId', auth, requireAdmin, async (req, res) => {
  try {
    const { postId } = req.params;

    const post = await db.getAsync('SELECT id FROM posts WHERE id = ?', [postId]);
    if (!post) {
      return res.status(404).json({ success: false, error: 'Post não encontrado' });
    }

    await db.runAsync('DELETE FROM posts WHERE id = ?', [postId]);

    // Log da ação
    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, 'DELETE_POST', 'post', parseInt(postId));

    res.json({ success: true, message: 'Post excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir post:', err);
    res.status(500).json({ success: false, error: 'Erro ao excluir post' });
  }
});

// List all reports (admin only)
app.get('/api/admin/reports', auth, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
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

// Create report (qualquer usuário autenticado)
app.post('/api/reports', auth, async (req, res) => {
  try {
    const { post_id, reason, description } = req.body;

    if (!post_id || !reason) {
      return res.status(400).json({ success: false, error: 'Post e motivo são obrigatórios' });
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
      message: 'Report enviado com sucesso',
      report_id: result.id
    });
  } catch (err) {
    console.error('Erro ao criar report:', err);
    res.status(500).json({ success: false, error: 'Erro ao enviar report' });
  }
});

// Resolve report (admin only)
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

    // Log da ação
    const admin = await db.getAsync('SELECT name FROM users WHERE id = ?', [req.userId]);
    await logAdminAction(req.userId, admin.name, 'RESOLVE_REPORT', 'report', parseInt(reportId));

    res.json({ success: true, message: 'Report resolvido com sucesso' });
  } catch (err) {
    console.error('Erro ao resolver report:', err);
    res.status(500).json({ success: false, error: 'Erro ao resolver report' });
  }
});

// List admin logs
app.get('/api/admin/logs', auth, requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;

    const logs = await db.allAsync(`
      SELECT * FROM admin_logs
      ORDER BY created_at DESC
      LIMIT ?
    `, [limit]);

    // Parse details JSON
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
  console.error('Erro não tratado:', err);
  res.status(500).json({
    success: false,
    error: process.env.NODE_ENV === 'production'
      ? 'Erro interno do servidor'
      : err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Rota não encontrada' });
});

// ================== SERVER ==================
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`🚀 Server rodando na porta ${PORT}`);
  console.log(`🔒 Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📱 Frontend: ${process.env.FRONTEND_URL || 'http://localhost:5173'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM recebido. Fechando servidor...');
  server.close(() => {
    db.close(() => {
      console.log('💾 Conexão com banco fechada');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('👋 SIGINT recebido. Fechando servidor...');
  server.close(() => {
    db.close(() => {
      console.log('💾 Conexão com banco fechada');
      process.exit(0);
    });
  });
});