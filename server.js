require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ================== DATABASE ==================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 🔥 AUTO CRIAR TABELAS
async function createTables() {
    try {
        await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(120) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id),
        user_name VARCHAR(120),
        text TEXT NOT NULL,
        category VARCHAR(50) DEFAULT 'outros',
        anonymous BOOLEAN DEFAULT false,
        likes INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        post_id INT REFERENCES posts(id) ON DELETE CASCADE,
        user_id INT REFERENCES users(id),
        text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
        console.log("✅ Tabelas prontas");
    } catch (err) {
        console.error("Erro ao criar tabelas:", err);
    }
}
createTables();

// ================== MIDDLEWARE ==================
function auth(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ================== REGISTER ==================
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Preencha todos os campos' });

    try {
        const exists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (exists.rows.length) return res.status(400).json({ error: 'Email já cadastrado' });

        const hash = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (name, email, password) VALUES ($1,$2,$3) RETURNING id,name,email',
            [name, email, hash]
        );

        const token = jwt.sign({ id: newUser.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token, user: newUser.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

// ================== LOGIN ==================
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Preencha todos os campos' });

    try {
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (!user.rows.length) return res.status(400).json({ error: 'Email ou senha inválidos' });

        const valid = await bcrypt.compare(password, user.rows[0].password);
        if (!valid) return res.status(400).json({ error: 'Email ou senha inválidos' });

        const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.rows[0].id, name: user.rows[0].name, email: user.rows[0].email } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

// ================== DASHBOARD ==================
app.get('/api/dashboard', auth, async (req, res) => {
    try {
        const user = await pool.query('SELECT id,name,email FROM users WHERE id = $1', [req.userId]);
        res.json({ user: user.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

// ================== POSTS ==================
app.get('/api/posts', auth, async (req, res) => {
    try {
        const posts = await pool.query(`
      SELECT p.*, u.name as user_name,
        COALESCE(likes, 0) as likes
      FROM posts p
      LEFT JOIN users u ON u.id = p.user_id
      ORDER BY created_at DESC
    `);

        // Buscar comentários para cada post
        const postIds = posts.rows.map(p => p.id);
        const comments = postIds.length ? await pool.query(
            `SELECT * FROM comments ORDER BY created_at ASC`
        ) : { rows: [] };

        const postsWithComments = posts.rows.map(post => ({
            ...post,
            comments: comments.rows.filter(c => c.post_id === post.id)
        }));

        res.json(postsWithComments);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao carregar posts' });
    }
});

app.post('/api/posts', auth, async (req, res) => {
    const { text, category, anonymous } = req.body;
    if (!text) return res.status(400).json({ error: 'Digite algo antes de postar' });

    try {
        const user = await pool.query('SELECT name FROM users WHERE id = $1', [req.userId]);
        const result = await pool.query(
            'INSERT INTO posts (user_id, user_name, text, category, anonymous) VALUES ($1,$2,$3,$4,$5) RETURNING *',
            [req.userId, user.rows[0].name, text, category || 'outros', anonymous || false]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao criar post' });
    }
});

app.post('/api/posts/:id/like', auth, async (req, res) => {
    try {
        await pool.query('UPDATE posts SET likes = likes + 1 WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Erro ao curtir post' });
    }
});

app.delete('/api/posts/:id', auth, async (req, res) => {
    try {
        await pool.query('DELETE FROM posts WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Erro ao deletar post' });
    }
});

// ================== COMMENTS ==================
app.post('/api/posts/:id/comment', auth, async (req, res) => {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Digite algo antes de comentar' });

    try {
        await pool.query(
            'INSERT INTO comments (post_id, user_id, text) VALUES ($1,$2,$3)',
            [req.params.id, req.userId, text]
        );
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Erro ao comentar' });
    }
});

app.delete('/api/comments/:id', auth, async (req, res) => {
    try {
        await pool.query('DELETE FROM comments WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Erro ao deletar comentário' });
    }
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🔥 API rodando na porta ${PORT}`));
