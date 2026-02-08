const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

// Caminho do banco de dados
const dbPath = path.join(__dirname, 'talkpro.db');
const db = new sqlite3.Database(dbPath);

// Promisify database methods
db.run = function(sql, params = []) {
  return new Promise((resolve, reject) => {
    this.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
};

async function seedDatabase() {
  console.log('🌱 Iniciando seed do banco de dados...');
  
  try {
    // Limpar tabelas existentes (opcional)
    await db.run('DELETE FROM admin_logs');
    await db.run('DELETE FROM reports');
    await db.run('DELETE FROM post_likes');
    await db.run('DELETE FROM comments');
    await db.run('DELETE FROM posts');
    await db.run('DELETE FROM users');
    
    console.log('✅ Tabelas limpas');

    // ================== CRIAR USUÁRIOS ==================
    console.log('👥 Criando usuários...');
    
    const users = [
      {
        name: 'Administrador',
        email: 'admin@talkpro.com',
        password: await bcrypt.hash('admin123', 10),
        is_admin: 1,
        is_active: 1
      },
      {
        name: 'João Silva',
        email: 'joao@email.com',
        password: await bcrypt.hash('senha123', 10),
        is_admin: 0,
        is_active: 1
      },
      {
        name: 'Maria Santos',
        email: 'maria@email.com',
        password: await bcrypt.hash('senha123', 10),
        is_admin: 0,
        is_active: 1
      },
      {
        name: 'Pedro Oliveira',
        email: 'pedro@email.com',
        password: await bcrypt.hash('senha123', 10),
        is_admin: 0,
        is_active: 1
      },
      {
        name: 'Ana Costa',
        email: 'ana@email.com',
        password: await bcrypt.hash('senha123', 10),
        is_admin: 0,
        is_active: 1
      },
      {
        name: 'Carlos Souza',
        email: 'carlos@email.com',
        password: await bcrypt.hash('senha123', 10),
        is_admin: 0,
        is_active: 0  // Usuário inativo
      }
    ];

    const userIds = [];
    for (const user of users) {
      const result = await db.run(
        'INSERT INTO users (name, email, password, is_admin, is_active, last_login) VALUES (?, ?, ?, ?, ?, datetime("now", "-" || abs(random() % 30) || " days"))',
        [user.name, user.email, user.password, user.is_admin, user.is_active]
      );
      userIds.push(result.id);
      console.log(`✅ Usuário criado: ${user.name} (ID: ${result.id})`);
    }

    // ================== CRIAR POSTS ==================
    console.log('📝 Criando posts...');
    
    const postsData = [
      {
        user_id: userIds[1], // João
        user_name: 'João Silva',
        text: 'Hoje foi um dia difícil no trabalho. Me sinto sobrecarregado com tantas demandas e prazos curtos. Alguém mais passa por isso?',
        category: 'trabalho',
        anonymous: 0,
        likes: 15
      },
      {
        user_id: userIds[2], // Maria
        user_name: null, // Anônimo
        text: 'Estou me sentindo muito sozinha ultimamente. Não tenho com quem conversar sobre meus sentimentos.',
        category: 'saude',
        anonymous: 1,
        likes: 8
      },
      {
        user_id: userIds[3], // Pedro
        user_name: 'Pedro Oliveira',
        text: 'Consegui minha promoção hoje! Trabalhei tanto para isso. Queria compartilhar minha felicidade com vocês!',
        category: 'trabalho',
        anonymous: 0,
        likes: 25
      },
      {
        user_id: userIds[4], // Ana
        user_name: 'Ana Costa',
        text: 'Dicas para lidar com ansiedade antes de apresentações importantes? Sempre fico muito nervosa.',
        category: 'saude',
        anonymous: 0,
        likes: 12
      },
      {
        user_id: userIds[1], // João
        user_name: 'João Silva',
        text: 'Minha família não entende minhas escolhas profissionais. É difícil quando as pessoas mais próximas não apoiam seus sonhos.',
        category: 'familia',
        anonymous: 0,
        likes: 18
      },
      {
        user_id: userIds[2], // Maria
        user_name: 'Maria Santos',
        text: 'Terminei um relacionamento de 5 anos. Estou perdida e não sei como seguir em frente.',
        category: 'relacionamento',
        anonymous: 0,
        likes: 30
      },
      {
        user_id: userIds[3], // Pedro
        user_name: null, // Anônimo
        text: 'Estou lutando contra pensamentos negativos há semanas. É uma batalha diária.',
        category: 'saude',
        anonymous: 1,
        likes: 20
      },
      {
        user_id: userIds[4], // Ana
        user_name: 'Ana Costa',
        text: 'Conheci pessoas incríveis na faculdade! Estou finalmente me sentindo parte de um grupo.',
        category: 'amizade',
        anonymous: 0,
        likes: 10
      },
      {
        user_id: userIds[1], // João
        user_name: 'João Silva',
        text: 'Meu chefe é muito abusivo. Não sei como lidar com essa situação sem perder meu emprego.',
        category: 'trabalho',
        anonymous: 0,
        likes: 22,
        is_flagged: 1
      },
      {
        user_id: userIds[2], // Maria
        user_name: 'Maria Santos',
        text: 'Estou orgulhosa de mim mesma! Consegui terminar aquele projeto que estava adiando há meses.',
        category: 'outros',
        anonymous: 0,
        likes: 14
      }
    ];

    const postIds = [];
    for (let i = 0; i < postsData.length; i++) {
      const post = postsData[i];
      const daysAgo = Math.floor(Math.random() * 30);
      const result = await db.run(
        `INSERT INTO posts (user_id, user_name, text, category, anonymous, likes, is_flagged, created_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime("now", "-${daysAgo} days"))`,
        [post.user_id, post.user_name, post.text, post.category, post.anonymous, post.likes, post.is_flagged || 0]
      );
      postIds.push(result.id);
      console.log(`✅ Post criado: "${post.text.substring(0, 50)}..." (ID: ${result.id})`);
    }

    // ================== CRIAR LIKES ==================
    console.log('❤️ Criando likes...');
    
    // Cada post recebe likes de usuários aleatórios
    for (const postId of postIds) {
      const numLikes = Math.floor(Math.random() * 5) + 1; // 1-5 likes por post
      const shuffledUsers = [...userIds].sort(() => Math.random() - 0.5);
      
      for (let i = 0; i < Math.min(numLikes, shuffledUsers.length); i++) {
        try {
          await db.run(
            'INSERT OR IGNORE INTO post_likes (user_id, post_id) VALUES (?, ?)',
            [shuffledUsers[i], postId]
          );
        } catch (error) {
          // Ignora erros de chave duplicada
        }
      }
    }
    console.log('✅ Likes criados');

    // ================== CRIAR COMENTÁRIOS ==================
    console.log('💬 Criando comentários...');
    
    const commentsData = [
      {
        post_id: postIds[0],
        user_id: userIds[2],
        text: 'Também passo por isso no meu trabalho. O que tem me ajudado é fazer pausas regulares.'
      },
      {
        post_id: postIds[0],
        user_id: userIds[3],
        text: 'Tenta conversar com seu supervisor sobre a carga de trabalho. Às vezes eles não percebem.'
      },
      {
        post_id: postIds[1],
        user_id: userIds[1],
        text: 'Estou aqui se quiser conversar. Às vezes falar com um estranho pode ajudar.'
      },
      {
        post_id: postIds[2],
        user_id: userIds[4],
        text: 'Parabéns pela promoção! Você merece!'
      },
      {
        post_id: postIds[2],
        user_id: userIds[2],
        text: 'Que notícia incrível! Celebre essa conquista!'
      },
      {
        post_id: postIds[3],
        user_id: userIds[3],
        text: 'Respira fundo antes de começar. Visualize o sucesso. Você consegue!'
      },
      {
        post_id: postIds[4],
        user_id: userIds[2],
        text: 'Minha família também não entendia no começo. Com o tempo e persistência, eles começaram a apoiar.'
      },
      {
        post_id: postIds[5],
        user_id: userIds[1],
        text: 'Dê tempo ao tempo. Cada dia é um passo para a cura. Você é mais forte do que imagina.'
      },
      {
        post_id: postIds[6],
        user_id: userIds[4],
        text: 'Busque ajuda profissional se precisar. Não há vergonha em cuidar da saúde mental.'
      },
      {
        post_id: postIds[7],
        user_id: userIds[1],
        text: 'Que legal! Amizades da faculdade podem durar a vida toda.'
      },
      {
        post_id: postIds[8],
        user_id: userIds[2],
        text: 'Isso é assédio moral. Procure o RH da empresa ou um advogado trabalhista.'
      },
      {
        post_id: postIds[9],
        user_id: userIds[3],
        text: 'Comemore cada conquista, mesmo as pequenas!'
      }
    ];

    for (const comment of commentsData) {
      const daysAgo = Math.floor(Math.random() * 20);
      await db.run(
        `INSERT INTO comments (post_id, user_id, text, created_at) 
         VALUES (?, ?, ?, datetime("now", "-${daysAgo} days"))`,
        [comment.post_id, comment.user_id, comment.text]
      );
    }
    console.log(`✅ ${commentsData.length} comentários criados`);

    // ================== CRIAR REPORTS ==================
    console.log('🚨 Criando reports...');
    
    const reportsData = [
      {
        post_id: postIds[8], // Post com conteúdo inapropriado
        reporter_id: userIds[2],
        reason: 'Conteúdo ofensivo',
        description: 'O post contém linguagem ofensiva e pode violar as regras da comunidade.',
        resolved: 0
      },
      {
        post_id: postIds[3],
        reporter_id: userIds[1],
        reason: 'Spam',
        description: 'Parece conteúdo promocional disfarçado.',
        resolved: 1
      },
      {
        post_id: postIds[0],
        reporter_id: userIds[4],
        reason: 'Assédio',
        description: 'Comentários ofensivos na thread.',
        resolved: 0
      }
    ];

    for (const report of reportsData) {
      const daysAgo = Math.floor(Math.random() * 10);
      await db.run(
        `INSERT INTO reports (post_id, reporter_id, reason, description, resolved, created_at) 
         VALUES (?, ?, ?, ?, ?, datetime("now", "-${daysAgo} days"))`,
        [report.post_id, report.reporter_id, report.reason, report.description, report.resolved]
      );
    }
    console.log(`✅ ${reportsData.length} reports criados`);

    // ================== CRIAR LOGS ADMIN ==================
    console.log('📋 Criando logs administrativos...');
    
    const logsData = [
      {
        admin_id: userIds[0], // Admin
        action: 'DELETE_POST',
        target_type: 'post',
        target_id: postIds[7],
        details: { reason: 'Conteúdo inapropriado' }
      },
      {
        admin_id: userIds[0],
        action: 'UPDATE_USER',
        target_type: 'user',
        target_id: userIds[5],
        details: { field: 'is_active', old_value: 1, new_value: 0 }
      },
      {
        admin_id: userIds[0],
        action: 'RESOLVE_REPORT',
        target_type: 'report',
        target_id: 2,
        details: { action_taken: 'Post verificado, sem violações' }
      },
      {
        admin_id: userIds[0],
        action: 'FLAG_POST',
        target_type: 'post',
        target_id: postIds[8],
        details: { reason: 'Conteúdo potencialmente ofensivo' }
      }
    ];

    for (const log of logsData) {
      const daysAgo = Math.floor(Math.random() * 15);
      await db.run(
        `INSERT INTO admin_logs (admin_id, action, target_type, target_id, details, created_at) 
         VALUES (?, ?, ?, ?, ?, datetime("now", "-${daysAgo} days"))`,
        [log.admin_id, log.action, log.target_type, log.target_id, JSON.stringify(log.details)]
      );
    }
    console.log(`✅ ${logsData.length} logs criados`);

    // ================== ATUALIZAR CONTAGENS ==================
    console.log('🔢 Atualizando contagens...');
    
    // Atualizar contagem de likes nos posts baseado nos likes reais
    for (const postId of postIds) {
      const likesCount = await db.get(
        'SELECT COUNT(*) as count FROM post_likes WHERE post_id = ?',
        [postId]
      );
      
      await db.run(
        'UPDATE posts SET likes = ? WHERE id = ?',
        [likesCount.count, postId]
      );
    }

    console.log('✅ Contagens atualizadas');

    // ================== RESUMO FINAL ==================
    console.log('\n🎉 Seed concluído com sucesso!');
    console.log('===================================');
    
    const counts = await Promise.all([
      db.get('SELECT COUNT(*) as count FROM users'),
      db.get('SELECT COUNT(*) as count FROM posts'),
      db.get('SELECT COUNT(*) as count FROM comments'),
      db.get('SELECT COUNT(*) as count FROM reports'),
      db.get('SELECT COUNT(*) as count FROM admin_logs')
    ]);
    
    console.log(`👥 Usuários: ${counts[0].count}`);
    console.log(`📝 Posts: ${counts[1].count}`);
    console.log(`💬 Comentários: ${counts[2].count}`);
    console.log(`🚨 Reports: ${counts[3].count}`);
    console.log(`📋 Logs Admin: ${counts[4].count}`);
    
    console.log('\n👑 Credenciais do Admin:');
    console.log('📧 Email: admin@talkpro.com');
    console.log('🔑 Senha: admin123');
    console.log('\n👤 Credenciais dos usuários (senha: senha123):');
    console.log('📧 joao@email.com');
    console.log('📧 maria@email.com');
    console.log('📧 pedro@email.com');
    console.log('📧 ana@email.com');
    console.log('\n🌐 Acesse o admin panel em: http://localhost:5173/admin');

  } catch (error) {
    console.error('❌ Erro durante o seed:', error);
  } finally {
    db.close();
  }
}

// Executar o seed
seedDatabase();