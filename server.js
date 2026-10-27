const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_padrao_para_desenvolvimento';

app.use(express.json());
app.use(cors());

// Configuração do Banco de Dados PostgreSQL (Render)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

console.log('Conectando ao banco de dados PostgreSQL...');

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
    if (!storedHash || !storedHash.includes(':')) return false;
    const [salt, key] = storedHash.split(':');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return key === hash;
}

async function initDatabase() {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            user_id TEXT UNIQUE,
            name TEXT,
            password TEXT,
            role TEXT,
            failed_login_attempts INT DEFAULT 0,
            lockout_until TIMESTAMP NULL
        )`);

        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0`);
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS lockout_until TIMESTAMP NULL`);

        await pool.query(`CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            name TEXT,
            sku TEXT,
            category TEXT,
            price REAL,
            quantity INTEGER,
            min_stock INTEGER,
            updated_at TEXT
        )`);

        await pool.query(`CREATE TABLE IF NOT EXISTS movements (
            id TEXT PRIMARY KEY,
            product_id TEXT,
            product_name TEXT,
            type TEXT,
            quantity INTEGER,
            unit_price REAL,
            old_price REAL,
            price_variation REAL,
            reason TEXT,
            user_name TEXT,
            date TEXT
        )`);

        // Garante que movements tenha a constraint de PRIMARY KEY caso a tabela já existisse sem ela
        await pool.query(`
            DO $$ 
            BEGIN 
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint WHERE conname = 'movements_pkey'
                ) THEN 
                    ALTER TABLE movements ADD CONSTRAINT movements_pkey PRIMARY KEY (id);
                END IF; 
            END $$;
        `);

        // Garante colunas de preço no histórico caso a tabela seja antiga
        await pool.query(`ALTER TABLE movements ADD COLUMN IF NOT EXISTS unit_price REAL`);
        await pool.query(`ALTER TABLE movements ADD COLUMN IF NOT EXISTS old_price REAL`);
        await pool.query(`ALTER TABLE movements ADD COLUMN IF NOT EXISTS price_variation REAL`);

        await pool.query(`CREATE TABLE IF NOT EXISTS price_history (
            id TEXT PRIMARY KEY,
            product_id TEXT,
            product_name TEXT,
            type TEXT,
            quantity INTEGER,
            unit_price REAL,
            old_price REAL,
            price_variation REAL,
            reason TEXT,
            user_name TEXT,
            date TEXT
        )`);

        // Garante que price_history tenha a constraint de PRIMARY KEY caso a tabela já existisse sem ela
        await pool.query(`
            DO $$ 
            BEGIN 
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint WHERE conname = 'price_history_pkey'
                ) THEN 
                    ALTER TABLE price_history ADD CONSTRAINT price_history_pkey PRIMARY KEY (id);
                END IF; 
            END $$;
        `);

        await pool.query(`CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )`);

        const migrationClient = await pool.connect();
        try {
            await migrationClient.query('BEGIN');
            const migration = await migrationClient.query(
                `INSERT INTO app_settings (key, value)
                 VALUES ('price_history_migrated', 'true')
                 ON CONFLICT (key) DO NOTHING
                 RETURNING key`
            );
            if (migration.rowCount > 0) {
                await migrationClient.query(
                    `INSERT INTO price_history (id, product_id, product_name, type, quantity, unit_price, old_price, price_variation, reason, user_name, date)
                     SELECT id, product_id, product_name, type, quantity, unit_price, old_price, price_variation, reason, user_name, date
                     FROM movements
                     WHERE type = 'ENTRADA'
                     ON CONFLICT (id) DO NOTHING`
                );
            }
            await migrationClient.query('COMMIT');
        } catch (err) {
            await migrationClient.query('ROLLBACK');
            throw err;
        } finally {
            migrationClient.release();
        }

        const defaultUsers = [
            { user_id: '91004500', name: 'João Vítor Maximiano', role: 'admin' },
            { user_id: '91002420', name: 'Maiara Lima de Souza Godoy', role: 'comum' },
            { user_id: '91006099', name: 'Mariane Ferreira Sampaio', role: 'comum' },
            { user_id: '91006300', name: 'Ana Júlia de Marins Costa', role: 'comum' },
            { user_id: '91004447', name: 'Júlio Gouveia', role: 'comum' },
            { user_id: '91002345', name: 'Júlia da Silva Martins Machado', role: 'comum' },
            { user_id: '91001371', name: 'Fábio Júnior Gonçalves', role: 'comum' }
        ];

        for (const u of defaultUsers) {
            const securePassword = hashPassword('123456');
            await pool.query(
                `INSERT INTO users (user_id, name, password, role) 
                 VALUES ($1, $2, $3, $4) 
                 ON CONFLICT (user_id) 
                 DO UPDATE SET name = EXCLUDED.name, role = EXCLUDED.role`,
                [u.user_id, u.name, securePassword, u.role]
            );
        }
        
        console.log('Banco de dados PostgreSQL inicializado e usuários verificados/criados com sucesso.');
    } catch (err) {
        console.error('Erro ao inicializar o banco de dados:', err);
        throw err;
    }
}

app.use(express.static(path.join(__dirname)));

app.post('/api/auth', async (req, res) => {
    const { userId, password } = req.body;
    if (!userId || !password) {
        return res.status(400).json({ error: 'Informe o ID e a senha.' });
    }

    try {
        const result = await pool.query(`SELECT * FROM users WHERE user_id = $1`, [userId]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'ID de acesso ou senha incorretos.' });
        }

        const agora = new Date();

        if (user.lockout_until && new Date(user.lockout_until) > agora) {
            const minutosRestantes = Math.ceil((new Date(user.lockout_until) - agora) / (1000 * 60));
            return res.status(429).json({ 
                error: `Conta temporariamente bloqueada devido a excesso de tentativas incorretas. Tente novamente em ${minutosRestantes} minuto(s).` 
            });
        }

        if (!verifyPassword(password, user.password)) {
            const novasTentativas = (user.failed_login_attempts || 0) + 1;
            let tempoBloqueio = null;

            if (novasTentativas >= 5) {
                tempoBloqueio = new Date(agora.getTime() + 15 * 60 * 1000);
            }

            await pool.query(
                `UPDATE users SET failed_login_attempts = $1, lockout_until = $2 WHERE user_id = $3`,
                [novasTentativas, tempoBloqueio, userId]
            );

            if (novasTentativas >= 5) {
                return res.status(429).json({ 
                    error: 'Muitas tentativas incorretas. Sua conta foi bloqueada por 15 minutos.' 
                });
            }

            const tentativasRestantes = 5 - novasTentativas;
            return res.status(401).json({ 
                error: `ID de acesso ou senha incorretos. Você tem ${tentativasRestantes} tentativa(s) restante(s) antes do bloqueio.` 
            });
        }

        await pool.query(
            `UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE user_id = $1`,
            [userId]
        );

        const token = jwt.sign(
            { id: user.user_id, role: user.role, name: user.name },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({
            token,
            user: {
                id: user.user_id,
                name: user.name,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Erro no login:', err);
        return res.status(500).json({ error: 'Erro interno no servidor.' });
    }
});

app.put('/api/users/password', async (req, res) => {
    const { userId, oldPassword, newPassword } = req.body;

    if (!userId || !oldPassword || !newPassword) {
        return res.status(400).json({ error: 'Preencha todos os campos.' });
    }

    try {
        const result = await pool.query(`SELECT * FROM users WHERE user_id = $1`, [userId]);
        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ error: 'Este ID não está registrado no sistema.' });
        }

        if (!verifyPassword(oldPassword, user.password)) {
            return res.status(401).json({ error: 'A senha atual está incorreta.' });
        }

        const secureNewPassword = hashPassword(newPassword);
        
        await pool.query(
            `UPDATE users SET password = $1, failed_login_attempts = 0, lockout_until = NULL WHERE user_id = $2`, 
            [secureNewPassword, userId]
        );

        res.json({ success: true, message: 'Senha alterada com sucesso!' });
    } catch (err) {
        return res.status(500).json({ error: 'Erro ao atualizar a senha.' });
    }
});

app.get('/api/data', async (req, res) => {
    try {
        const productsRes = await pool.query(`SELECT * FROM products`);
        const movementsRes = await pool.query(`SELECT * FROM movements ORDER BY date DESC`);
        const priceHistoryRes = await pool.query(`SELECT * FROM price_history ORDER BY date DESC`);
        const usersRes = await pool.query(`SELECT user_id as id, name, role FROM users`);

        res.json({ 
            products: productsRes.rows, 
            movements: movementsRes.rows, 
            price_history: priceHistoryRes.rows,
            users: usersRes.rows 
        });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao carregar dados do sistema.' });
    }
});

app.post('/api/sync', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Acesso negado. Token de autenticação ausente.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (!decoded) {
            return res.status(403).json({ error: 'Acesso negado. Sessão inválida.' });
        }

        const { products, movements, priceHistory } = req.body;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            if (products && Array.isArray(products)) {
                for (const p of products) {
                    await client.query(
                        `INSERT INTO products (id, name, sku, category, price, quantity, min_stock, updated_at) 
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                         ON CONFLICT (id) DO UPDATE SET 
                            name = EXCLUDED.name,
                            sku = EXCLUDED.sku,
                            category = EXCLUDED.category,
                            price = EXCLUDED.price,
                            quantity = EXCLUDED.quantity,
                            min_stock = EXCLUDED.min_stock,
                            updated_at = EXCLUDED.updated_at`,
                        [p.id, p.name, p.sku, p.category, p.price, p.quantity, p.min_stock, p.updated_at]
                    );
                }
            }

            if (movements !== undefined && Array.isArray(movements)) {
                await client.query(`DELETE FROM movements`);
                for (const m of movements) {
                    await client.query(
                        `INSERT INTO movements (id, product_id, product_name, type, quantity, unit_price, old_price, price_variation, reason, user_name, date) 
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                        [m.id, m.product_id, m.product_name, m.type, m.quantity, m.unit_price || 0, m.old_price || 0, m.price_variation || 0, m.reason, m.user_name, m.date]
                    );
                }
            }

            if (priceHistory !== undefined && Array.isArray(priceHistory)) {
                await client.query(`DELETE FROM price_history`);
                for (const m of priceHistory) {
                    await client.query(
                        `INSERT INTO price_history (id, product_id, product_name, type, quantity, unit_price, old_price, price_variation, reason, user_name, date)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                        [m.id, m.product_id, m.product_name, m.type, m.quantity, m.unit_price || 0, m.old_price || 0, m.price_variation || 0, m.reason, m.user_name, m.date]
                    );
                }
            }

            await client.query('COMMIT');
            res.json({ success: true });
        } catch (err) {
            await client.query('ROLLBACK');
            console.error('Erro na transação de sync:', err);
            res.status(500).json({ error: 'Erro ao sincronizar dados.' });
        } finally {
            client.release();
        }
    } catch (err) {
        return res.status(403).json({ error: 'Sessão inválida ou expirada. Faça login novamente.' });
    }
});

initDatabase()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Servidor rodando na porta ${PORT}`);
        });
    })
    .catch(async () => {
        console.error('Servidor não iniciado porque o banco de dados não foi inicializado.');
        await pool.end();
        process.exitCode = 1;
    });
