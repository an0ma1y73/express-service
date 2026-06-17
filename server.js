// server.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// --- Конфигурация ---
const PORT = 3000;
const HOST = 'localhost';
const DATA_FILE = path.join(__dirname, 'data.json');
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 минут
const BRUTE_FORCE_TIMEOUT = 15 * 60 * 1000; // 15 минут
const MAX_LOGIN_ATTEMPTS = 3;

// --- Инициализация базы данных ---
let db = { users: {}, orders: [] };

function loadDatabase() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            const rawData = fs.readFileSync(DATA_FILE, 'utf8');
            db = JSON.parse(rawData);
            console.log('✅ База данных загружена.');
        } else {
            console.log('📁 Файл базы данных не найден. Создаем новый...');
            // Создаем тестового пользователя
            registerUser('Администратор', 'admin@example.com', 'admin123');
            console.log('👤 Создан тестовый пользователь: admin@example.com / admin123');
        }
    } catch (error) {
        console.error('❌ Ошибка загрузки базы данных:', error);
        db = { users: {}, orders: [] };
    }
}

function saveDatabase() {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
        console.log('💾 База данных сохранена.');
    } catch (error) {
        console.error('❌ Ошибка сохранения базы данных:', error);
    }
}

// --- Хелперы ---
function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

function generateSalt() {
    return crypto.randomBytes(16).toString('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function parseCookies(request) {
    const list = {};
    const cookieHeader = request.headers.cookie;
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            let parts = cookie.split('=');
            list[parts.shift().trim()] = decodeURI(parts.join('='));
        });
    }
    return list;
}

function getClientIP(req) {
    return req.headers['x-forwarded-for'] || 
           req.headers['x-real-ip'] || 
           req.socket.remoteAddress || 
           'unknown';
}

// --- Работа с пользователями ---
function registerUser(name, email, password) {
    if (db.users[email]) {
        return { success: false, message: 'Пользователь с таким email уже существует' };
    }
    
    // Валидация
    if (!name || name.trim().length < 2) {
        return { success: false, message: 'Имя должно содержать минимум 2 символа' };
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return { success: false, message: 'Некорректный email' };
    }
    if (!password || password.length < 6) {
        return { success: false, message: 'Пароль должен содержать минимум 6 символов' };
    }

    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);
    const id = Date.now().toString(16) + Math.random().toString(16).substring(2, 8);
    
    db.users[email] = {
        id,
        name: name.trim(),
        email: email.trim(),
        passwordHash,
        salt,
        loginAttempts: 0,
        lockedUntil: null,
        createdAt: new Date().toISOString()
    };
    saveDatabase();
    return { success: true, message: 'Регистрация успешна' };
}

function authenticateUser(email, password, ip) {
    const user = db.users[email];
    if (!user) {
        return { success: false, message: 'Пользователь не найден' };
    }

    // Проверка блокировки
    if (user.lockedUntil && Date.now() < user.lockedUntil) {
        const remainingMinutes = Math.ceil((user.lockedUntil - Date.now()) / 60000);
        return { 
            success: false, 
            message: `Аккаунт заблокирован на ${remainingMinutes} мин. из-за множества неудачных попыток входа.` 
        };
    }

    // Сброс блокировки после истечения времени
    if (user.lockedUntil && Date.now() >= user.lockedUntil) {
        user.loginAttempts = 0;
        user.lockedUntil = null;
        saveDatabase();
    }

    const passwordHash = hashPassword(password, user.salt);

    if (user.passwordHash === passwordHash) {
        // Успешный вход: сброс попыток
        user.loginAttempts = 0;
        user.lockedUntil = null;
        saveDatabase();
        return { 
            success: true, 
            user: { id: user.id, name: user.name, email: user.email } 
        };
    } else {
        // Неудачная попытка
        user.loginAttempts = (user.loginAttempts || 0) + 1;
        console.log(`⚠️ Неудачная попытка входа для ${email}. Попытка ${user.loginAttempts} из ${MAX_LOGIN_ATTEMPTS} (IP: ${ip})`);
        
        if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
            user.lockedUntil = Date.now() + BRUTE_FORCE_TIMEOUT;
            user.loginAttempts = 0;
            saveDatabase();
            return { 
                success: false, 
                message: `Аккаунт заблокирован на 15 минут из-за превышения попыток входа.` 
            };
        }
        saveDatabase();
        return { success: false, message: 'Неверный пароль' };
    }
}

// --- Работа с сессиями ---
const sessions = {};

function createSession(user) {
    const token = generateToken();
    sessions[token] = {
        userId: user.id,
        userEmail: user.email,
        userName: user.name,
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_TIMEOUT
    };
    return token;
}

function getSession(token) {
    const session = sessions[token];
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        delete sessions[token];
        return null;
    }
    return session;
}

function deleteSession(token) {
    if (token) {
        delete sessions[token];
    }
}

// --- Валидация заказов ---
function validateOrderData(name, phone, equipment, comment) {
    const errors = [];
    if (!name || name.trim().length < 2) {
        errors.push('Имя должно содержать минимум 2 символа');
    }
    if (!phone || !/^[\+\d\s\-\(\)]{10,15}$/.test(phone)) {
        errors.push('Некорректный номер телефона (минимум 10 цифр)');
    }
    if (!equipment || equipment.trim().length === 0) {
        errors.push('Необходимо указать оборудование');
    }
    return errors;
}

// --- Обработка статических файлов ---
function serveStaticFile(filePath, res) {
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('404 Not Found');
            return;
        }
        const ext = path.extname(filePath).toLowerCase();
        const contentTypes = {
            '.html': 'text/html; charset=utf-8',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon'
        };
        res.writeHead(200, { 'Content-Type': contentTypes[ext] || 'application/octet-stream' });
        res.end(data);
    });
}

// --- Обработка API запросов ---
function handleAPI(req, res, parsedUrl) {
    const pathname = parsedUrl.pathname;

    // CORS заголовки для разработки
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return true;
    }

    // --- Регистрация ---
    if (pathname === '/api/register' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const { name, email, password, confirm } = JSON.parse(body);
                
                if (password !== confirm) {
                    throw new Error('Пароли не совпадают');
                }

                const result = registerUser(name, email, password);
                res.writeHead(result.success ? 200 : 400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: error.message }));
            }
        });
        return true;
    }

    // --- Вход ---
    if (pathname === '/api/login' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const { email, password } = JSON.parse(body);
                const ip = getClientIP(req);
                const result = authenticateUser(email.trim(), password, ip);

                if (result.success) {
                    const token = createSession(result.user);
                    res.writeHead(200, {
                        'Content-Type': 'application/json',
                        'Set-Cookie': `sessionToken=${token}; Path=/; HttpOnly; Max-Age=${SESSION_TIMEOUT/1000}; SameSite=Lax`
                    });
                    res.end(JSON.stringify({ success: true, user: result.user }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: result.message }));
                }
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Неверный запрос' }));
            }
        });
        return true;
    }

    // --- Выход ---
    if (pathname === '/api/logout' && req.method === 'POST') {
        const cookies = parseCookies(req);
        const token = cookies.sessionToken;
        deleteSession(token);
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': `sessionToken=; Path=/; HttpOnly; Max-Age=0`
        });
        res.end(JSON.stringify({ success: true }));
        return true;
    }

    // --- Проверка текущего пользователя ---
    if (pathname === '/api/me' && req.method === 'GET') {
        const cookies = parseCookies(req);
        const token = cookies.sessionToken;
        const session = getSession(token);

        if (session) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                authenticated: true,
                user: { id: session.userId, name: session.userName, email: session.userEmail }
            }));
        } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ authenticated: false }));
        }
        return true;
    }

    // --- Создание заказа ---
    if (pathname === '/api/orders' && req.method === 'POST') {
        const cookies = parseCookies(req);
        const token = cookies.sessionToken;
        const session = getSession(token);

        if (!session) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Необходимо авторизоваться' }));
            return true;
        }

        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const { name, phone, equipment, comment } = JSON.parse(body);
                const errors = validateOrderData(name, phone, equipment, comment);
                
                if (errors.length > 0) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, errors }));
                    return;
                }

                const newOrder = {
                    id: Date.now().toString(16) + Math.random().toString(16).substring(2, 8),
                    userId: session.userId,
                    userName: name.trim(),
                    userPhone: phone.trim(),
                    equipmentName: equipment.trim(),
                    comment: comment ? comment.trim() : '',
                    createdAt: new Date().toISOString(),
                    status: 'new'
                };
                db.orders.push(newOrder);
                saveDatabase();

                res.writeHead(201, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, order: newOrder }));
            } catch (error) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Ошибка обработки заказа' }));
            }
        });
        return true;
    }

    // --- Получение заказов пользователя ---
    if (pathname === '/api/orders' && req.method === 'GET') {
        const cookies = parseCookies(req);
        const token = cookies.sessionToken;
        const session = getSession(token);

        if (!session) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Необходимо авторизоваться' }));
            return true;
        }

        const userOrders = db.orders.filter(order => order.userId === session.userId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, orders: userOrders }));
        return true;
    }

    // Если API роут не найден
    return false;
}

// --- Создание сервера ---
const server = http.createServer((req, res) => {
    console.log(`${req.method} ${req.url}`);
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    // 1. Проверяем API запросы
    if (pathname.startsWith('/api/')) {
        handleAPI(req, res, parsedUrl);
        return;
    }

    // 2. Отдаем статические файлы (изображения, CSS, JS)
    if (pathname.startsWith('/images/') || 
        pathname.startsWith('/css/') || 
        pathname.startsWith('/js/')) {
        const filePath = path.join(__dirname, 'views', pathname);
        serveStaticFile(filePath, res);
        return;
    }

    // 3. Отдаем HTML страницы
    let filePath = './views/error.html';
    if (pathname === '/') filePath = './views/index.html';
    else if (pathname === '/about') filePath = './views/about.html';
    else if (pathname === '/catalog') filePath = './views/catalog.html';
    else if (pathname === '/equipment') filePath = './views/equipment.html';
    else if (pathname === '/login') filePath = './views/login.html';
    else if (pathname === '/register') filePath = './views/register.html';

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('404 Not Found');
            return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(data);
    });
});

// --- Запуск сервера ---
loadDatabase();

server.listen(PORT, HOST, () => {
    console.log(`\n🚀 Сервер запущен: http://${HOST}:${PORT}`);
    console.log(`📊 База данных: ${DATA_FILE}`);
    console.log(`👤 Тестовый пользователь: admin@example.com / admin123`);
    console.log(`🔒 Блокировка после ${MAX_LOGIN_ATTEMPTS} неудачных попыток на ${BRUTE_FORCE_TIMEOUT/60000} минут\n`);
});

// Обработка завершения
process.on('SIGINT', () => {
    console.log('\n💾 Сохранение базы данных...');
    saveDatabase();
    console.log('👋 Сервер остановлен');
    process.exit(0);
});