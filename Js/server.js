const express = require('express');
const multer = require('multer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key'; // Змініть на щось безпечне
const USERS_FILE = path.join(__dirname, 'users.json');
const ACCESS_FILE = path.join(__dirname, 'access.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOADS_DIR));

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
if (!fs.existsSync(ACCESS_FILE)) fs.writeFileSync(ACCESS_FILE, JSON.stringify([]));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => cb(null, file.originalname + '_' + Date.now())
});
const upload = multer({ storage });

// Реєстрація
app.post('/register', (req, res) => {
    const { login, password } = req.body;
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    if (users.find(u => u.login === login)) return res.json({ message: 'Логін зайнятий' });
    users.push({ login, password }); // У реальності хешуйте пароль!
    fs.writeFileSync(USERS_FILE, JSON.stringify(users));
    res.json({ message: 'Реєстрація успішна' });
});

// Вхід
app.post('/login', (req, res) => {
    const { login, password } = req.body;
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const user = users.find(u => u.login === login && u.password === password);
    if (!user) return res.json({ message: 'Неправильні дані' });
    const token = jwt.sign({ login }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Middleware для перевірки токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Токен відсутній' });
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Недійсний токен' });
        req.user = user;
        next();
    });
}

// Завантаження фото
app.post('/upload', authenticateToken, upload.array('photos'), (req, res) => {
    res.json({ message: 'Фото завантажено' });
});

// Список фото
app.get('/photos', authenticateToken, (req, res) => {
    const access = JSON.parse(fs.readFileSync(ACCESS_FILE));
    if (req.user.login !== 'owner' && !access.includes(req.user.login)) {
        return res.json({ error: 'У вас немає доступу' });
    }
    fs.readdir(UPLOADS_DIR, (err, files) => {
        if (err) return res.status(500).json({ error: 'Помилка' });
        const photos = files.map(file => ({
            url: `http://localhost:${PORT}/uploads/${file}`,
            filename: file,
            uploader: req.user.login || 'Анонім' // Для простоти, uploader = поточний користувач
        }));
        res.json(photos);
    });
});

// Видалення фото
app.delete('/photos/:filename', authenticateToken, (req, res) => {
    if (req.user.login !== 'owner') return res.status(403).json({ error: 'Тільки власник може видаляти' });
    const filePath = path.join(UPLOADS_DIR, req.params.filename);
    fs.unlink(filePath, err => {
        if (err) return res.status(500).json({ error: 'Помилка видалення' });
        res.json({ message: 'Видалено' });
    });
});

// Додати доступ
app.post('/add-access', authenticateToken, (req, res) => {
    if (req.user.login !== 'owner') return res.status(403).json({ error: 'Тільки власник' });
    const { accessLogin } = req.body;
    const access = JSON.parse(fs.readFileSync(ACCESS_FILE));
    if (!access.includes(accessLogin)) {
        access.push(accessLogin);
        fs.writeFileSync(ACCESS_FILE, JSON.stringify(access));
    }
    res.json({ message: 'Додано' });
});

// Видалити доступ
app.post('/remove-access', authenticateToken, (req, res) => {
    if (req.user.login !== 'owner') return res.status(403).json({ error: 'Тільки власник' });
    const { accessLogin } = req.body;
    let access = JSON.parse(fs.readFileSync(ACCESS_FILE));
    access = access.filter(l => l !== accessLogin);
    fs.writeFileSync(ACCESS_FILE, JSON.stringify(access));
    res.json({ message: 'Видалено' });
});

// Список дозволених
app.get('/allowed-users', authenticateToken, (req, res) => {
    if (req.user.login !== 'owner') return res.status(403).json({ error: 'Тільки власник' });
    const access = JSON.parse(fs.readFileSync(ACCESS_FILE));
    res.json(access);
});

app.listen(PORT, () => console.log(`Сервер на http://localhost:${PORT}`));