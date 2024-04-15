const express = require('express');
const app = express();
const sqlite = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const PORT = process.env.PORT || 3000;

const db = new sqlite.Database(path.join(__dirname, 'database.db'));

app.use(bodyParser.json());

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
}))
const checkSession = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

app.use((req, res, next) => {
    if (req.path === '/login' || req.path === '/register') {
        next();
    } else {
        checkSession(req, res, next);
    }
});
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER, task TEXT)");
});
app.get('/register', async (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            return res.status(200).json({ message: 'User registered successfully' });
        });
    } catch (error) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/login', async (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            if (!row) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }
            const isValidPassword = await bcrypt.compare(password, row.password);
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }
            req.session.userId = row.id;
            return res.status(200).json({ message: 'Logged in successfully' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', './pages');

app.get('/tasks', (req, res) => {
  console.log("getting tasks");
    const userId = req.session.userId;
    db.all("SELECT id, task FROM tasks WHERE userId = ?" ,[userId] , (err, rows) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
      console.log(rows);
        return res.render('index.ejs', { tasks: rows });
    });
});
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.delete('/tasks/:id', (req, res) => {
    const { id } = req.params;
    db.run("DELETE FROM tasks WHERE id = ?", [id], (err) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        return res.status(200).json({ message: 'Task deleted successfully' });
    });
});
app.post('/add', (req, res) => {
    var { task } = req.body;
    const userId = req.session.userId;
    db.run("INSERT INTO tasks (task, userId) VALUES (?, ?)", [task, userId], (err) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        else {
            res.status(200).json({ message: 'Task added successfully' });
        }
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
