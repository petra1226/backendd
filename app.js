const express = require('express');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const mysql = require('mysql2');
const validator = require('validator');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();

dotenv.config();
const PORT = process.env.PORT;
const HOSTNAME = process.env.HOSTNAME;

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    timezone: 'Z',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const limiter = rateLimit({
    windowMs: 1000 * 60 * 15,
    max: 1000
});

const uploadDir = 'uploads/';
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const now = new Date().toISOString().split('T')[0];
        cb(null, `${req.user.id}-${now}-${file.originalname}`);
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif|webp|avif/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);

        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb(new Error('Csak képformátumok megengedettek'));
        }
    }
});

const JWT_SECRET = process.env.JWT_SECRET;
function authenticateToken(req, res, next) {
    const token = req.cookies.auth_token;

    if (!token) {
        return res.status(403).json({ error: 'Nincsen tokened' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Van tokened, de nem jó' });
        }
        req.user = user;
        next();
    });
};

function authorizeAdmin(req, res, next) {
    if (!req.user.is_admin) {
        return res.status(403).json({ error: 'Nincs admin jogosultságod' });
    }
    next();
}
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(limiter);
app.use(cookieParser());
app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://192.168.10.14:5500','http://localhost:5500'],
    credentials: true
}));

app.use('/uploads', authenticateToken, express.static(path.join(__dirname, 'uploads')));



//regisztráció
app.post('/api/register', (req, res) => {
    const { email, username, psw } = req.body;
    const errors = [];

    if (!validator.isEmail(email)) {
        errors.push({ error: 'Nem valós email' });
    }

    if (validator.isEmpty(username)) {
        errors.push({ error: 'Töltsd ki a nevet ' });
    }

    if (!validator.isLength(psw, { min: 6 })) {
        errors.push({ error: 'A jelszónak minimum 6 karakterből kell állnia' });
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    const salt = 10;
    bcrypt.hash(psw, salt, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba a sózáskor' });
        }

        const sql = 'INSERT INTO users (user_id, email, username, psw) VALUES (NULL, ?, ?, ?)';
        pool.query(sql, [email, username, hash], (err2, result) => {
            if (err2) {
                return res.status(500).json({ error: 'Az email már foglalt' });
            }

            res.status(201).json({ message: 'Sikeres regisztráció' });
        });
    });
});


// bejelentkezés
app.post('/api/login', (req, res) => {
    const { email, psw } = req.body;
    const errors = [];

    if (!validator.isEmail(email)) {
        errors.push({ error: 'Add meg az email címet' });
    }

    if (validator.isEmpty(psw)) {
        errors.push({ error: 'Add meg a jelszót' });
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    const sql = 'SELECT * FROM users WHERE email LIKE ?';
    pool.query(sql, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        if (result.length === 0) {
            return res.status(404).json({ error: 'A felhasználó nem található' });
        }

        const user = result[0];
        bcrypt.compare(psw, user.psw, (err, isMatch) => {
            if (isMatch) {
                const token = jwt.sign(
                    {
                        id: user.user_id,
                        is_admin: user.is_admin // Admin státusz a tokenben
                    },
                    JWT_SECRET,
                    {
                        expiresIn: '1y'
                    }
                );

                res.cookie('auth_token', token, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'none',
                    maxAge: 3600000 * 24 * 31 * 12
                });
                

                return res.status(200).json({ message: 'Sikeres bejelentkezés' });
            } else {
                return res.status(401).json({ error: 'Rossz a jelszó' });
            }
        });
    });
});


//termék keresése
app.get('/products/:search', (req, res) => {
 
    const { search } = req.params;

    const keres = `%${search}%`;
    const sql = 'SELECT * FROM uploads WHERE name LIKE ? OR price LIKE ?';

    db.query(sql, [keres, keres], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send({ error: 'Adatbázis hiba' });
        }

        res.send(result);
    });
});


// teszt végpont
app.get('/api/teszt', authenticateToken, (req, res) => {
    const user = req.user;
    return res.status(200).json({ message: 'bent vagy ', user });
});


// profil név szerkesztése
app.put('/api/editProfileName', authenticateToken, (req, res) => {
    console.log('Token info:', req.user);  // Ellenőrizd, hogy megjelenik-e a token
    const firstname = req.body.firstname;
    const surname = req.body.surname;
    const user_id = req.user.id;

    const sql = 'UPDATE users SET firstname = COALESCE(NULLIF(?, ""), firstname), surname = COALESCE(NULLIF(?, ""), surname) WHERE user_id = ?';


    pool.query(sql, [firstname, surname, user_id], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Felhasználó nem található' });
        }

        return res.status(200).json({ message: 'Név frissítve' });
    });
});


// jelszó módosítása

app.put('/api/editProfilePsw', authenticateToken, (req, res) => {
    const psw = req.body.psw;
    const user_id = req.user.id;

    const salt = 10;

    if (psw === '' && !validator.isLength(psw, { min: 6 })) {
        return res.status(400).json({ error: 'A jelszónak min 6 karakterből kell állnia' });
    }

    bcrypt.hash(psw, salt, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba a sózáskor' });
        }

        const sql = 'UPDATE users SET psw = COALESCE(NULLIF(?, ""), psw) WHERE user_id = ?';

        pool.query(sql, [hash, user_id], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Hiba az SQL-ben' });
            }

            return res.status(200).json({ message: 'Jelszó frissítve ' });
        });
    });
});


// új termék feltöltése

app.post('/api/upload', authenticateToken, upload.single('product'), (req, res) => {
    const user_id = req.user.id;

    // Ellenőrizzük, hogy admin-e
    const sqlCheckAdmin = 'SELECT is_admin FROM users WHERE user_id = ?';
    pool.query(sqlCheckAdmin, [user_id], (err, result) => {
        if (err) {
            console.error('SQL hiba:', err);
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        if (result.length === 0 || result[0].is_admin !== 1) {
            return res.status(403).json({ error: 'Nincs admin jogosultságod' });
        }

        // Ha admin, folytatódhat a termék feltöltése
        const product = req.file ? req.file.filename : null;
        const price = req.body.price;

        if (!product) {
            return res.status(400).json({ error: 'Válassz ki egy képet' });
        }

        if (!price || isNaN(price)) {
            return res.status(400).json({ error: 'Érvénytelen ár megadva.' });
        }

        const sqlInsertProduct = 'INSERT INTO uploads (user_id, product, price) VALUES (?, ?, ?)';
        pool.query(sqlInsertProduct, [user_id, product, price], (err2, result2) => {
            if (err2) {
                console.error('SQL hiba:', err2);
                return res.status(500).json({ error: 'Hiba az SQL-ben', details: err2.message });
            }

            res.status(201).json({ message: 'Kép feltöltve', upload_id: result2.insertId });
        });
    });
});


// Termékek listázása
app.get('/api/uploads', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM uploads';
    pool.query(sql, (err, results) => {
        if (err) {
            console.error('SQL hiba:', err);
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        res.status(200).json(results);
    });
});



// Összes termék lekérése
app.get('/api/products', (req, res) => {
    const sql = 'SELECT * FROM uploads';

    pool.query(sql, (err, result) => {
        if (err) {
            console.error('Hiba a termékek lekérdezésekor:', err);
            return res.status(500).json({ error: 'Hiba a termékek lekérdezésekor' });
        }

        // Ha sikerült lekérni a termékeket, visszaadjuk őket
        res.status(200).json(result);
    });
});


//kosár
app.post('/api/cart/:upload_id', authenticateToken, (req, res) => {
    const user_id = req.user.id; // Felhasználó azonosítója a tokenből
    const upload_id = req.params.upload_id; // Termék azonosítója a kérésből

    // Ellenőrizzük, hogy az upload_id érvényes szám-e
    if (isNaN(upload_id)) {
        return res.status(400).json({ error: 'Érvénytelen termékazonosító (upload_id)' });
    }

    // Ellenőrizzük, hogy a termék már a kosárban van-e
    const sqlSelect = 'SELECT * FROM cart WHERE upload_id = ? AND user_id = ?';
    pool.query(sqlSelect, [upload_id, user_id], (err, result) => {
        if (err) {
            console.error('SQL Hiba a kosár ellenőrzésekor:', err);
            return res.status(500).json({ error: 'Hiba a kosár ellenőrzése során' });
        }

        if (result.length > 0) {
            // Ha már létezik a termék a kosárban, növeljük a mennyiségét
            const sqlUpdate = 'UPDATE cart SET quantity = quantity + 1 WHERE upload_id = ? AND user_id = ?';
            pool.query(sqlUpdate, [upload_id, user_id], (err, updateResult) => {
                if (err) {
                    console.error('SQL Hiba a termék mennyiségének frissítésekor:', err);
                    return res.status(500).json({ error: 'Hiba a termék mennyiségének frissítése során' });
                }

                return res.status(200).json({ message: 'A termék mennyisége növelve a kosárban' });
            });
        } else {
            // Ha még nincs a kosárban, hozzáadjuk újként
            const sqlInsert = 'INSERT INTO cart (upload_id, user_id, quantity) VALUES (?, ?, 1)';
            pool.query(sqlInsert, [upload_id, user_id], (err, insertResult) => {
                if (err) {
                    console.error('SQL Hiba a termék kosárba helyezésekor:', err);
                    return res.status(500).json({ error: 'Hiba a termék kosárba helyezése során' });
                }

                return res.status(200).json({ message: 'A termék sikeresen kosárba került' });
            });
        }
    });
});


                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    

app.listen(PORT, HOSTNAME, () => {
    console.log(`IP: http://${HOSTNAME}:${PORT}`);
});