const express = require('express')
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const mysql = require('mysql2/promise');
const validator = require('validator');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { error } = require('console');

const app = express();

dotenv.config();
const PORT = process.env.PORT;
const HOSTNAME = process.env.HOSTNAME;

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
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
    console.log(token);

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
    const user_id = req.user.id;
    console.log(user_id);

    const sqlCheckAdmin = 'SELECT is_admin FROM users WHERE user_id = ?';
    pool.query(sqlCheckAdmin, [user_id], (err, result) => {
        if (err) {
            console.error('SQL hiba:', err);
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        if (result.length === 0 || result[0].is_admin !== 1) {
            return res.status(403).json({ error: 'Nincs admin jogosultságod' });
        }

        next();
    });
}


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
//app.use(limiter);
app.use(cookieParser());
app.use(cors({
    origin: 'https://revyn.netlify.app',
    credentials: true,

}));

app.use('/uploads', authenticateToken, express.static(path.join(__dirname, 'uploads')));

// Regisztráció
app.post('/api/register', (req, res) => {
    const { email, firstname, lastname, psw } = req.body;
    const errors = [];
    console.log(email, firstname, lastname, psw);
    console.log(errors);

    if (!validator.isEmail(email)) {
        errors.push({ error: 'Nem valós email' });
    }

    if (validator.isEmpty(firstname)) {
        errors.push({ error: 'Töltsd ki a keresztnevet' });
    }

    if (validator.isEmpty(lastname)) {
        errors.push({ error: 'Töltsd ki a vezetéknevet' });
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

        const sql = 'INSERT INTO users (email, firstname, lastname, psw, user_picture) VALUES (?, ?, ?, ?, ?)';
        pool.query(sql, [email, firstname, lastname, hash, 'default.png'], (err2, result) => {
            if (err2) {
                return res.status(500).json({ error: 'Az email már foglalt' });
            }

            res.status(201).json({ message: 'Sikeres regisztráció' });
        });
    });
});

// login
app.post('/api/login', (req, res) => {
    const { email, psw } = req.body;
    const errors = [];
    console.log(email, psw);

    if (!validator.isEmail(email)) {
        errors.push({ error: 'Add meg az email címet ' });
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
            console.log(err);
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        if (result.length === 0) {
            return res.status(404).json({ error: 'A felhasználó nem található' });
        }

        const user = result[0];
        const is_admin = user.is_admin;
        console.log(`Admin-e: ${is_admin}`);

        console.log(user);
        bcrypt.compare(psw, user.psw, (err, isMatch) => {
            if (isMatch) {
                const token = jwt.sign({ id: user.user_id }, JWT_SECRET, { expiresIn: '1y' });
                console.log(token);

                res.cookie('auth_token', token, {
                    httpOnly: true,
                    secure: true,
                    sameSite: 'none',
                    maxAge: 1000 * 60 * 60 * 24 * 10
                });

                // Ellenőrizzük, hogy a felhasználó admin-e
                if (is_admin === 1) {
                    return res.status(200).json({ message: 'Sikeres bejelentkezés adminként', is_admin });
                } else {
                    return res.status(200).json({ message: 'Sikeres bejelentkezés', is_admin });
                }
            } else {
                return res.status(401).json({ error: 'Rossz a jelszó' });
            }
        });
    });
});

// Termék keresése
app.get('/api/products/:search', (req, res) => {
    const { search } = req.params;

    const keres = `%${search}%`;
    const sql = 'SELECT * FROM products WHERE product_name LIKE ? OR product_price LIKE ? OR product_description LIKE ?';

    pool.query(sql, [keres, keres, keres], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send({ error: 'Adatbázis hiba' });
        }

        res.send(result);
    });
});

// Teszt végpont
app.get('/api/teszt', authenticateToken, (req, res) => {
    const user = req.user;
    return res.status(200).json({ message: 'bent vagy ', user });
});

// Profil név szerkesztése
app.put('/api/editProfileName', authenticateToken, (req, res) => {
    console.log('Token info:', req.user);  // Ellenőrizd, hogy megjelenik-e a token
    const { firstname, lastname } = req.body;
    const user_id = req.user.id;

    // Ellenőrizzük, hogy legalább az egyik mező (firstname vagy lastname) meg van-e adva
    if (!firstname && !lastname) {
        return res.status(400).json({ error: 'Legalább egy névmezőt meg kell adni' });
    }

    // SQL lekérdezés frissítése firstname és lastname mezőkre
    const sql = `
        UPDATE users 
        SET 
            firstname = COALESCE(NULLIF(?, ""), firstname),
            lastname = COALESCE(NULLIF(?, ""), lastname)
        WHERE user_id = ?
    `;

    pool.query(sql, [firstname, lastname, user_id], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Hiba az SQL-ben' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Felhasználó nem található' });
        }

        return res.status(200).json({ message: 'Név frissítve' });
    });
});


// Profilkép módosítása
app.put('/api/editProfilePicture', authenticateToken, upload.single('profile_picture'), (req, res) => {
    const user_id = req.user.id;
    const profile_picture = req.file ? req.file.filename : null; // Fájl neve
    console.log(user_id);
    console.log(profile_picture);



    // Ellenőrizzük, hogy van-e fájl
    if (!profile_picture) {
        return res.status(400).json({ error: 'Nincs fájl feltöltve' });
    }

    // SQL lekérdezés a profilkép frissítéséhez
    const sql = 'UPDATE users SET user_picture = ? WHERE user_id = ?';
    pool.query(sql, [profile_picture, user_id], (err, result) => {
        if (err) {
            console.error('SQL hiba:', err);
            return res.status(500).json({ error: 'Hiba a profilkép frissítésekor' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Felhasználó nem található' });
        }

        return res.status(200).json({ message: 'Profilkép sikeresen frissítve', profile_picture });
    });
});




// Jelszó módosítása
app.put('/api/editProfilePsw', authenticateToken, (req, res) => {
    const psw = req.body.psw;
    const user_id = req.user.id;
    console.log(psw);
    console.log(user_id);



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


// Termék feltöltése (csak adminok számára)
app.post('/api/upload', authenticateToken, authorizeAdmin, upload.single('product_image'), (req, res) => {
    const { product_name, product_price, product_stock, product_description } = req.body;
    const product_image = req.file ? req.file.filename : null;

    // Validáció
    if (!product_name || !product_price || !product_stock || !product_image || !product_description) {
        return res.status(400).json({ error: 'Minden mezőt ki kell tölteni' });
    }

    if (isNaN(product_price) || isNaN(product_stock) || product_stock < 0) {
        return res.status(400).json({ error: 'Érvénytelen ár vagy készlet' });
    }

    // Termék beszúrása az adatbázisba
    const sqlInsertProduct = 'INSERT INTO products (product_name, product_image, product_price, product_stock, product_description) VALUES (?, ?, ?, ?, ?)';
    pool.query(sqlInsertProduct, [product_name, product_image, product_price, product_stock, product_description], (err, result) => {
        if (err) {
            console.error('Hiba az SQL-ben:', err);
            return res.status(500).json({ error: 'Hiba az SQL-ben', details: err.message });
        }

        res.status(201).json({ message: 'Termék feltöltve', product_id: result.insertId });
    });
});

// Termékek listázása
app.get('/api/products', (req, res) => {
    const sql = 'SELECT * FROM products';

    pool.query(sql, (err, result) => {
        if (err) {
            console.error('Hiba a termékek lekérdezésekor:', err);
            return res.status(500).json({ error: 'Hiba a termékek lekérdezésekor' });
        }

        res.status(200).json(result);
    });
});

/*
// Kosárba helyezés
app.post('/api/cart/:product_id', authenticateToken, (req, res) => {
    const user_id = req.user.id;
    const product_id = req.params.product_id;

    if (isNaN(product_id)) {
        return res.status(400).json({ error: 'Érvénytelen termékazonosító' });
    }

    // Ellenőrizzük, hogy a felhasználónak van-e már kosara
    const sqlCheckCart = 'SELECT cart_id FROM cart WHERE user_id = ?';
    pool.query(sqlCheckCart, [user_id], (err, cartResult) => {
        if (err) {
            console.error('SQL Hiba a kosár ellenőrzésekor:', err);
            return res.status(500).json({ error: 'Hiba a kosár ellenőrzése során' });
        }

        let cart_id;
        if (cartResult.length === 0) {
            // Ha nincs kosara, létrehozunk egy újat
            const sqlCreateCart = 'INSERT INTO cart (user_id) VALUES (?)';
            pool.query(sqlCreateCart, [user_id], (err, createResult) => {
                if (err) {
                    console.error('SQL Hiba a kosár létrehozásakor:', err);
                    return res.status(500).json({ error: 'Hiba a kosár létrehozása során' });
                }
                cart_id = createResult.insertId;
                addToCart(cart_id, product_id, res);
            });
        } else {
            // Ha van már kosara, azt használjuk
            cart_id = cartResult[0].cart_id;
            addToCart(cart_id, product_id, res);
        }
    });
});

// Segédfüggvény a termék kosárba helyezéséhez
function addToCart(cart_id, product_id, res) {
    // Ellenőrizzük, hogy a termék már benne van-e a kosárban
    const sqlCheckItem = 'SELECT * FROM cart_items WHERE cart_id = ? AND product_id = ?';
    pool.query(sqlCheckItem, [cart_id, product_id], (err, itemResult) => {
        if (err) {
            console.error('SQL Hiba a termék ellenőrzésekor:', err);
            return res.status(500).json({ error: 'Hiba a termék ellenőrzése során' });
        }

        if (itemResult.length > 0) {
            // Ha már benne van, növeljük a mennyiséget
            const sqlUpdateQuantity = 'UPDATE cart_items SET quantity = quantity + 1 WHERE cart_id = ? AND product_id = ?';
            pool.query(sqlUpdateQuantity, [cart_id, product_id], (err, updateResult) => {
                if (err) {
                    console.error('SQL Hiba a mennyiség frissítésekor:', err);
                    return res.status(500).json({ error: 'Hiba a mennyiség frissítése során' });
                }
                return res.status(200).json({ message: 'A termék mennyisége növelve a kosárban' });
            });
        } else {
            // Ha nincs benne, beszúrjuk az új terméket
            const sqlInsertItem = 'INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (?, ?, 1)';
            pool.query(sqlInsertItem, [cart_id, product_id], (err, insertResult) => {
                if (err) {
                    console.error('SQL Hiba a termék beszúrásakor:', err);
                    return res.status(500).json({ error: 'Hiba a termék beszúrása során' });
                }
                return res.status(200).json({ message: 'A termék sikeresen kosárba került' });
            });
        }
    });
}
*/

//rendelés rögzítése
app.post('/api/orders/', authenticateToken, async (req, res) => {
    const user_id = req.user.id;
    const { first_name, last_name, address, phone_number, card_number, expiration_date, name_on_card, cart } = req.body;

    if (!Array.isArray(cart) || cart.length === 0) {
        return res.status(400).json({ error: "A kosár tartalma hiányzik vagy nem megfelelő formátumú." });
    }

    let connection = null;

    try {
        connection = await pool.getConnection();
        if (!connection) {
            throw new Error("Nem sikerült adatbáziskapcsolatot létesíteni.");
        }

        await connection.beginTransaction();

        // 🏷️ **1. Lépés: Rendelés teljes összegének kiszámítása**
        let total = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);

        const orderValues = [
            user_id || null,
            total || 0.00,
            first_name || null,
            last_name || null,
            address || null,
            phone_number || null,
            card_number || null,
            expiration_date || null,
            name_on_card || null
        ];

        // 📝 **2. Lépés: Rendelés beszúrása az `orders` táblába**
        const [orderResult] = await connection.execute(
            `INSERT INTO orders (user_id, total, first_name, last_name, address, phone_number, card_number, expiration_date, name_on_card)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            orderValues
        );
        const order_id = orderResult.insertId;

        // 🔄 **3. Lépés: Product ID-k lekérése a nevek alapján**
        let first_order_item_id = null;

        for (let item of cart) {
            // 🔍 **Lekérjük az azonosítót a termék nevéből**
            const [product] = await connection.execute(
                `SELECT product_id FROM products WHERE product_name = ? LIMIT 1`,
                [item.name]
            );

            if (product.length === 0) {
                throw new Error(`Nem található termék a következő névvel: ${item.name}`);
            }

            const product_id = product[0].product_id;

            // 🛒 **4. Lépés: Termékek beszúrása az `order_items` táblába**
            const [orderItemResult] = await connection.execute(
                `INSERT INTO order_items (product_id, quantity, price) VALUES (?, ?, ?)`,
                [product_id, item.quantity, item.price]
            );
            const order_item_id = orderItemResult.insertId;

            if (!first_order_item_id) {
                first_order_item_id = order_item_id;
            }
        }

        // 🔗 **5. Lépés: Az orders táblában frissítjük az order_item_id mezőt**
        if (first_order_item_id) {
            await connection.execute(
                `UPDATE orders SET order_item_id = ? WHERE order_id = ?`,
                [first_order_item_id, order_id]
            );
        }

        await connection.commit();
        res.json({ message: "Rendelés sikeresen rögzítve!", order_id, total });

    } catch (error) {
        if (connection) {
            await connection.rollback();
        }
        console.error("Hiba a rendelés rögzítésénél:", error);

        if (!res.headersSent) {
            res.status(500).json({ error: "Hiba történt a rendelés rögzítése közben." });
        }

    } finally {
        if (connection) connection.release();
    }
});

app.listen(PORT, () => {
    console.log(`IP: https://${HOSTNAME}  || PORT: ${PORT}`);
});