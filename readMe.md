## Áttekintés
Ez a dokumentáció a Revyn webshop backend API-ját írja le, amely Express.js keretrendszerrel készült, MySQL adatbázist használ, és RESTful végpontokat biztosít a felhasználói hitelesítéstől a termékkezelésig.

## Főbb jellemzők
- Felhasználókezelés (regisztráció, bejelentkezés, profil szerkesztés)
- Termékkezelés (feltöltés, keresés, módosítás, törlés)
- Rendeléskezelés (rendelés rögzítése, rendelések listázása)
- Adminisztrációs funkciók (csak admin jogosultsággal)
- Képfeltöltés támogatása

## Technológiai verem
- Backend: Node.js, Express.js
- Adatbázis: MySQL
- Hitelesítés: JWT (JSON Web Token)
- Fájlkezelés: Multer
- Biztonság: bcrypt jelszótitkosítás, rate limiting
    - Egyéb függőségek:
        - dotenv - környezeti változók kezelése
        - validator - bemeneti validáció
        - cors - Cross-Origin Resource Sharing
        - cookie-parser - cookie kezelés


## API Végpontok

### Felhasználókezelés
   1. Regisztráció
        - POST /api/register
        - Szükséges adatok: email, firstname, lastname, psw
    
   2. Bejelentkezés
        - POST /api/login
        - Szükséges adatok: email, psw

  3. Kijelentkezés
        - POST /api/logout
        - Hitelesítés szükséges

   4. Profil szerkesztése
        - Név módosítása: PUT /api/editProfileName
        - Profilkép módosítása: PUT /api/editProfilePicture
        - Jelszó módosítása: PUT /api/editProfilePsw
        - Mindegyik végponthoz hitelesítés szükséges


## Termékkezelés
1. Termékek listázása
    - GET /api/products
2. Termék keresése
    - GET /api/products/:search
3. Termék részletei
    - GET /api/product/:product_id
    - Hitelesítés szükséges
4. Termék feltöltése (csak admin)
    - POST /api/upload
    - Szükséges adatok: product_name, product_price, product_stock, product_description, product_image (fájl)

5. Termék módosítása (csak admin)
    - PUT /api/products/:product_id

6. Termék törlése (csak admin)
    - DELETE /api/products/:product_id

## Rendeléskezelés
1. Rendelés létrehozása
    - POST /api/orders/
    - Szükséges adatok: first_name, last_name, address, phone_number, card_number, expiration_date, name_on_card, cart (tömb)
    - Hitelesítés szükséges

2. Rendelések listázása
    - GET /api/orders
    - Hitelesítés szükséges

## Admin funkciók
- Az admin funkciókhoz (/api/upload, /api/products/:product_id, /api/admin/products) mindkét jogosultság szükséges:
    - Érvényes JWT token
    - Admin jogosultság (users.is_admin = 1)


## Adatbázis
- orders
    - order_id
    - user_id
    - total
    - order_date
    - first_name
    - last_name
    - address
    - phone_number
    - card_number
    - expiration_date
    - name_on_card
- order_items
    - order_item_id
    - order_id
    - product_id
    - quantity
    - price
- products
    - product_id
    - product_name
    - product_price
    - product_stock
    - product_image
    - product_description
- users
    - user_id
    - email
    - firstname
    - lastname
    - user_picture
    - psw
    - is_admin

![táblázat](https://snipboard.io/v6f2kT.jpg)


## Használ package-ek
- bcrypt
- bcryptjs
- cars
- cookie-parser
- cors
- dotenv
- express
- express-rate-limit
- fs
- jsonwebtoken
- multer
- mysql
- mysql2
- path
- validator
- nodemon


```javascript
"dependencies": {
    "bcrypt": "^5.1.1",
    "bcryptjs": "^2.4.3",
    "cars": "^1.1.6",
    "cookie-parser": "^1.4.7",
    "cors": "^2.8.5",
    "dotenv": "^16.4.7",
    "express": "^4.21.2",
    "express-rate-limit": "^7.5.0",
    "fs": "^0.0.1-security",
    "jsonwebtoken": "^9.0.2",
    "multer": "^1.4.5-lts.1",
    "mysql": "^2.18.1",
    "mysql2": "^3.12.0",
    "path": "^0.12.7",
    "validator": "^13.12.0"
  },
  "devDependencies": {
    "nodemon": "^3.1.9"
  }
```

## Biztonsági megfontolások
- Minden jelszó bcrypt-el van titkosítva
- JWT token használata hitelesítéshez
- Rate limiting beállítva (jelenleg kikapcsolva)
- CORS korlátozva a revyn.netlify.app domainre
- HTTP-only, secure cookie-k használata

## Linkek
- [Deepseek](https://chat.deepseek.com)
- [Github](https://github.com/petra1226/backendd) 
- [W3schools](https://www.w3schools.com)
- [Postman](https://www.postman.com)
- [phpMyAdmin](http://localhost/phpmyadmin/index.php)
