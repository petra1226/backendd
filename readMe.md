# Áttekintés
Ez a dokumentáció a Revyn webshop backend API-ját írja le, amely Express.js keretrendszerrel készült, MySQL adatbázist használ, és RESTful végpontokat biztosít a felhasználói hitelesítéstől a termékkezelésig.

# Főbb jellemzők
- Felhasználókezelés (regisztráció, bejelentkezés, profil szerkesztés)
- Termékkezelés (feltöltés, keresés, módosítás, törlés)
- Rendeléskezelés (rendelés rögzítése, rendelések listázása)
- Adminisztrációs funkciók (csak admin jogosultsággal)
- Képfeltöltés támogatása

# Technológiai verem
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


# API Végpontok

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


# Termékkezelés
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

# Rendeléskezelés
1. Rendelés létrehozása
    - POST /api/orders/
    - Szükséges adatok: first_name, last_name, address, phone_number, card_number, expiration_date, name_on_card, cart (tömb)
    - Hitelesítés szükséges

2. Rendelések listázása
    - GET /api/orders
    - Hitelesítés szükséges

# Admin funkciók
- Az admin funkciókhoz (/api/upload, /api/products/:product_id, /api/admin/products) mindkét jogosultság szükséges:
    1. Érvényes JWT token
    2. Admin jogosultság (users.is_admin = 1)


https://documenter.getpostman.com/view/38557569/2sB2cVfhfh