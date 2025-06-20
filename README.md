
# 🎮 PukHub – Platformă de Boosting pentru Gamers Competitivi

**PukHub** este o aplicație web dezvoltată pentru a oferi servicii de boosting, coaching și consultanță în jocuri competitive precum **Valorant**, **League of Legends**, **Minecraft**, **CS2** și altele. Proiect realizat ca temă pentru disciplina **Programare Web**.

## 🔧 Tehnologii Utilizate
- **Frontend:** HTML5, CSS3, Bootstrap, EJS (Embedded JavaScript)
- **Backend:** Node.js, Express.js
- **Bază de date:** MongoDB + Mongoose
- **Design & Icons:** Bootstrap Icons, AOS, Swiper.js
- **Altele:** Express Sessions, Validare Formular, Captcha, Middleware-uri custom

## 📂 Structura Proiectului

```
├── models/
│   └── produs.js          # Modelul MongoDB pentru produse
├── views/
│   ├── service-details.ejs
│   ├── autentificare.ejs
│   ├── admin.ejs
│   └── partials/
├── public/
│   ├── assets/img/
│   ├── assets/css/
│   └── assets/js/
├── routes/
│   └── siteRoutes.js      # Toate rutele site-ului
├── app.js                 # Fișierul principal al aplicației Express
└── README.md              # Acest fișier
```

## ⚙️ Funcționalități

- ✅ Autentificare utilizator cu validare și captcha
- 🛒 Coș de cumpărături dinamic cu preview în navbar
- 🧩 Panou de administrare pentru adăugare produse
- 📊 Chestionar de gaming cu verificare răspunsuri
- 🗃️ Salvare date în MongoDB
- 💬 Testimoniale reale + sistem de rating
- 📍 Pagină Contact integrată cu Google Maps

## 👤 Echipa

- **George Lupu** – Team Lead & Boost Strategist  
- **Delia Bărbuță** – Content & Product Strategy  
- **Adrian Alexandrescu** – Backend & Infra  
- **Adelina Hrițcu** – Community Manager  

## 🚀 Instalare locală

1. Clonează proiectul:
   ```bash
   git clone https://github.com/Puk3p/GameBoostingPlatform.git
   cd GameBoostingPlatform
   ```

2. Instalează dependențele:
   ```bash
   npm install
   ```

3. Creează fișierul `.env`:
   ```env
   PORT=3000
   MONGO_URI=mongodb://localhost:27017/pukhub
   SESSION_SECRET=supersecret
   ```

4. Rulează aplicația:
   ```bash
   npm start
   ```

Accesează [http://localhost:3000](http://localhost:3000)

## 📸 Capturi din aplicație

![Homepage](./public/assets/img/screenshot-home.png)
![Panou Admin](./public/assets/img/screenshot-admin.png)

## 📜 Licență

Acest proiect este realizat ca temă de facultate și este destinat uzului educațional.

---

> 💡 Pentru orice întrebare legată de proiect, trimite un mesaj pe [Discord](https://discord.gg/boosting) sau contactează-mă la `gheorghe.lupu2@student.tuiasi.ro`.
