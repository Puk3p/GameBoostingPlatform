const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const expressLayouts = require('express-ejs-layouts');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const axios = require('axios');

const fs = require('fs').promises;

const Produs = require('./views/models/Produs');

const blocariTemporare = new Map();
const autentificariNereusite = new Map();
const DURATA_BLOCARE_MS = 10 * 1000; // 10 minute
const MAX_INCERCARI = 3;
const INTERVAL_SCURT_MS = 1 * 1000; // 1 minut

const loginLimiter = rateLimit({
    windowMs: 10 * 1000,
    max: 3,
    message: '⏱ Prea multe cereri de la acest IP. Încearcă mai târziu.',
    standardHeaders: true,
    legacyHeaders: false,
});

mongoose.connect('mongodb://localhost:27017/cumparaturi', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Conectare reușită la MongoDB!');
}).catch((err) => {
    console.error('❌ Eroare MongoDB:', err);
});

const app = express();
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret123',
    resave: false,
    saveUninitialized: true
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.use(expressLayouts);

app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    const ip = req.ip;
    const acum = Date.now();

    const blocare = blocariTemporare.get(ip);
    if (blocare && blocare.expiraLa > acum) {
        return res.status(403).send('⛔ IP-ul tău este blocat temporar.');
    }

    next();
});


function verificaAdmin(req, res, next) {
    if (req.session.utilizator && req.session.utilizator.rol === 'ADMIN') {
        next();
    } else {
        res.status(403).send('Acces interzis');
    }
}



app.get('/', (req, res) => {
    const utilizator = req.session.utilizator;
    res.render('home', {
        title: 'Acasă',
        bodyClass: 'index-page',
        utilizator: req.session.utilizator,
        cart: req.session.cart || []
    });
});

app.get('/autentificare', (req, res) => {
    const mesajEroare = req.session.mesajEroare || '';
    req.session.mesajEroare = null;

    const intrebari = [
        { intrebare: 'Câte litere are cuvântul „soare”?', raspuns: '5' },
        { intrebare: 'Care este al doilea număr din șirul: 3, 9, 6?', raspuns: '9' },
        { intrebare: 'Scrie numele culorii: roșu', raspuns: 'roșu' },
        { intrebare: 'Cât face 7 minus 3?', raspuns: '4' },
        { intrebare: 'Care e primul număr impar: 2, 4, 3?', raspuns: '3' },
        { intrebare: 'Ce culoare are frunza?', raspuns: 'verde' },
        { intrebare: 'Scrie cuvântul invers: “eticudorp”', raspuns: 'productie' },
    ];

    const index = Math.floor(Math.random() * intrebari.length);
    const captchaText = intrebari[index].intrebare;
    const captchaRezultat = intrebari[index].raspuns;

    req.session.captchaRezultat = captchaRezultat;

    res.render('autentificare', {
        title: 'Autentificare',
        bodyClass: 'login-page',
        mesajEroare,
        captchaText
    });
});



app.post('/verificare-autentificare', loginLimiter, async (req, res) => {
    const { utilizator, parola, captcha } = req.body;
    const ip = req.ip;
    const acum = Date.now();

    const pattern = /["'=;]/;
    if (pattern.test(utilizator) || pattern.test(parola)) {
        req.session.mesajEroare = '⚠️ Caracter interzis în datele introduse.';
        return res.redirect('/autentificare');
    }

    const captchaCorect = (req.session.captchaRezultat || '').toString().toLowerCase().trim();
    const captchaUser = (captcha || '').toString().toLowerCase().trim();
    if (captchaUser !== captchaCorect) {
        req.session.mesajEroare = '❌ CAPTCHA incorect.';
        return res.redirect('/autentificare');
    }

    const blocare = blocariTemporare.get(ip);
    if (blocare && blocare.expiraLa > acum) {
        return res.status(403).send('⛔ IP-ul tău este blocat temporar. Încearcă mai târziu.');
    }

    const cheie = `${ip}|${utilizator}`;
    let incercari = autentificariNereusite.get(cheie) || [];
    incercari = incercari.filter(ts => acum - ts < INTERVAL_SCURT_MS);

    if (incercari.length >= MAX_INCERCARI) {
        blocariTemporare.set(ip, { expiraLa: acum + DURATA_BLOCARE_MS });
        req.session.mesajEroare = '⛔ Prea multe încercări eșuate. IP blocat 10 minute.';
        return res.redirect('/autentificare');
    }

    try {
        const data = await fs.readFile('utilizatori.json', 'utf8');
        const utilizatori = JSON.parse(data);
        const user = utilizatori.find(u => u.utilizator === utilizator && u.parola === parola);

        if (user) {
            req.session.utilizator = {
                utilizator: user.utilizator,
                nume: user.nume,
                prenume: user.prenume,
                rol: user.rol
            };
            autentificariNereusite.delete(cheie);
            return res.redirect('/');
        } else {
            incercari.push(acum);
            autentificariNereusite.set(cheie, incercari);
            req.session.mesajEroare = '❌ Date de autentificare incorecte!';
            return res.redirect('/autentificare');
        }
    } catch (err) {
        console.error('❌ Eroare la citirea utilizatorilor:', err);
        return res.status(500).send('Eroare internă server.');
    }
});


app.get('/adauga-planuri-boost', async (req, res) => {
    try {
        const produse = [
            {
                nume: "Starter Boost",
                descriere: "Boost rapid până la Silver",
                pret: 12,
                categorie: "boost"
            },
            {
                nume: "Elite Boost",
                descriere: "Boost până la Diamond + DuoQ",
                pret: 39,
                categorie: "boost"
            },
            {
                nume: "Legend Boost",
                descriere: "Boost până la Top Rank + Coaching 1:1",
                pret: 79,
                categorie: "boost"
            }
        ];

        const rezultate = await Produs.insertMany(produse);
        res.send(`✅ Produse adăugate:<br>${rezultate.map(p => `${p.nume} - ${p._id}`).join('<br>')}`);
    } catch (err) {
        console.error('❌ Eroare la inserare:', err);
        res.status(500).send('Eroare la inserare planuri boost.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get('/chestionar', async (req, res) => {
    const data = await fs.readFile('intrebari.json', 'utf8');
    const intrebari = JSON.parse(data);
    res.render('chestionar', {
        title: 'Chestionar Gaming',
        bodyClass: 'quiz-page',
        intrebari,
        cart: req.session.cart || []
    });
});

app.post('/rezultat-chestionar', async (req, res) => {
    const data = await fs.readFile('intrebari.json', 'utf8');
    const intrebari = JSON.parse(data);

    let scor = 0;
    intrebari.forEach((q) => {
        if (req.body[q.id] === q.corect) {
            scor++;
        }
    });

    res.render('rezultat-chestionar', {
        title: 'Rezultatul Tău',
        bodyClass: 'quiz-page',
        scor,
        total: intrebari.length
    });
});

app.get('/portfolio-details', (req, res) => {
    res.render('portfolio-details', {
        title: 'Portfolio Details',
        bodyClass: 'portfolio-details-page'
    });
});

app.get('/service-details', async (req, res) => {
    try {
        const produse = await Produs.find();
        const utilizator = req.session.utilizator;
        const cart = req.session.cart || [];
        res.render('service-details', {
            title: 'Detalii Servicii',
            utilizator,
            produse,
            cart
        });
    } catch (err) {
        console.error('Eroare la interogare BD:', err);
        res.status(500).send('Eroare server');
    }
});

app.get('/admin', (req, res) => {
    const utilizator = req.session.utilizator;

    if (!utilizator || utilizator.rol !== 'ADMIN') {
        return res.status(403).send('⛔ Acces interzis');
    }

    res.render('admin', {
        title: 'Panou Administrator',
        bodyClass: 'admin-page',
        utilizator,
        cart: req.session.cart || [],
        mesajSucces: null,
        mesajEroare: null
    });
});


app.post('/admin/adauga-produs', async (req, res) => {
    const utilizator = req.session.utilizator;

    if (!utilizator || utilizator.rol !== 'ADMIN') {
        return res.status(403).send('⛔ Acces interzis');
    }

    const { nume, descriere, pret, categorie } = req.body;

    try {
        const exista = await Produs.findOne({ nume: nume });

        if (exista) {
            return res.render('admin', {
                title: 'Panou Administrator',
                bodyClass: 'admin-page',
                utilizator,
                cart: req.session.cart || [],
                mesajSucces: null,
                mesajEroare: `❌ Produsul "${nume}" există deja în baza de date.`
            });
        }

        await Produs.create({ nume, descriere, pret, categorie });

        res.render('admin', {
            title: 'Panou Administrator',
            bodyClass: 'admin-page',
            utilizator,
            cart: req.session.cart || [],
            mesajSucces: '✅ Produs adăugat cu succes!',
            mesajEroare: null
        });
    } catch (err) {
        console.error("❌ Eroare la adăugare produs:", err);
        res.render('admin', {
            title: 'Panou Administrator',
            bodyClass: 'admin-page',
            utilizator,
            cart: req.session.cart || [],
            mesajSucces: null,
            mesajEroare: '❌ Eroare la adăugare produs.'
        });
    }
});



app.get('/creare-bd', async (req, res) => {
    try {
        await Produs.deleteMany();
        console.log('✅ BD pregătită (colecția curățată)');
        res.redirect('/');
    } catch (err) {
        console.error('❌ Eroare creare BD:', err);
        res.status(500).send('Eroare la creare BD');
    }
});

app.get('/inserare-produse', async (req, res) => {
    try {
        await Produs.insertMany([
            {
                nume: "Starter Boost",
                descriere: "Rank Bronze to Silver",
                pret: 14.99,
                categorie: "boost"
            },
            {
                nume: "Elite Boost",
                descriere: "Rank Platinum to Diamond",
                pret: 49.99,
                categorie: "boost"
            },
            {
                nume: "Custom Boost",
                descriere: "Orice rank la cerere",
                pret: 0,
                categorie: "boost"
            }
        ]);
        res.send('✅ Produse adăugate cu succes!');
    } catch (err) {
        console.error("Eroare inserare produse:", err);
        res.status(500).send('❌ Eroare la inserare produse.');
    }
});

app.get('/cos', (req, res) => {
    const cart = req.session.cart || [];
    const utilizator = req.session.utilizator;
    res.render('vizualizare-cos', {
        title: 'Coșul Meu',
        bodyClass: 'cart-page',
        cart,
        utilizator
    });
});

app.get('/cart/add', async (req, res) => {
    const id = req.query.productId;
    const produs = await Produs.findById(id);
    if (!req.session.cart) req.session.cart = [];

    const exista = req.session.cart.find(p => p._id.toString() === id);
    if (!exista) {
        req.session.cart.push(produs);
    }

    res.redirect('/cos');
});

app.get('/cart/clear', (req, res) => {
    req.session.cart = [];
    res.redirect('/cos');
});


app.get('/cart/remove', (req, res) => {
    const id = req.query.id;
    req.session.cart = (req.session.cart || []).filter(p => p._id != id);
    res.redirect('/cos');
});

app.use((req, res) => {
    const ip = req.ip;
    const acum = Date.now();

    const ignora = /\.(ico|png|jpg|jpeg|gif|svg|css|js|map)$/i.test(req.path);
    if (ignora) {
        return res.status(404).send('Resursă lipsă (statică)');
    }

    const info = blocariTemporare.get(ip) || { count: 0 };
    info.count++;

    if (info.count >= MAX_INCERCARI) {
        if (!info.expiraLa || acum > info.expiraLa) {
            info.expiraLa = acum + DURATA_BLOCARE_MS;
            console.warn(`🚫 IP ${ip} blocat pentru ${DURATA_BLOCARE_MS / 1000}s`);
        }
    }

    blocariTemporare.set(ip, info);
    res.status(404).send('<h1>404 - Pagina nu există</h1><p>Încercare invalidă</p>');
});



setInterval(() => {
    const acum = Date.now();
    for (const [ip, info] of blocariTemporare.entries()) {
        if (info.expiraLa && acum > info.expiraLa) {
            blocariTemporare.delete(ip);
        }
    }
}, 60 * 1000);


const PORT = process.env.PORT || 6789;
app.listen(PORT, () => {
    console.log(`🚀 Server pornit pe http://localhost:${PORT}`);
});
