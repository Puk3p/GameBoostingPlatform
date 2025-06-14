const mongoose = require('mongoose');

const produsSchema = new mongoose.Schema({
    nume: String,
    descriere: String,
    pret: Number,
    categorie: String
});


module.exports = mongoose.model('Produs', produsSchema);
