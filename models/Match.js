// models/Match.js
const mongoose = require('mongoose');

const matchSchema = new mongoose.Schema({
  roomCode: { type: String, required: true }
});

const Match = mongoose.model('Match', matchSchema);

module.exports = Match;