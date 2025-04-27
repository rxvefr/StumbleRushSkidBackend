// models/Code.js
const mongoose = require('mongoose');

const codeSchema = new mongoose.Schema({
  code: { type: String, required: true },
  discordUserId: { type: String, required: true },
  discordUserName: { type: String, required: true },
  Username: { type: String, required: true },
  banned: { type: Boolean, required: true },
  banReason: { type: String, required: false },
  crowns: { type: Number, required: true },
  nameChangesLeft: { type: Number, required: true, default: 3 },
  Friends: [String],
  FriendRequests: [String]
});

const Code = mongoose.model('Code', codeSchema);

module.exports = Code;