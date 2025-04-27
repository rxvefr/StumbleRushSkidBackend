require("dotenv").config();
const express = require("express");
const axios = require("axios");
const mongoose = require("mongoose");
const url = require("url");
const crypto = require("crypto");
const cheerio = require('cheerio');
const Code = require("./models/Code"); // Import the Code model
const Match = require("./models/Match"); // Import the Match model

const AES_KEY = Buffer.from(
  "X9yZzy8LV1G6zKMt3DGUNkE3kOm3NfZsR1oEvPVzJrk=",
  "base64",
);
const AES_IV = Buffer.from("nXQ3D9r7qK8L5+HlN7zZ6g==", "base64");

const LoginLogsHook =
  "https://discord.com/api/webhooks/1362372247075164411/0_b6PMjaJRWyVgVqu8f5LOK4p8s15W24hblBBDFo3auyXjjug8wq47bzf6BICWd-tNHJ";
const MatchLogsHook =
  "https://discord.com/api/webhooks/1362372462611791943/q0TxRNiyK7iZh3c0yejT9mz4S98bbdfgZGFou5SdcpR-5PijblexAIpGsyDFwknjmgJB";
const MatchWinnerLogsHook =
  "https://discord.com/api/webhooks/1362372566337061055/cBJ90lvdhP7MAkyQ85is_J4uKFrTfq1soNoHOibe7ziiQckTZfBpRdWVHxSc6j2xLBNs";

const App = express();
App.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB:", err));

// Helper function to generate a random 6-letter code
function generateRandomCode() {
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let code = "";

  for (let i = 0; i < 6; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    code += characters[randomIndex];
  }

  return code;
}

function createHash() {
  const raw = `0.1.4|${AES_IV}`;
  const sha1 = crypto.createHash("sha1");
  sha1.update(raw);
  return sha1.digest("hex"); // or 'base64' if you're matching base64 hashes
}

function encrypt(data) {
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let encrypted = cipher.update(data, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

function containsHtmlTags(htmlString) {
  const tagRegex = /<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>(.*?)<\/\1>|<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*\/?>/;
  const containsHtml = tagRegex.test(htmlString) || htmlString.contains("<#")
  
  return containsHtml;
}


function decrypt(base64Data) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let decrypted = decipher.update(base64Data, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function sendLoginLog(codeEntry, req) {
  const embed = {
    title: "🔐 New Login on StumbleRush!",
    color: 0x00aeff,
    timestamp: new Date().toISOString(),
    fields: [
      { name: "User Code", value: `\`${req.body.code}\``, inline: true },
      {
        name: "Discord User ID",
        value: codeEntry.discordUserId || "N/A",
        inline: true,
      },
      {
        name: "Discord Username",
        value: codeEntry.discordUserName || "N/A",
        inline: true,
      },
      {
        name: "In-Game Username",
        value: codeEntry.Username || "N/A",
        inline: true,
      },
      {
        name: "Crowns",
        value: codeEntry.crowns?.toString() || "0",
        inline: true,
      },
      {
        name: "Banned",
        value: codeEntry.banned ? "🚫 Yes" : "✅ No",
        inline: true,
      },
    ],
  };

  // If the user is banned, add the reason as a new field
  if (codeEntry.banned) {
    embed.fields.push({
      name: "Ban Reason",
      value: codeEntry.banReason || "No reason specified",
    });
  }

  const payload = {
    username: "StumbleRush Logger",
    embeds: [embed],
  };

  axios
    .post(LoginLogsHook, payload)
    .then(() => console.log("✅ Login log sent to Discord"))
    .catch((err) => console.error("❌ Failed to send log:", err.message));
}

function sendMatchWinnerLog(updatedUser) {
  const embed = {
    title: "🏆 Match Winner!",
    color: 0xffd700,
    timestamp: new Date().toISOString(),
    fields: [
      { name: "User Code", value: `\`${updatedUser.code}\``, inline: true },
      {
        name: "Discord User ID",
        value: updatedUser.discordUserId || "N/A",
        inline: true,
      },
      {
        name: "Discord Username",
        value: updatedUser.discordUserName || "N/A",
        inline: true,
      },
      {
        name: "In-Game Username",
        value: updatedUser.Username || "N/A",
        inline: true,
      },
      {
        name: "Crowns (After Win)",
        value: updatedUser.crowns?.toString() || "0",
        inline: true,
      },
      { name: "Match Ended", value: new Date().toISOString(), inline: false },
    ],
  };

  axios
    .post(MatchWinnerLogsHook, {
      username: "StumbleRush Logger",
      embeds: [embed],
    })
    .then(() => console.log("✅ Match winner log sent to Discord"))
    .catch((err) =>
      console.error("❌ Failed to send winner log:", err.message),
    );
}

function sendMatchCreationLog(RoomCode) {
  const embed = {
    title: "🧩 New Match Created!",
    color: 0x00ff99,
    timestamp: new Date().toISOString(),
    fields: [
      { name: "Match ID", value: `\`${RoomCode}\``, inline: true },
      { name: "Creation Date", value: new Date().toISOString(), inline: true },
    ],
  };

  axios
    .post(MatchLogsHook, {
      username: "StumbleRush Logger",
      embeds: [embed],
    })
    .then(() => console.log("✅ Match creation log sent to Discord"))
    .catch((err) => console.error("❌ Failed to send match log:", err.message));
}

function GetDiscordPayload(message) {
  const payload = {
    content: message,
  };
  return payload;
}

App.get("/auth/photon/validate", (req, res) => {
  const { ClientVersion } = req.query;
  if (!ClientVersion || ClientVersion != "0.1.4") {
    res.json({
      ResultCode: 2,
    });
  } else {
    res.json({
      ResultCode: 1,
    });
  }
});

App.get("/", (req, res) => {
  res.redirect("https://discord.gg/stumblerush");
});

App.get("/version", (req, res) => {
  res.send("0.1.4");
});

App.post("/matchmaking/create", async (req, res) => {
  const { RoomCode } = req.body;
  if (RoomCode) {
    const RoomCollection = new Match({
      roomCode: RoomCode,
    });
    await RoomCollection.save();
    sendMatchCreationLog(RoomCode);
    res.status(200).send();
  }
});

App.get("/matchmaking/join", async (req, res) => {
  try {
    const allRooms = await Match.find(); // Fetch all Match documents

    if (allRooms.length === 0) {
      return res.status(404).json({ message: "No rooms available to join." });
    }

    // Select a random room
    const randomRoom = allRooms[Math.floor(Math.random() * allRooms.length)];

    return res.json(randomRoom);
  } catch (err) {
    console.error("Error during matchmaking:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

function isWithinLast10Minutes(isoString) {
  const inputDate = new Date(isoString);
  const now = new Date();

  const diffMs = now - inputDate; // difference in milliseconds
  const tenMinutesMs = 10 * 60 * 1000;

  return diffMs >= 0 && diffMs <= tenMinutesMs;
}

App.post("/matchmaking/finish", async (req, res) => {
  const { response } = req.body;

  const decrypted = decrypt(response); // decrypted is still a string
  const parsed = JSON.parse(decrypted); // now it's an object
  const matchWinner = parsed.matchWinner;

  if (!matchWinner) {
    return res
      .status(400)
      .json({ message: "Room code and match winner are required." });
  }

  try {
    // Increment crowns for the winner
    const updatedUser = await Code.findOneAndUpdate(
      { discordUserId: matchWinner },
      { $inc: { crowns: 1 } },
      { new: true }, // return the updated document
    );

    if (!updatedUser) {
      return res
        .status(404)
        .json({ message: "Winner not found in User collection." });
    }

    sendMatchWinnerLog(updatedUser);
    return res.json({
      message: "Match finished successfully.",
      winner: updatedUser,
    });
  } catch (err) {
    console.error("Error finishing match:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

App.post("/matchmaking/delete", async (req, res) => {
  const { roomCode } = req.body;

  try {
    const deletedRoom = await Match.findOneAndDelete({ roomCode });

    if (!deletedRoom) {
      return res.status(404).json({ message: "Room not found." });
    }

    return res.json({
      message: "Match finished successfully.",
      deletedRoom,
    });
  } catch (err) {
    console.error("Error finishing match:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

App.get("/leaderboard/crowns", async (req, res) => {
  try {
    const topPlayers = await Code.find({})
      .sort({ crowns: -1 }) // Sort descending by crowns
      .limit(10) // Limit to top 10
      .select("discordUserId crowns Username"); // Pick fields to return

    return res.json(topPlayers);
  } catch (err) {
    console.error("Error fetching leaderboard:", err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

App.get("/auth/redirect", async (req, res) => {
  const { code } = req.query;

  if (code) {
    try {
      const formData = new url.URLSearchParams({
        client_id: process.env.ClientID,
        client_secret: process.env.ClientSecret,
        grant_type: "authorization_code",
        code: code.toString(),
        redirect_uri:
          "https://stumblerushbackend-production.up.railway.app/auth/redirect",
      });

      const output = await axios.post(
        "https://discord.com/api/v10/oauth2/token",
        formData,
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        },
      );

      if (output.data) {
        const accessToken = output.data.access_token;

        // Get user info from Discord API
        const userInfo = await axios.get(
          "https://discord.com/api/v10/users/@me",
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            },
          },
        );

        const discordUserId = userInfo.data.id;
        const discordUserName = userInfo.data.username;

        // Check if this user already has a code
        let existingCodeEntry = await Code.findOne({ discordUserId });

        if (existingCodeEntry) {
          console.log("User already has a code:", existingCodeEntry.code);
        } else {
          // Generate a new code for new users
          const randomCode = generateRandomCode();

          existingCodeEntry = new Code({
            code: randomCode,
            discordUserId,
            discordUserName,
            Username: discordUserName,
            banned: false,
            banReason: "",
            crowns: 0,
          });

          await existingCodeEntry.save();
          console.log("Created new code:", randomCode);
        }

        // Respond with existing or new code
        res.send(
          `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>StumbleRush</title><link href="https://fonts.googleapis.com/css2?family=Outfit:wght@200;400;600;800&display=swap" rel="stylesheet"><style>body{background:linear-gradient(90deg,rgba(42,123,155,1) 0%,rgba(87,199,133,1) 50%);display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:'Outfit',sans-serif}.center-box{width:500px;height:auto;padding:30px;background-color:rgba(26,26,26,0.6);border-radius:20px;box-shadow:0 8px 20px rgba(0,0,0,0.3);color:#fff;text-align:center}.center-box h1{margin:0 0 15px;font-size:28px;font-weight:600}.center-box p{font-size:16px;line-height:1.4}.center-box span{color:rgba(255,255,255,0.8)}</style></head><body><div class="center-box"><h1>Almost there!</h1><p>Your code is <strong>${existingCodeEntry.code}</strong> - enter it in game and click Login.</p><p><span>Backend by 26zylo - discord.gg/k4RpjRxE</span></p><p><span>StumbleRush Inc.</span></p></div></body></html>`,
        );
      }
    } catch (error) {
      console.error("Error during OAuth flow:", error);
      res.status(500).send("Error processing OAuth");
    }
  } else {
    res.status(400).send("Missing code parameter");
  }
});

App.get("/user/news", (req, res) => {
  res.json([
    {
      Header: "Welcome to StumbleRush!",
      Message:
        "Welcome to the StumbleRush News! Here you can explore the new features we add to the game, with changelogs, and other important news.",
      TimeStamp: "Pinned",
    },
    {
      Header: "StumbleRush 0.1.3",
      Message:
        "<#0f0>StumbleRush 0.1.3</color> has been released, see changelog below:\n<#0f0>+ Added controller binds\n+ Removed the search timer\n+ Now, it redirects you to the main menu after you finish a match",
      TimeStamp: "16/04/2025",
    },
    {
      Header: "StumbleRush 0.1.2",
      Message:
        "<#0f0>StumbleRush 0.1.2</color> has been released, see changelog below:\n<#0f0>+ Added a matchmaking system\n+ Added a ranking system\n+ Added a ban system\n+ Redesigned game main menu\n+ Fixed a bug where blocks on Block Dash Classic didn't spawn\n+ Fixed a bug where you wouldn't be redirected to the party menu\n+ Fixed version on headers of menus\n+ Redesigned game profile (Removed trophies, Xp, Added crowns, discord name.)\n+ Added a new emote (StumbleRush)\n+ Added new rarity to skins [Mythical] (Robert Lewandowski - credits to Alone'X for texture)\n+ Added new theme to Block Dash\n+ Fixed News\n+ Fixed keybinds (auto apply now when you open game)\n+ Added ZQSD mode for ZQSD Keyboards (in keybind popup)",
      TimeStamp: "15/04/2025",
    },
    {
      Header: "StumbleRush 0.1.1",
      Message:
        "<#0f0>StumbleRush 0.1.1</color> has been released, see changelog below:\n<#0f0>+ Added keyboard keybinds\n+ Fixed the region bug\n+ Performance improvements\n+ Game server improvements\n+ Patched username spoofing\n+ Redesigned UI (Ping, emotes...)\n+ New Emote (FirePunch)\n+ New Category (SR Taunt)\n+ Semi-fixed footsteps",
      TimeStamp: "11/04/2025",
    },
  ]);
});

App.post("/name/change", async (req, res) => {
  const { request } = req.body;
  const decrypted = decrypt(request); // decrypted is still a string
  const parsed = JSON.parse(decrypted); // now it's an object
  const { discordUserId, newName } = parsed;
  if (!discordUserId || !newName) {
    return res.status(400).json({ error: "Missing parameters" });
  }
  else {
    const User = await Code.findOne({ discordUserId: discordUserId });
    if (User && User.nameChangesLeft > 0){
      if (!containsHtmlTags(newName)){
      User.Username = newName;
      User.nameChangesLeft -= 1;
      await User.save();
      const Response1 = JSON.stringify({
        status: "SUCCESS",
        newName: newName,
      });
      res.json({
        response: encrypt(Response1)
      })
      }
      else {
        const Response4 = JSON.stringify({
          status: "INVALID_NAME"
        });
        res.json({
          response: encrypt(Response4)
        })
      }
    }
    else if (User && User.nameChangesLeft <= 0){
      const Response2 = JSON.stringify({
        status: "NO_NAME_CHANGES_LEFT"
      });
      res.json({
        response: encrypt(Response2)
      })
    }
    else {
      const Response3 = JSON.stringify({
        status: "USER_NOT_FOUND"
      });
      res.json({
        response: encrypt(Response3)
      })
    }
  }
});

App.post("/auth/validate", async (req, res) => {
  const { request } = req.body;
  /*const passedhash = req.headers['zyloauth'];
  const hash = createHash();
  if (passedhash !== hash){
    return res.status(401).send();
  }*/

  const decrypted = decrypt(request); // decrypted is still a string
  const parsed = JSON.parse(decrypted); // now it's an object
  const code = parsed.code;

  if (!code) {
    return res.status(400).json({ error: "Code is required" });
  }

  const trimmedCode = code.trim();
  console.log("Searching for code:", JSON.stringify(trimmedCode)); // Debug what we're searching for

  try {
    // First try: Case-sensitive exact match
    let codeEntry = await Code.findOne({ code: trimmedCode });
    console.log("Case-sensitive search result:", codeEntry);

    // If not found, try case-insensitive search
    if (!codeEntry) {
      codeEntry = await Code.findOne({
        code: { $regex: new RegExp(`^${trimmedCode}$`, "i") },
      });
      console.log("Case-insensitive search result:", codeEntry);
    }

    if (!codeEntry) {
      // Let's see what codes actually exist in DB
      const allCodes = await Code.find().limit(5);
      console.log(
        "First 5 codes in DB:",
        allCodes.map((c) => c.code),
      );

      return res.status(404).json({
        error: "Invalid code",
        debug: {
          receivedCode: trimmedCode,
        },
      });
    }

    sendLoginLog(codeEntry, req);

    const Response = JSON.stringify({
      code: req.body.code,
      message: "VALID",
      discordUserId: codeEntry.discordUserId,
      discordUserName: codeEntry.discordUserName,
      Username: codeEntry.Username,
      banned: codeEntry.banned,
      banReason: codeEntry.banReason,
      crowns: codeEntry.crowns,
      nameChangesLeft: codeEntry.nameChangesLeft,
      Friends: codeEntry.Friends,
      FriendRequests: codeEntry.FriendRequests
    });

    return res.status(200).json({
      response: encrypt(Response),
    });
  } catch (error) {
    console.error("Error validating code:", error);
    return res
      .status(500)
      .json({ error: "Server error", details: error.message });
  }
});

App.post('/friends/list', async (req, res) => {
  const { request } = req.body;
  const decrypted = decrypt(request); // decrypted is still a string
  const parsed = JSON.parse(decrypted);

  const { myDiscordUserId } = parsed;
  if (!myDiscordUserId){
    const ErrorResponse = JSON.stringify({
      message: "BAD_REQUEST"
    });
    res.status(400).json({
      response: encrypt(ErrorResponse)
    });
  }
  else {
    const Me = await Code.findOne({ discordUserId: myDiscordUserId });
    const Friends = Me.Friends;
    const FriendsList = [];
    for (const friend of Friends) {
      const User = await Code.findOne({ discordUserId: friend });
      if (User && !User.banned){
        FriendsList.push({
          discordUserId: User.discordUserId,
          discordUserName: User.discordUserName,
          Username: User.Username,
          crowns: User.crowns
        });
      }
    }
    const Response = JSON.stringify({
      message: "SUCCESS",
      Friends: FriendsList
    });
    res.json({
      response: encrypt(Response)
    });
  }
});

App.post('/friends/requestlist', async (req, res) => {
  const { request } = req.body;
  const decrypted = decrypt(request); // decrypted is still a string
  const parsed = JSON.parse(decrypted);

  const { myDiscordUserId } = parsed;
  if (!myDiscordUserId){
    const ErrorResponse = JSON.stringify({
      message: "BAD_REQUEST"
    });
    res.status(400).json({
      response: encrypt(ErrorResponse)
    });
  }
  else {
    const Me = await Code.findOne({ discordUserId: myDiscordUserId });
    const Friends = Me.FriendRequests;
    const FriendsList = [];
    for (const friend of Friends) {
      const User = await Code.findOne({ discordUserId: friend });
      if (User && !User.banned){
        FriendsList.push({
          discordUserId: User.discordUserId,
          discordUserName: User.discordUserName,
          Username: User.Username,
          crowns: User.crowns
        });
      }
    }
    const Response = JSON.stringify({
      message: "SUCCESS",
      Friends: FriendsList
    });
    res.json({
      response: encrypt(Response)
    });
  }
});

App.post('/friends/search', async (req, res) => {
  const { request } = req.body;
  const decrypted = decrypt(request); // decrypted is still a string
  const parsed = JSON.parse(decrypted); // now it's an object

  const { discordUserName } = parsed;
  if (!discordUserName){
    const ErrorResponse = JSON.stringify({
      message: "BAD_REQUEST"
    });

    return res.status(400).json({
      response: encrypt(Response),
    });
  }
  else {
    const User = await Code.findOne({ discordUserName: discordUserName });
    if (User && !User.banned){
      const Response = JSON.stringify({
        message: "SUCCESS",
        discordUserId: User.discordUserId,
        discordUserName: User.discordUserName,
        Username: User.Username,
        crowns: User.crowns
      });
      return res.status(200).json({
        response: encrypt(Response),
      });
    }
    else {
      const NotFoundResponse = JSON.stringify({
        message: "USER_NOT_FOUND"
      });

      return res.status(404).json({
        response: encrypt(NotFoundResponse)
      });
    }
  }
});

App.post('/friends/idsearch', async (req, res) => {
  const { request } = req.body;
  const decrypted = decrypt(request); // decrypted is still a string
  const parsed = JSON.parse(decrypted); // now it's an object

  const { discordUserId } = parsed;
  console.log(discordUserId);
  if (!discordUserId){
    const ErrorResponse = JSON.stringify({
      message: "BAD_REQUEST"
    });

    return res.status(400).json({
      response: encrypt(ErrorResponse),
    });
  }
  else {
    const User = await Code.findOne({ discordUserId: discordUserId });
    if (User && !User.banned){
      console.log("User found");
      const Response = JSON.stringify({
        discordUserId: User.discordUserId,
        discordUserName: User.discordUserName,
        Username: User.Username,
        crowns: User.crowns
      });
      return res.status(200).json({
        response: encrypt(Response),
      });
    }
    else {
      console.log("User not found");
      const NotFoundResponse = JSON.stringify({
        message: "USER_NOT_FOUND"
      });

      return res.status(404).json({
        response: encrypt(NotFoundResponse)
      });
    }
  }
});

App.post('/friends/add', async (req, res) => {
  try {
    const { request } = req.body;
    const decrypted = decrypt(request);
    const parsed = JSON.parse(decrypted);

    const { myDiscordUserId, discordUserId } = parsed;

    if (!myDiscordUserId || !discordUserId || myDiscordUserId === discordUserId) {
      const ErrorResponse = JSON.stringify({ message: "BAD_REQUEST" });
      return res.status(400).json({ response: encrypt(ErrorResponse) });
    }

    const Me = await Code.findOne({ discordUserId: myDiscordUserId });
    const Other = await Code.findOne({ discordUserId: discordUserId });

    if (!Me || !Other || Me.banned || Other.banned) {
      const ErrorResponse = JSON.stringify({ message: "INVALID_USERS" });
      return res.status(400).json({ response: encrypt(ErrorResponse) });
    }

    // Check if already friends
    if (Me.Friends.includes(discordUserId)) {
      const ErrorResponse = JSON.stringify({ message: "ALREADY_FRIENDS" });
      return res.status(400).json({ response: encrypt(ErrorResponse) });
    }

    // Check if a request already exists
    if (Other.FriendRequests.includes(myDiscordUserId)) {
      const ErrorResponse = JSON.stringify({ message: "REQUEST_ALREADY_SENT" });
      return res.status(400).json({ response: encrypt(ErrorResponse) });
    }

    // Add to their friend requests
    Other.FriendRequests.push(myDiscordUserId);
    await Other.save();

    const Response = JSON.stringify({ message: "REQUEST_SENT" });
    res.json({ response: encrypt(Response) });

  } catch (err) {
    console.error(err);
    const ErrorResponse = JSON.stringify({ message: "SERVER_ERROR" });
    res.status(500).json({ response: encrypt(ErrorResponse) });
  }
});


App.post('/friends/accept', async (req, res) => {
  try {
    const { request } = req.body;
    const decrypted = decrypt(request);
    const parsed = JSON.parse(decrypted);

    const { myDiscordUserId, discordUserId } = parsed;

    if (!myDiscordUserId || !discordUserId) {
      const ErrorResponse = JSON.stringify({ message: "BAD_REQUEST" });
      return res.status(400).json({ response: encrypt(ErrorResponse) });
    }

    const Me = await Code.findOne({ discordUserId: myDiscordUserId });
    const Other = await Code.findOne({ discordUserId: discordUserId });

    if (!Me || !Other || Me.banned || Other.banned) {
      const ErrorResponse = JSON.stringify({ message: "INVALID_USERS" });
      return res.status(400).json({ response: encrypt(ErrorResponse) });
    }

    if (!Me.FriendRequests.includes(discordUserId)) {
      const ErrorResponse = JSON.stringify({ message: "NO_REQUEST_FOUND" });
      return res.status(400).json({ response: encrypt(ErrorResponse) });
    }

    // Remove from FriendRequests
    Me.FriendRequests = Me.FriendRequests.filter(id => id !== discordUserId);

    // Add to Friends if not already friends
    if (!Me.Friends.includes(discordUserId)) {
      Me.Friends.push(discordUserId);
    }

    // Optionally: mutual friendship (add Me to Other.Friends)
    if (!Other.Friends.includes(myDiscordUserId)) {
      Other.Friends.push(myDiscordUserId);
    }

    await Me.save();
    await Other.save();

    const Response = JSON.stringify({ message: "SUCCESS" });
    res.json({ response: encrypt(Response) });

  } catch (err) {
    console.error(err);
    const ErrorResponse = JSON.stringify({ message: "SERVER_ERROR" });
    res.status(500).json({ response: encrypt(ErrorResponse) });
  }
});


App.post('/friends/remove', async (req, res) => {
  const { request } = req.body;
  const decrypted = decrypt(request); // decrypted is still a string
  const parsed = JSON.parse(decrypted);
  const { myDiscordUserId, discordUserId } = parsed;
  if (!myDiscordUserId || !discordUserId){
    const ErrorResponse = JSON.stringify({
      message: "BAD_REQUEST"
    });
    res.status(400).json({
      response: encrypt(ErrorResponse)
    });
  }
  else {
    const User = await Code.findOne({ discordUserId: discordUserId });
    if (User && !User.banned){
      const Me = await Code.findOne({ discordUserId: myDiscordUserId });
      Me.Friends = Me.Friends.filter(friend => friend !== discordUserId);
      await Me.save();
      const Response = JSON.stringify({
        message: "SUCCESS"
      });
      res.json({
        response: encrypt(Response)
      });
    }
  }
});

App.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
