const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'chiave_segreta_molto_sicura';
const MONGO_URI = process.env.MONGO_URI;

app.use(cors());
app.use(express.json());

// Connessione al database MongoDB reale
mongoose.connect(MONGO_URI)
  .then(() => console.log('Database MongoDB connesso con successo'))
  .catch(err => console.error('Errore di connessione a MongoDB:', err));

// Schema e Modello Utente
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: 'user' },
  status: { type: String, default: 'approved' },
  wallet: {
    deposit: { type: Number, default: 0 },
    earnings: { type: Number, default: 0 }
  },
  investments: { type: Array, default: [] },
  transactions: { type: Array, default: [] },
  depositRequests: { type: Array, default: [] },
  withdrawalRequests: { type: Array, default: [] },
  preferences: { type: Object, default: { language: 'it', theme: 'dark' } },
  withdrawalWallet: { type: Object, default: null },
  h9Points: { type: Number, default: 0 },
  bonusSpins: { type: Number, default: 0 },
  pointHistory: { type: Array, default: [] },
  referrals: { type: Array, default: [] },
  activeBonuses: { type: Array, default: [] },
  rewardRedemptions: { type: Array, default: [] },
  dailyPrizes: { type: Array, default: [] },
  referralCode: { type: String },
  lastDailyPrizeDate: { type: String, default: null },
  revision: { type: Number, default: 1 },
  createdAt: { type: Number, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Middleware di autenticazione Bearer Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token mancante' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token non valido o scaduto' });
    req.user = user;
    next();
  });
}

// 1. Registrazione account reale
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Campi obbligatori mancanti' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email già registrata' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    
    const count = await User.countDocuments();
    const role = count === 0 ? 'admin' : 'user';

    const newUser = new User({
      username,
      email,
      passwordHash,
      role,
      referralCode: Math.random().toString(36).substring(2, 9).toUpperCase()
    });

    await newUser.save();
    const token = jwt.sign({ id: newUser._id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, account: newUser });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 2. Login reale
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Credenziali non valide' });

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(400).json({ error: 'Credenziali non valide' });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 3. Logout
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ ok: true });
});

// 4. Dati Conto Corrente
app.get('/api/account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Account non trovato' });
    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 5. Aggiornamento Conto / Preferenze
app.put('/api/account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Account non trovato' });

    Object.assign(user, req.body);
    user.revision = (user.revision || 1) + 1;
    await user.save();

    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 6. Gestione Admin - Elenco Account
app.get('/api/admin/accounts', authenticateToken, async (req, res) => {
  try {
    const admin = await User.findById(req.user.id);
    if (!admin || admin.role !== 'admin') return res.status(403).json({ error: 'Non autorizzato' });

    const accounts = await User.find({});
    res.json({ accounts });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 7. Depositi Reali
app.post('/api/deposits', authenticateToken, async (req, res) => {
  try {
    const { amount, network, txHash } = req.body;
    const user = await User.findById(req.user.id);

    const depositReq = {
      id: Date.now().toString(),
      amount,
      network,
      txHash,
      status: 'pending',
      createdAt: Date.now()
    };

    user.depositRequests.unshift(depositReq);
    await user.save();
    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 8. Prelievi Reali
app.post('/api/withdrawals', authenticateToken, async (req, res) => {
  try {
    const { amount, network, address } = req.body;
    const user = await User.findById(req.user.id);

    if (user.wallet.earnings < amount) {
      return res.status(400).json({ error: 'Saldo guadagni insufficiente' });
    }

    user.wallet.earnings -= Number(amount);
    const withdrawalReq = {
      id: Date.now().toString(),
      amount,
      network,
      address,
      status: 'pending',
      createdAt: Date.now()
    };

    user.withdrawalRequests.unshift(withdrawalReq);
    await user.save();
    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

// 9. Creazione Investimento Reale
app.post('/api/investments', authenticateToken, async (req, res) => {
  try {
    const { amount, planId } = req.body;
    const user = await User.findById(req.user.id);

    if (user.wallet.deposit < amount) {
      return res.status(400).json({ error: 'Saldo deposito insufficiente' });
    }

    user.wallet.deposit -= Number(amount);
    const investment = {
      id: Date.now().toString(),
      planId,
      principal: amount,
      startedAt: Date.now(),
      status: 'active'
    };

    user.investments.unshift(investment);
    await user.save();
    res.json({ account: user });
  } catch (err) {
    res.status(500).json({ error: 'Errore interno del server' });
  }
});

app.listen(PORT, () => {
  console.log(`Server avviato sulla porta ${PORT}`);
});
