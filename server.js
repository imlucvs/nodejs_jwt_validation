const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');

let EncryptJWT, jwtDecrypt;
import('jose').then((jose) => {
  EncryptJWT = jose.EncryptJWT;
  jwtDecrypt = jose.jwtDecrypt;
});

const app = express();

app.use(express.static(path.join(__dirname, 'public')));

app.use(cors());
app.use(bodyParser.json());

const secretKey = crypto.randomBytes(32);

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (username === 'usuario' && password === 'senha') {
    const payload = { userId: 1, username: 'usuario' };
    const jwe = await new EncryptJWT(payload)
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setExpirationTime('2h')
      .encrypt(secretKey);

    res.json({ token: jwe });
  } else {
    res.status(401).json({ error: 'Credenciais inválidas' });
  }
});

app.post('/verify-auth', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ authenticated: false });

  try {
    const { payload } = await jwtDecrypt(token, secretKey);
    res.json({ authenticated: true, user: payload });
  } catch (error) {
    res.status(401).json({ authenticated: false });
  }
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(3000, () => console.log('Servidor rodando na porta 3000'));