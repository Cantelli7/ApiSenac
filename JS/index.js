const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key';

app.use(bodyParser.json());

const users = [];

// Cadastro de usuário
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = users.find(user => user.email === email);
  if (existingUser) {
    return res.status(400).json({ message: 'Usuário já existe' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { name, email, password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ message: 'Usuário cadastrado com sucesso' });
});


// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(user => user.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: 'Credenciais inválidas' });
  }

  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(403);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.get('/api/auth/users', authenticateJWT, (req, res) => {
  res.json(users.map(user => ({ name: user.name, email: user.email })));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
