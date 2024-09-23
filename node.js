const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key'; // Use uma chave secreta segura

app.use(bodyParser.json());

// Rota para a raiz
app.get('/', (req, res) => {
  res.send('Bem-vindo à API de Autenticação JWT!');
});

// Cadastro de usuário
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Verifica se o usuário já existe
  const existingUser = users.find(user => user.email === email);
  if (existingUser) {
    return res.status(400).json({ message: 'Usuário já existe' });
  }

  // Cria novo usuário
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { name, email, password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ message: 'Usuário cadastrado com sucesso' });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  // Encontra o usuário
  const user = users.find(user => user.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: 'Credenciais inválidas' });
  }

  // Gera o token JWT
  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware para autenticação
const authenticateJWT = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(403);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Listagem de usuários (protegido)
app.get('/api/auth/users', authenticateJWT, (req, res) => {
  // Retorna todos os usuários (sem senha)
  res.json(users.map(user => ({ name: user.name, email: user.email })));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
