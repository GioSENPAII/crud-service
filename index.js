const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Datos de ejemplo (simulando una base de datos)
let users = [];
let data = [];

// Registro de usuario
app.post('/register', (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const user = { id: users.length + 1, username, password: hashedPassword, role };
    users.push(user);
    res.status(201).json({ message: 'Usuario registrado', user });
});

// Inicio de sesión
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, 'secret_key', { expiresIn: '1h' });
    res.json({ message: 'Inicio de sesión exitoso', token });
});

// Middleware para verificar el token
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Token no proporcionado' });
    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Token inválido' });
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    });
}

// Operaciones CRUD (solo para administradores)
app.get('/data', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
    res.json(data);
});

app.post('/data', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
    const newData = req.body;
    data.push(newData);
    res.status(201).json({ message: 'Dato creado', newData });
});

app.put('/data/:id', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
    const id = req.params.id;
    const updatedData = req.body;
    data[id] = updatedData;
    res.json({ message: 'Dato actualizado', updatedData });
});

app.delete('/data/:id', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
    const id = req.params.id;
    data.splice(id, 1);
    res.json({ message: 'Dato eliminado' });
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});