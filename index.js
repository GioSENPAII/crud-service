const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use('/uploads', express.static('uploads'));

// Configuración para subir imágenes
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      if (!fs.existsSync('./uploads')){
        fs.mkdirSync('./uploads');
      }
      cb(null, './uploads');
    },
    filename: function (req, file, cb) {
      // Usamos el userId de la URL si existe (para admin), o el del token
      const userId = req.params.id || req.userId;
      const timestamp = Date.now(); // Añadimos timestamp para evitar caché
      cb(null, `profile-${userId}-${timestamp}${path.extname(file.originalname)}`);
    }
  });

const upload = multer({ storage: storage });

// Datos de ejemplo (simulando una base de datos)
let users = [
  {
    id: 1,
    username: 'admin',
    password: bcrypt.hashSync('admin', 8),
    role: 'admin',
    profilePicture: null
  },
  {
    id: 2,
    username: 'user',
    password: bcrypt.hashSync('user', 8),
    role: 'user',
    profilePicture: null
  }
];

let data = [
  {
    id: 1,
    name: "Ejemplo 1",
    description: "Descripción del ejemplo 1"
  },
  {
    id: 2,
    name: "Ejemplo 2",
    description: "Descripción del ejemplo 2"
  }
];

// Registro de usuario
app.post('/auth/register', (req, res) => {
    const { username, password, role = 'user' } = req.body;
    
    // Verificar si el usuario ya existe
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ message: 'El nombre de usuario ya existe' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 8);
    const user = { 
        id: users.length + 1, 
        username, 
        password: hashedPassword, 
        role,
        profilePicture: null
    };
    users.push(user);
    
    // No devolvemos la contraseña
    const { password: _, ...userWithoutPassword } = user;
    res.status(201).json(userWithoutPassword);
});

// Inicio de sesión
app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    
    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role }, 
        'secret_key', 
        { expiresIn: '1h' }
    );
    
    // No devolvemos la contraseña
    const { password: _, ...userWithoutPassword } = user;
    
    res.json({ 
        message: 'Inicio de sesión exitoso', 
        token,
        user: userWithoutPassword
    });
});

// Middleware para verificar el token
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    console.log('Token recibido en verifyToken:', token);
    
    if (!token) {
        console.log('Token no proporcionado');
        return res.status(403).json({ message: 'Token no proporcionado' });
    }
    
    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err) {
            console.log('Error al verificar token:', err.message);
            return res.status(401).json({ message: 'Token inválido' });
        }
        
        console.log('Token verificado correctamente. Usuario decodificado:', decoded);
        
        req.userId = decoded.id;
        req.username = decoded.username;
        req.userRole = decoded.role;
        next();
    });
}

// Obtener todos los usuarios (solo admin)
app.get('/users', verifyToken, (req, res) => {
    // Solo administradores pueden ver todos los usuarios
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    
    // No devolvemos las contraseñas
    const usersWithoutPasswords = users.map(user => {
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
    });
    
    res.json(usersWithoutPasswords);
});

// Crear un nuevo usuario (solo admin)
app.post('/users', verifyToken, (req, res) => {
    // Solo administradores pueden crear usuarios
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    
    const { username, password, role = 'user' } = req.body;
    
    // Verificar si el usuario ya existe
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ message: 'El nombre de usuario ya existe' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 8);
    const user = { 
        id: users.length + 1, 
        username, 
        password: hashedPassword, 
        role,
        profilePicture: null
    };
    users.push(user);
    
    // No devolvemos la contraseña
    const { password: _, ...userWithoutPassword } = user;
    res.status(201).json(userWithoutPassword);
});

// Actualizar un usuario (solo admin)
app.put('/users/:id', verifyToken, (req, res) => {
    // Solo administradores pueden actualizar usuarios
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    
    const userId = parseInt(req.params.id);
    const userIndex = users.findIndex(u => u.id === userId);
    
    if (userIndex === -1) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    const { username, role, password } = req.body;
    
    // Verificar si el nuevo nombre de usuario ya existe (si se cambió)
    if (username && username !== users[userIndex].username) {
        // Solo considerar duplicado si es de otro usuario
        const existingUser = users.find(u => u.username === username && u.id !== userId);
        if (existingUser) {
            return res.status(400).json({ message: 'El nombre de usuario ya existe' });
        }
        users[userIndex].username = username;
    }
    
    // Actualizar el rol si se proporcionó
    if (role) {
        users[userIndex].role = role;
    }
    
    // Actualizar la contraseña si se proporcionó
    if (password && password.trim() !== '') {
        users[userIndex].password = bcrypt.hashSync(password, 8);
    }
    
    // No devolvemos la contraseña
    const { password: _, ...userWithoutPassword } = users[userIndex];
    res.json(userWithoutPassword);
});

// Eliminar un usuario (solo admin)
app.delete('/users/:id', verifyToken, (req, res) => {
    // Solo administradores pueden eliminar usuarios
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    
    const userId = parseInt(req.params.id);
    const userIndex = users.findIndex(u => u.id === userId);
    
    if (userIndex === -1) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // No permitir eliminar al propio administrador
    if (userId === req.userId) {
        return res.status(400).json({ message: 'No puede eliminarse a sí mismo' });
    }
    
    const removedUser = users.splice(userIndex, 1)[0];
    const { password, ...userWithoutPassword } = removedUser;
    
    res.json({ message: 'Usuario eliminado', removedUser: userWithoutPassword });
});

// Perfil de usuario
app.get('/users/profile', verifyToken, (req, res) => {
    const user = users.find(u => u.id === req.userId);
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
    
    // No devolvemos la contraseña
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});

// Actualizar perfil de usuario - Corregido para permitir a cualquier usuario actualizar su propio perfil
// Servidor - nuevo código para paste.txt
// Este código debe reemplazar la ruta actual de actualización de perfil en el servidor

// Ruta específica para usuarios/profile ANTES de la ruta /users/:id para evitar conflictos
app.put('/users/profile', verifyToken, (req, res) => {
    // NO incluir ninguna verificación de rol aquí
    const userIndex = users.findIndex(u => u.id === req.userId);
    if (userIndex === -1) return res.status(404).json({ message: 'Usuario no encontrado' });
    
    console.log(`Actualizando perfil para usuario: ${req.userId}, ${req.username}, rol: ${req.userRole}`);
    console.log('Datos recibidos:', req.body);
    
    const { username } = req.body;
    
    if (username && username !== users[userIndex].username) {
      const existingUser = users.find(u => u.username === username && u.id !== req.userId);
      if (existingUser) {
        return res.status(400).json({ message: 'El nombre de usuario ya existe' });
      }
      users[userIndex].username = username;
    }
    
    const { password, ...userWithoutPassword } = users[userIndex];
    res.json(userWithoutPassword);
  });

// Subir imagen de perfil - Corregido para permitir a cualquier usuario actualizar su propia imagen
// También asegúrate de que esta ruta NO tenga verificación de rol
app.post('/users/profile/picture', verifyToken, upload.single('image'), (req, res) => {
    const userIndex = users.findIndex(u => u.id === req.userId);
    if (userIndex === -1) return res.status(404).json({ message: 'Usuario no encontrado' });
    
    if (!req.file) {
      return res.status(400).json({ message: 'No se ha proporcionado ninguna imagen' });
    }
    
    // Eliminar imagen anterior si existe
    if (users[userIndex].profilePicture) {
      const oldImagePath = './uploads/' + users[userIndex].profilePicture.split('/').pop();
      if (fs.existsSync(oldImagePath)) {
        try {
          fs.unlinkSync(oldImagePath);
        } catch (error) {
          console.error('Error al eliminar imagen anterior:', error);
        }
      }
    }
    
    // Guardar la ruta de la nueva imagen
    users[userIndex].profilePicture = `/uploads/${req.file.filename}`;
    
    const { password, ...userWithoutPassword } = users[userIndex];
    res.json(userWithoutPassword);
  });

// Para que los administradores gestionen fotos de perfil de usuarios
app.post('/admin/users/:id/picture', verifyToken, upload.single('image'), (req, res) => {
    console.log('Solicitud de actualización de imagen por admin recibida');
    console.log('Usuario admin:', req.userId, req.username, req.userRole);
    console.log('Usuario target:', req.params.id);
    
    // Solo administradores pueden cambiar fotos de otros usuarios
    if (req.userRole !== 'admin') {
        console.log('Acceso denegado. No es admin');
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    
    const userId = parseInt(req.params.id);
    const userIndex = users.findIndex(u => u.id === userId);
    
    if (userIndex === -1) {
        console.log('Usuario no encontrado');
        return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    if (!req.file) {
        console.log('No se ha proporcionado ninguna imagen');
        return res.status(400).json({ message: 'No se ha proporcionado ninguna imagen' });
    }
    
    console.log('Archivo recibido:', req.file);
    
    // Primero, eliminamos la imagen anterior si existe
    if (users[userIndex].profilePicture) {
        const oldImagePath = './uploads/' + users[userIndex].profilePicture.split('/').pop();
        console.log('Intentando eliminar imagen anterior:', oldImagePath);
        if (fs.existsSync(oldImagePath)) {
            try {
                fs.unlinkSync(oldImagePath);
                console.log('Imagen anterior eliminada con éxito');
            } catch (error) {
                console.error('Error al eliminar imagen anterior:', error);
            }
        } else {
            console.log('La imagen anterior no existe en el sistema de archivos');
        }
    }
    
    // Guardamos la ruta de la nueva imagen
    users[userIndex].profilePicture = `/uploads/${req.file.filename}`;
    console.log('Nueva ruta de imagen guardada:', users[userIndex].profilePicture);
    
    // No devolvemos la contraseña
    const { password, ...userWithoutPassword } = users[userIndex];
    res.json(userWithoutPassword);
});

// Operaciones CRUD
app.get('/data', verifyToken, (req, res) => {
    // Solo administradores pueden ver todos los datos
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    res.json(data);
});

app.post('/data', verifyToken, (req, res) => {
    // Solo administradores pueden crear datos
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    
    const newData = {
        id: data.length > 0 ? Math.max(...data.map(item => item.id)) + 1 : 1,
        ...req.body,
        userId: req.userId
    };
    data.push(newData);
    res.status(201).json(newData);
});

app.put('/data/:id', verifyToken, (req, res) => {
    // Solo administradores pueden actualizar datos
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    
    const id = parseInt(req.params.id);
    const dataIndex = data.findIndex(item => item.id === id);
    
    if (dataIndex === -1) {
        return res.status(404).json({ message: 'Datos no encontrados' });
    }
    
    // Mantener el ID y userId originales
    const updatedData = {
        ...data[dataIndex],
        ...req.body,
        id: id,
        userId: data[dataIndex].userId
    };
    
    data[dataIndex] = updatedData;
    res.json(updatedData);
});

app.delete('/data/:id', verifyToken, (req, res) => {
    // Solo administradores pueden eliminar datos
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden acceder a esta funcionalidad.' });
    }
    
    const id = parseInt(req.params.id);
    const dataIndex = data.findIndex(item => item.id === id);
    
    if (dataIndex === -1) {
        return res.status(404).json({ message: 'Datos no encontrados' });
    }
    
    const removedItem = data.splice(dataIndex, 1)[0];
    res.json({ message: 'Dato eliminado', removedItem });
});

// En el archivo paste.txt, añade este nuevo endpoint
app.post('/users/profile', verifyToken, (req, res) => {
    console.log('Solicitud POST de actualización de perfil recibida');
    console.log('Usuario autenticado:', req.userId, req.username, req.userRole);
    console.log('Datos recibidos en el cuerpo:', req.body);
    
    const userIndex = users.findIndex(u => u.id === req.userId);
    if (userIndex === -1) {
        console.log('Usuario no encontrado');
        return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // Solo permitimos actualizar ciertos campos
    const { username } = req.body;
    
    // Verificar si el nuevo nombre de usuario ya existe
    if (username && username !== users[userIndex].username) {
        // Solo considerar duplicado si es de otro usuario
        const existingUser = users.find(u => u.username === username && u.id !== req.userId);
        if (existingUser) {
            console.log('El nombre de usuario ya existe');
            return res.status(400).json({ message: 'El nombre de usuario ya existe' });
        }
        console.log(`Actualizando nombre de usuario de ${users[userIndex].username} a ${username}`);
        users[userIndex].username = username;
    } else {
        console.log('No hay cambios en el nombre de usuario o no se proporcionó un nombre');
    }
    
    console.log('Perfil actualizado exitosamente');
    
    // No devolvemos la contraseña
    const { password, ...userWithoutPassword } = users[userIndex];
    res.json(userWithoutPassword);
});

// Para probar el servidor
app.get('/', (req, res) => {
    res.send('Servidor CRUD funcionando correctamente');
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
