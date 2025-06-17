// ─── Elevar límite de listeners ────────────────────────────────
require('events').EventEmitter.defaultMaxListeners = 20;

require('dotenv').config();
const express       = require('express');
const session       = require('express-session');
const hbs           = require('hbs');
const pool          = require('./db');
const path          = require('path');
const moment        = require('moment-timezone');
const fs            = require('fs');
const cron          = require('node-cron');
const handlebars    = require('handlebars');
const jwt           = require('jsonwebtoken');
const multer        = require('multer');
const { S3Client }  = require('@aws-sdk/client-s3');
const { Upload }    = require('@aws-sdk/lib-storage');

const app = express();
const SECRET_KEY = 'MiClaveSuperSegura!$%&/()=12345';





// 1. Multer en memoria
const upload = multer({ storage: multer.memoryStorage() });

// 2. Cliente S3 v3
const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId:     process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});













app.use(session({
    secret: 'mysecret',  // Cambia este secreto
    resave: false,
    saveUninitialized: true
}));
// Configurar el motor de plantillas
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));  // Asegúrate de que apunte correctamente a tu carpeta de vistas
app.use(express.static(__dirname + '/public'));

// Middleware para parsing
app.use(express.urlencoded({ extended: false }));


// Ruta para mostrar el formulario de login
app.get('/login', (req, res) => {
    res.render('login/login');
});

// Asegúrate de que Express pueda manejar datos en formato JSON
app.use(express.json());



hbs.registerHelper('formatDate', (date) => {
    return moment(date).format('DD/MM/YYYY');
});


// Registrar el helper 'eq' para comparar dos valores
hbs.registerHelper('eq', (a, b) => {
    return a === b;
});

hbs.registerHelper('formatoHora', function(datetime) {
    if (!datetime) return '';
    const date = new Date(datetime);
    return date.toTimeString().split(' ')[0]; // Devuelve HH:MM:SS
  });


hbs.registerHelper('incluye', function (array, valor, options) {
    return array && array.includes(valor) ? options.fn(this) : options.inverse(this);
  });
  hbs.registerHelper('noIncluye', function (array, valor, options) {
    return !array.includes(valor) ? options.fn(this) : options.inverse(this);
  });

app.use(express.static('public', {
    etag: false,
    maxAge: 0
  }));







// Ruta para manejar el login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Consulta para verificar si el usuario existe con el correo, contraseña dados y está activo
        const [results] = await pool.query(
            'SELECT * FROM usuarios WHERE email = ? AND password = ?',
            [email, password]
        );

        if (results.length > 0) {
            const user = results[0];

            // Verificar si el estado del usuario es activo
            if (user.estado !== 'activo') {
                // Devolver un mensaje de usuario inactivo sin destruir la sesión
                return res.json({ status: 'inactive', message: 'Usuario inactivo' });
            } else {
                // Almacena los datos del usuario en la sesión
                req.session.user = user;  // Almacena el objeto completo del usuario
                req.session.userId = user.id; // Guarda el `userId` en la sesión
                req.session.name = user.nombre;  // Guarda el nombre del usuario en la sesión
                req.session.loggedin = true;  // Establece el estado de sesión como conectado
                req.session.roles = user.role;  // Guarda los roles en la sesión
                req.session.cargo = user.cargo; // Almacena el cargo en la sesión

                const role = user.role;  // Obtiene el rol del usuario

                // Redirige basado en el rol del usuario
                if (role === '1') {
                    return res.redirect('/menuAdministrativo');
                } else if (role === 'tecnico') {
                    return res.redirect('/tecnico');
                } else if (role === 'residentes') {
                    return res.redirect('/menu_residentes');
                }
            }
        } else {
            // Muestra la página de login con mensaje de error si las credenciales son incorrectas
            res.render('login/login', { error: 'Correo, contraseña incorrectos o usuario inactivo' });
        }
    } catch (err) {
        // Maneja los errores y envía una respuesta 500 en caso de problemas con la base de datos o el servidor
        res.status(500).json({ error: err.message });
    }
});



// Verifica que el código se ejecuta en el navegador antes de registrar el Service Worker
if (typeof window !== "undefined" && "serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("/service-worker.js")
        .then((registration) => {
          console.log("✅ Service Worker registrado correctamente:", registration);
        })
        .catch((error) => console.error("❌ Error al registrar el Service Worker:", error));
    });
  
    // Recargar la página cuando se active un nuevo SW
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      console.log("♻️ Nueva versión activa, recargando página...");
      window.location.reload();
    });
  }
  







  app.get('/geolocalizacion', (req, res) => {
    if (req.session.loggedin === true) {
        const userId = req.session.userId;
        const nombreUsuario = req.session.user.name;

        // Procesar roles
        const cargos = req.session.cargo?.split(',').map(c => c.trim()) || [];

        console.log(`🔐 Usuario en geolocalización: ${nombreUsuario} (ID: ${userId})`);
        console.log(`🎯 Roles asignados: [${cargos.join(', ')}]`);

        res.render('administrativo/mapa/ver_mapa.hbs', {
            nombreUsuario,
            userId,
            roles: cargos // <-- pasa roles como array a la vista
        });
    } else {
        res.redirect('/login');
    }
});



app.get('/reset-password', (req, res) => {
    res.render('login/reset-password');
});



const formatDateForMySQL = (date) => {
    return date.toISOString().slice(0, 19).replace('T', ' ');
};

// ✅ Ruta para solicitar restablecimiento de contraseña
app.post('/request-password-reset', async (req, res) => {
    try {
        const { email } = req.body;

        // Verificar si el usuario existe
        const [users] = await pool.query(
            'SELECT reset_token, reset_token_exp FROM usuarios WHERE email = ?',
            [email]
        );

        let token;
        let expireTime = new Date(Date.now() + 3600000); // Sumar 1 hora en UTC
        let mysqlExpireTime = formatDateForMySQL(expireTime);

        if (users.length > 0 && users[0].reset_token && new Date(users[0].reset_token_exp) > new Date()) {
            // Si el usuario ya tiene un token válido, reutilizarlo
            token = users[0].reset_token;
            mysqlExpireTime = users[0].reset_token_exp; // Mantener la fecha de expiración original
        } else {
            // Generar un nuevo token y actualizar en la base de datos
            token = crypto.randomBytes(32).toString('hex');
            const [result] = await pool.query(
                'UPDATE usuarios SET reset_token = ?, reset_token_exp = ? WHERE email = ?',
                [token, mysqlExpireTime, email]
            );

            if (result.affectedRows === 0) {
                return res.status(400).json({ message: 'No se pudo actualizar el token, verifica el correo.' });
            }
        }

        console.log("✅ Token generado:", token);
        console.log("✅ Fecha de expiración guardada:", mysqlExpireTime);

        // Verificar que el token realmente se guardó en la base de datos
        const [checkToken] = await pool.query(
            'SELECT reset_token, reset_token_exp FROM usuarios WHERE email = ?', 
            [email]
        );
        console.log("🔍 Token en la BD después de la actualización:", checkToken[0]?.reset_token);
        console.log("🔍 Expiración en la BD:", checkToken[0]?.reset_token_exp);

        // Construir enlace de restablecimiento
        const resetLink = `http://sistemacerceta.com/reset-password/${encodeURIComponent(token)}`;

        // Configuración del correo
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
        user: 'cercetasolucionempresarial@gmail.com', // ← Faltaba cerrar comillas aquí
                pass: 'yuumpbszqtbxscsq'
            }
        });

        // Enviar el correo con el enlace
        await transporter.sendMail({
            from: 'cercetasolucionempresarial@gmail.com',
            to: email,
            subject: `Restablece tu contraseña`,
            html: `<p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
                   <a href="${resetLink}">${resetLink}</a>`
        });

        res.json({ message: 'Se ha enviado un enlace a tu correo.' });

    } catch (error) {
        console.error("❌ Error en /request-password-reset:", error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});





// ✅ Ruta para validar el token y mostrar el formulario de restablecimiento
app.get('/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;
        console.log("🔑 Token recibido en la URL:", token);

        // Verificar si el token es válido y no ha expirado
        const [users] = await pool.query(
            'SELECT id FROM usuarios WHERE reset_token = ? AND CONVERT_TZ(reset_token_exp, "+00:00", "+00:00") > UTC_TIMESTAMP()', 
            [token]
        );
        
        console.log("🔎 Resultado de la consulta:", users);

        if (!users || users.length === 0) {
            return res.send("⚠️ El enlace para restablecer la contraseña es inválido o ha expirado.");
        }

        res.render('login/change-password.hbs', { token });

    } catch (error) {
        console.error("❌ Error en /reset-password/:token:", error);
        res.status(500).send("Error en el servidor.");
    }
});






app.post('/update-password', async (req, res) => {
    try {
        const { token, password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).json({ message: 'Las contraseñas no coinciden.' });
        }

        if (password.length < 8) {
            return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres.' });
        }

        const [users] = await pool.query(
            'SELECT id, reset_token_exp FROM usuarios WHERE reset_token = ? AND reset_token_exp > UTC_TIMESTAMP()', 
            [token]
        );

        if (users.length === 0) {
            return res.status(400).json({ message: 'El enlace para restablecer la contraseña es inválido o ha expirado.' });
        }

        const userId = users[0].id;

        await pool.query(
            'UPDATE usuarios SET password = ?, reset_token = NULL, reset_token_exp = NULL WHERE id = ?', 
            [password, userId]
        );

        res.json({ message: "Contraseña actualizada con éxito.", redirect: "/login" });

    } catch (error) {
        console.error("❌ Error en /update-password:", error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});


hbs.registerHelper('add', (a, b) => a + b);
hbs.registerHelper('subtract', (a, b) => a - b);
hbs.registerHelper('gt', (a, b) => a > b);
hbs.registerHelper('lt', (a, b) => a < b);

app.get('/menu_residentes', async (req, res) => {
    if (req.session.loggedin !== true) {
        return res.redirect('/login');
    }

    const name = req.session.name;
    const userId = req.session.userId;

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const offset = (page - 1) * limit;

    try {
        const [userResult] = await pool.query('SELECT edificio FROM usuarios WHERE id = ?', [userId]);
        if (userResult.length === 0) {
            return res.status(404).send('Usuario no encontrado');
        }

        const edificioId = userResult[0].edificio;

        const [totalResult] = await pool.query(
            'SELECT COUNT(*) as total FROM publicaciones WHERE edificio_id = ?',
            [edificioId]
        );
        const totalPosts = totalResult[0].total;
        const totalPages = Math.ceil(totalPosts / limit);

       const [resultados] = await pool.query(
    'SELECT * FROM publicaciones WHERE edificio_id = ? ORDER BY id DESC LIMIT ? OFFSET ?',
    [edificioId, limit, offset]
);


        const postIds = resultados.map(post => post.id);
        if (postIds.length === 0) {
            return res.render('Residentes/home_residentes.hbs', {
                name,
                userId,
                blogPosts: [],
                currentPage: page,
                totalPages,
                layout: 'layouts/nav_residentes.hbs'
            });
        }

        // Reacciones agrupadas
        const [reaccionesTotales] = await pool.query(`
            SELECT publicacion_id, tipo, COUNT(*) as count 
            FROM reacciones 
            WHERE publicacion_id IN (?) 
            GROUP BY publicacion_id, tipo
        `, [postIds]);

        // Comentarios agrupados
        const [comentariosTotales] = await pool.query(`
            SELECT publicacion_id, COUNT(*) as count 
            FROM comentarios 
            WHERE publicacion_id IN (?) 
            GROUP BY publicacion_id
        `, [postIds]);

        // Reacción del usuario actual
        const [reaccionesUsuario] = await pool.query(`
            SELECT publicacion_id, tipo 
            FROM reacciones 
            WHERE publicacion_id IN (?) AND usuario_id = ?
        `, [postIds, userId]);

        // Mapear resultados por publicación
        const blogPosts = resultados.map(post => {
            const reacciones = reaccionesTotales.filter(r => r.publicacion_id === post.id);
            const comentario = comentariosTotales.find(c => c.publicacion_id === post.id);
            const reaccionUsuario = reaccionesUsuario.find(r => r.publicacion_id === post.id);

            return {
                ...post,
                imagen: post.imagen ? post.imagen.toString('base64') : null,
                pdf: post.pdf ? post.pdf.toString('base64') : null,
                word: post.word ? post.word.toString('base64') : null,
                excel: post.excel ? post.excel.toString('base64') : null,
                estadisticas: {
                    reacciones,
                    totalComentarios: comentario?.count || 0,
                    userReaccion: reaccionUsuario?.tipo || null
                }
            };
        });

        res.render('Residentes/home_residentes.hbs', {
            name,
            userId,
            blogPosts,
            currentPage: page,
            totalPages,
            layout: 'layouts/nav_residentes.hbs'
        });

    } catch (err) {
        console.error(err);
        res.status(500).send('Error al obtener las entradas del blog');
    }
});


app.get('/api/publicacioness', async (req, res) => {
    if (!req.session.loggedin) return res.status(403).send('No autorizado');

    try {
        const userId = req.session.userId;
        const [userResult] = await pool.query('SELECT edificio FROM usuarios WHERE id = ?', [userId]);
        if (userResult.length === 0) return res.status(404).send('Usuario no encontrado');

        const edificioId = userResult[0].edificio;

        const [resultados] = await pool.query(
            'SELECT id, titulo, contenido, fecha FROM publicaciones WHERE edificio_id = ? ORDER BY id DESC LIMIT 5',
            [edificioId]
        );

        res.json(resultados);
    } catch (err) {
        console.error('Error al cargar publicaciones:', err.message);
        res.json([]); // enviar lista vacía para evitar que se rompa
    }
});


// En tu configuración de Handlebars
hbs.registerHelper('ifCond', function (v1, v2, options) {
    return (v1 === v2) ? options.fn(this) : options.inverse(this);
});




app.get('/subir_pago_residentes', async (req, res) => {
    if (req.session.loggedin === true) {
        const userId = req.session.userId;

        try {
            // Consulta para obtener edificio y apartamento del usuario
            const query = 'SELECT edificio, apartamento FROM usuarios WHERE id = ?';
            const [rows] = await pool.query(query, [userId]);

            if (rows.length > 0) {
                const { edificio, apartamento } = rows[0];

                // Procesar roles del usuario desde la sesión
                const cargos = req.session.cargo?.split(',').map(c => c.trim()) || [];

                console.log('📍 Usuario:', req.session.user.name);
                console.log('🏢 Edificio:', edificio, '| 🏠 Apartamento:', apartamento);
                console.log('🎯 Roles asignados:', cargos);

                res.render('Residentes/pagos/subir_mi_pago.hbs', {
                    nombreUsuario: req.session.user.name,
                    userId,
                    roles: cargos, // <- importante
                    edificioSeleccionado: edificio,
                    apartamentoSeleccionado: apartamento,
                    layout: 'layouts/nav_residentes.hbs'
                });
            } else {
                res.redirect('/login');
            }
        } catch (error) {
            console.error('❌ Error al obtener edificio y apartamento:', error);
            res.status(500).send('Error interno del servidor');
        }
    } else {
        res.redirect('/login');
    }
});




























// Ruta para manejar el cierre de sesión
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Error al cerrar sesión' });
        }
        res.redirect('/login');  // Redirige al usuario a la página de login
    });
});






const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid'); // Utiliza UUID para generar IDs únicos

// Configurar el transporter con nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
         user: 'cercetasolucionempresarial@gmail.com', // ← Faltaba cerrar comillas aquí
                pass: 'yuumpbszqtbxscsq'
    },
    messageId: uuidv4(), // Genera un Message-ID único para cada correo enviado
});

const crypto = require('crypto'); // Importa el módulo crypto



hbs.registerHelper('json', function(context) {
    return JSON.stringify(context);
});



app.get("/menuAdministrativo", (req, res) => {
    if (req.session.loggedin === true) {
        try {
            const userId = req.session.userId;
            const nombreUsuario = req.session.name || req.session.user.name;
            req.session.nombreGuardado = nombreUsuario;

            const cargos = req.session.cargo?.split(',').map(c => c.trim()) || [];

            console.log(`🔐 Usuario autenticado: ${nombreUsuario} (ID: ${userId})`);
            console.log(`🎯 Roles asignados: [${cargos.join(', ')}]`);

            res.render("administrativo/menuadministrativo.hbs", {
                layout: 'layouts/nav_admin.hbs',
                name: nombreUsuario,
                userId,
                roles: cargos // pasamos el array directamente
            });
        } catch (error) {
            console.error('Error al cargar el menú administrativo:', error);
            res.status(500).send('Error interno');
        }
    } else {
        res.redirect("/login");
    }
});


















app.get("/menu_inventarios", async (req, res) => {
    if (req.session.loggedin === true) {
        try {
            const userId = req.session.userId;
            const nombreUsuario = req.session.name || req.session.user.name;
            req.session.nombreGuardado = nombreUsuario;

            // Procesar roles como array de números en string
            const cargos = req.session.cargo?.split(',').map(c => c.trim()) || [];

            console.log(`🔐 Usuario autenticado: ${nombreUsuario} (ID: ${userId})`);
            console.log(`🎯 Roles asignados: [${cargos.join(', ')}]`);

            res.render("inventarios/menu.hbs", {
                layout: 'layouts/nav_admin.hbs',
                name: nombreUsuario,
                userId,
                roles: cargos // <-- aquí se pasa a la vista
            });
        } catch (error) {
            console.error('❌ Error al cargar el menú de inmuebles:', error);
            res.status(500).send('Error al cargar el menú de inmuebles');
        }
    } else {
        res.redirect("/login");
    }
});









app.get("/Agregar_nuevo", async (req, res) => {
    if (req.session.loggedin === true) {
        try {
            const userId = req.session.userId;
            const nombreUsuario = req.session.name || req.session.user.name;
            req.session.nombreGuardado = nombreUsuario;

            // Procesar roles como array de números en string
            const cargos = req.session.cargo?.split(',').map(c => c.trim()) || [];

            console.log(`🔐 Usuario autenticado: ${nombreUsuario} (ID: ${userId})`);
            console.log(`🎯 Roles asignados: [${cargos.join(', ')}]`);

            res.render("inventarios/agregar.hbs", {
                layout: 'layouts/nav_admin.hbs',
                name: nombreUsuario,
                userId,
                roles: cargos // <-- aquí se pasa a la vista
            });
        } catch (error) {
            console.error('❌ Error al cargar el menú de inmuebles:', error);
            res.status(500).send('Error al cargar el menú de inmuebles');
        }
    } else {
        res.redirect("/login");
    }
});




app.post('/agregar', upload.array('imagenes'), async (req, res) => {
  const { nombre, categoria, cantidad, precio, descripcion, tallas } = req.body;

  try {
    // 1️⃣ Insertar producto
    const [producto] = await pool.query(`
      INSERT INTO productos (nombre, categoria, cantidad_total, precio_unitario, descripcion)
      VALUES (?, ?, ?, ?, ?)
    `, [nombre, categoria, cantidad, precio, descripcion]);
    const productoId = producto.insertId;

    // 2️⃣ Insertar tallas
// 2️⃣ Insertar tallas
const tallasArray = typeof tallas === 'string'
  ? JSON.parse(tallas)
  : tallas;

// Filtrar sólo los objetos que tengan nombre, cantidad y precio
const tallasFiltradas = tallasArray.filter(t =>
  t.nombre && t.cantidad != null && t.precio != null
);

for (const t of tallasFiltradas) {
  await pool.query(`
    INSERT INTO productos_tallas (producto_id, talla, cantidad, precio)
    VALUES (?, ?, ?, ?)
  `, [
    productoId,
    t.nombre,
    t.cantidad,
    t.precio
  ]);
}

    // 3️⃣ Subir cada imagen a S3 y guardar su URL en la BD
    for (const file of req.files) {
      // Genera un Key único
      const key = `productos/${Date.now()}_${file.originalname.replace(/\s+/g, '_')}`;
      
      // Sube con el helper v3
      await new Upload({
   client: s3Client,
  params: {
    Bucket:      process.env.AWS_BUCKET_NAME,
    Key:         key,
    Body:        file.buffer,
    ContentType: file.mimetype
    // ← ya no se incluye ACL aquí
  }
}).done();

      // Construye la URL pública
      const fileUrl = `https://${process.env.AWS_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;

      // Guarda en productos_imagenes
      await pool.query(`
        INSERT INTO productos_imagenes (producto_id, nombre_archivo, ruta_archivo)
        VALUES (?, ?, ?)
      `, [productoId, file.originalname, fileUrl]);
    }

    res.json({ mensaje: '✅ Producto creado y guardado correctamente.' });
  } catch (error) {
    console.error('❌ Error al guardar el producto:', error);
    res.status(500).send('Error al guardar el producto');
  }
});

app.get("/ver_inventario", async (req, res) => {
  if (!req.session.loggedin) return res.redirect("/login");

  try {
    const [rows] = await pool.query(`
      SELECT
        p.id                  AS productoId,
        p.nombre              AS nombre,
        p.categoria           AS categoria,
        p.descripcion         AS descripcion,
        p.precio_unitario     AS precio,          -- <–– lo añadimos
        pt.talla              AS talla,
        pt.cantidad           AS tallaCantidad,
        pt.precio             AS tallaPrecio,
        pi.nombre_archivo     AS imgNombre,
        pi.ruta_archivo       AS imgRuta
      FROM productos p
      LEFT JOIN productos_tallas pt ON pt.producto_id = p.id
      LEFT JOIN productos_imagenes pi ON pi.producto_id = p.id
      ORDER BY p.categoria, p.id;
    `);

    const categoriasMap = new Map();
    for (const r of rows) {
      if (!categoriasMap.has(r.categoria)) {
        categoriasMap.set(r.categoria, new Map());
      }
      const prodMap = categoriasMap.get(r.categoria);

      if (!prodMap.has(r.productoId)) {
        prodMap.set(r.productoId, {
          id:          r.productoId,
          nombre:      r.nombre,
          descripcion: r.descripcion,
          precio:      r.precio,      // <–– aquí lo guardamos
          tallas:      [],
          imagenes:    []
        });
      }
      const prod = prodMap.get(r.productoId);

      // tallas
      if (r.talla) {
        const exists = prod.tallas.some(t =>
          t.nombre   === r.talla &&
          t.cantidad === r.tallaCantidad &&
          t.precio   === r.tallaPrecio
        );
        if (!exists) {
          prod.tallas.push({
            nombre:   r.talla,
            cantidad: r.tallaCantidad,
            precio:   r.tallaPrecio
          });
        }
      }

      // imágenes
      if (r.imgNombre) {
        const existsImg = prod.imagenes.some(i =>
          i.nombre === r.imgNombre &&
          i.ruta   === r.imgRuta
        );
        if (!existsImg) {
          prod.imagenes.push({
            nombre: r.imgNombre,
            ruta:   r.imgRuta
          });
        }
      }
    }

    const categorias = Array.from(
      categoriasMap,
      ([nombre, prodMap]) => ({
        nombre,
        productos: Array.from(prodMap.values())
      })
    );

    res.render("inventarios/ver.hbs", {
      layout:     'layouts/nav_admin.hbs',
      name:       req.session.name,
      userId:     req.session.userId,
      roles:      req.session.cargo?.split(',').map(c=>c.trim())||[],
      categorias
    });
  } catch (error) {
    console.error('❌ Error al cargar inventario:', error);
    res.status(500).send('Error al cargar inventario');
  }
});









app.get('/', (req, res) => {
    res.redirect('/login');
});

app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});