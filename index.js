// 1. IMPORTAMOS LAS LIBRERÍAS
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

// IMPORTACIONES DE IMAGENES
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');
// const upload = multer({ dest: 'uploads/' }); // Carpeta temporal

// --- IMPORTS ---
const cron = require('node-cron'); // Importar al inicio del archivo

const crypto = require('crypto'); // Nativo de Node.js, no hace falta npm install


// --- IMPORTACIÓN MERCADO PAGO ---
const { MercadoPagoConfig, Preference } = require('mercadopago');

// Configura con tu ACCESS TOKEN de PRUEBA (Ponlo en .env en el futuro)
const client = new MercadoPagoConfig({ accessToken: 'APP_USR-7458384450787340-120216-78724c3a5f2c37e72886e52c26816cc0-161693502' });

// APP_USR-7458384450787340-120216-78724c3a5f2c37e72886e52c26816cc0-161693502 producción
// APP_USR-6372969451024117-120216-c0b561a0dbe692690a56e2696d333ea2-3035329953 prueba

// --- IMPORTACIONES ---
const nodemailer = require('nodemailer');


// --- CONFIGURACIÓN DE EMAIL (MODO RESISTENTE) ---
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587, // Probamos el puerto alternativo (TLS)
  secure: false, 
  auth: {
    user: 'cercamioapp@gmail.com', 
    pass: 'wdnb ewmc lsyp labk' 
  },
  tls: {
    rejectUnauthorized: false // Esto ayuda a saltar bloqueos de certificados en Render
  }
});


// Función auxiliar BLINDADA
const enviarEmail = async (destinatario, asunto, texto) => {
  console.log("========================================");
  console.log(`📨 INTENTANDO ENVIAR EMAIL A: ${destinatario}`);
  console.log(`📝 CONTENIDO (Por si falla): ${texto}`); // <--- AQUÍ VERÁS EL CÓDIGO
  console.log("========================================");

  try {
    await transporter.sendMail({
      from: '"Soporte CercaMío" <tu_email_de_empresa@gmail.com>',
      to: destinatario,
      subject: asunto,
      text: texto,
    });
    console.log('✅ Email enviado correctamente por SMTP.');
  } catch (error) {
    // AQUÍ ESTÁ EL TRUCO: Capturamos el error pero NO lo lanzamos (throw).
    // Solo avisamos en consola y dejamos que el código siga.
    console.error("⚠️ EL EMAIL FALLÓ (TIMEOUT/BLOQUEO), PERO SEGUIMOS.");
    console.error("👉 Usa el código que se imprimió arriba para probar.");
  }
};

// Función para generar código de 6 números
const generarCodigo = () => Math.floor(100000 + Math.random() * 900000).toString();

// Función para capitalizar nombres (ej: "juan perez" -> "Juan Perez")
const capitalizarNombre = (texto) => {
  if (!texto) return "";
  return texto
    .toLowerCase()
    .split(' ')
    .map(palabra => palabra.charAt(0).toUpperCase() + palabra.slice(1))
    .join(' ');
};


// CONFIGURACIÓN DE CLOUDINARY (¡Pon tus datos aquí!)
cloudinary.config({ 
  cloud_name: 'dd7yzrvpn', 
  api_key: '328861189229127', 
  api_secret: 'mMehF9awKrLWZTd-br3VdzBKS5g' 
});

// 3. MOTOR DE ALMACENAMIENTO (ESTO ES LO NUEVO)
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'fotosresenas', // Nombre de carpeta en tu nube
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
  },
});

// 4. INICIALIZAR MULTER CON CLOUDINARY
const upload = multer({ storage: storage });

// 2. CONFIGURAMOS LA APP
const app = express();
const port = process.env.PORT || 3000;

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// CLAVE SECRETA PARA LOS TOKENS (En producción esto va en variables de entorno)
const JWT_SECRET = process.env.JWT_SECRET || 'mi_secreto_super_seguro_globaltrade_2024';

// --- CONFIGURACIÓN FIREBASE ADMIN (PROFESIONAL) ---
const admin = require('firebase-admin');
const fs = require('fs'); // Necesitamos 'fs' para verificar si el archivo existe

// Definimos las dos rutas posibles
const rutaLocal = './serviceAccountKey.json';
const rutaRender = '/etc/secrets/serviceAccountKey.json'; // Render guarda aquí los Secret Files

let serviceAccount;

try {
  if (fs.existsSync(rutaRender)) {
    // Estamos en RENDER
    console.log('🔒 Cargando credenciales desde Secret Files (Render)...');
    serviceAccount = require(rutaRender);
  } else if (fs.existsSync(rutaLocal)) {
    // Estamos en LOCAL
    console.log('💻 Cargando credenciales locales...');
    serviceAccount = require(rutaLocal);
  } else {
    // NO SE ENCONTRÓ
    console.error('❌ ERROR CRÍTICO: No se encontró serviceAccountKey.json ni en local ni en secrets.');
    // No detenemos el proceso, pero las notificaciones fallarán.
  }

  // Inicializar solo si tenemos credenciales y no se ha iniciado antes
  if (serviceAccount && !admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('✅ Firebase Admin inicializado correctamente.');
  }

} catch (error) {
  console.error('❌ Error inicializando Firebase:', error);
}


app.use(cors({
  origin: '*', // <--- Permite conexiones desde CUALQUIER lugar (incluido localhost)
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json()); // Permitir recibir datos en formato JSON

// Asegúrate de requerir dotenv al principio de tu archivo si estás en local
// require('dotenv').config(); 

app.get('/ping', (req, res) => {
  res.send('pong');
});

// OBTENER LA URL (Prioridad: Variable de Entorno -> Hardcode -> String vacío)
// IMPORTANTE: Asegúrate de que NO haya comillas extras si usas el string directo
const connectionString = process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_5IHPFzWvme9g@ep-dawn-pond-ac51t2cr-pooler.sa-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require';

// --- DIAGNÓSTICO (Esto saldrá en los logs de Render) ---
console.log("------------------------------------------------");
console.log("INTENTANDO CONECTAR A BASE DE DATOS...");
if (!process.env.DATABASE_URL) {
    console.warn("⚠️ ADVERTENCIA: No se detectó process.env.DATABASE_URL. Usando fallback hardcodeado.");
} else {
    console.log("✅ Variable de entorno detectada.");
    // Imprimimos solo los primeros 10 caracteres para verificar que no sea "undefined" o tenga comillas, sin revelar la clave
    console.log("Valor inicia con:", process.env.DATABASE_URL.substring(0, 15) + "..."); 
}
console.log("------------------------------------------------");

const pool = new Pool({
  connectionString: connectionString,
  ssl: {
    require: true,
    rejectUnauthorized: false // <--- ESTO ES VITAL PARA NEON A VECES
  },
});



// --- FUNCIÓN AUXILIAR PARA ENVIAR NOTIFICACIONES (AUTO-CLEANUP) ---
const enviarNotificacion = async (usuarioIdDestino, titulo, mensaje, dataPayload = {}) => {
  try {
    // 1. Buscamos el token en la base de datos
    const query = 'SELECT fcm_token FROM usuarios WHERE usuario_id = $1';
    const res = await pool.query(query, [usuarioIdDestino]);

    // Si no tiene token, no hacemos nada
    if (res.rows.length === 0 || !res.rows[0].fcm_token) {
      console.log(`⚠️ El usuario ${usuarioIdDestino} no tiene token activo.`);
      return; 
    }

    const fcmToken = res.rows[0].fcm_token;

    // 2. Preparamos el mensaje
    const message = {
      notification: { title: titulo, body: mensaje },
      token: fcmToken,
      data: dataPayload // Datos ocultos (ej: ID de pedido para abrir pantalla exacta)
    };

    // 3. Enviamos
    await admin.messaging().send(message);
    console.log(`✅ Notificación enviada a ${usuarioIdDestino}`);

  } catch (error) {
    console.error('❌ Error enviando notificación:', error);

    // --- LÓGICA DE AUTO-LIMPIEZA ---
    // Si Firebase nos dice que el token no existe (App desinstalada o datos borrados)
    if (error.codePrefix === 'messaging' && 
       (error.errorInfo.code === 'messaging/registration-token-not-registered' || 
        error.errorInfo.code === 'messaging/invalid-argument')) {
      
      console.log(`🗑️ Token inválido detectado para usuario ${usuarioIdDestino}. Limpiando base de datos...`);
      
      // Borramos el token muerto para que no de error la próxima vez
      try {
        await pool.query('UPDATE usuarios SET fcm_token = NULL WHERE usuario_id = $1', [usuarioIdDestino]);
        console.log("✨ Base de datos actualizada (Token eliminado).");
      } catch (dbError) {
        console.error("Error al limpiar token de DB:", dbError);
      }
    }
  }
};

// 4. CREAMOS LAS RUTAS (LOS "PEDIDOS" QUE ACEPTA EL MESERO)

// Ruta de prueba básica
app.get('/', (req, res) => {
  res.send('¡Hola! El servidor de CercaMío está funcionando 🚀');
});


// ==========================================
// RUTA 1: OBTENER LOCALES (CON GEO + OFERTAS FLASH + HISTORIAS)
// ==========================================
app.get('/api/locales', async (req, res) => {
  // Pedimos latitud, longitud y un radio (por defecto 5km)
  const { filtro, lat, lng, radio = 5000 } = req.query; 

  try {
    // Validamos que vengan las coordenadas (Vital para PostGIS)
    if (!lat || !lng) {
      return res.status(400).json({ error: "Se requiere latitud y longitud del usuario" });
    }

    let consulta = `
      SELECT 
        L.local_id, 
        L.nombre, 
        L.categoria, 
        L.plan_tipo,
        L.modo_operacion, 
        L.reputacion, 
        L.foto_url, 
        L.tipo_actividad, 
        L.rubro,
        L.hora_apertura,
        L.hora_cierre,
        L.dias_atencion,
        L.estado_manual,
        L.permite_delivery,
        L.permite_retiro,
        L.pago_efectivo,
        L.pago_transferencia,
        L.pago_tarjeta,
        ST_X(L.ubicacion::geometry) as long, 
        ST_Y(L.ubicacion::geometry) as lat,
        
        -- Distancia en metros
        ST_Distance(
          L.ubicacion::geometry, 
          ST_SetSRID(ST_MakePoint($1, $2), 4326)::geometry
        ) as distancia_metros,

        -- 1. DETECCIÓN DE OFERTA FLASH 🔥
        CASE 
          WHEN O.oferta_id IS NOT NULL THEN json_build_object(
            'titulo', O.titulo,
            'descripcion', O.descripcion,
            'fecha_fin', O.fecha_fin
          )
          ELSE NULL 
        END as oferta_flash,  -- <--- ¡AQUÍ FALTABA UNA COMA!

        -- 2. DETECCIÓN HISTORIAS (ANILLO DE COLOR 🟣)
        -- Devuelve true si hay al menos una historia vigente
        (EXISTS (
          SELECT 1 FROM historias H 
          WHERE H.local_id = L.local_id 
          AND H.fecha_expiracion > NOW()
        )) as tiene_historias

      FROM locales L
      
      -- UNIÓN INTELIGENTE (LEFT JOIN)
      LEFT JOIN ofertas_flash O ON L.local_id = O.local_id 
        AND O.activa = TRUE 
        AND O.fecha_fin > NOW()

      WHERE 
        -- Filtro Geoespacial: Solo dentro del radio
        ST_DWithin(
          L.ubicacion::geometry,
          ST_SetSRID(ST_MakePoint($1, $2), 4326)::geometry,
          $3
        )
    `;
    
    // Parámetros SQL: Longitud, Latitud, Radio
    let params = [parseFloat(lng), parseFloat(lat), parseFloat(radio)]; 
    let paramCounter = 4; 

    // Filtro de texto opcional
    if (filtro) {
      consulta += ` 
        AND (
          L.categoria ILIKE $${paramCounter} OR 
          L.tipo_actividad ILIKE $${paramCounter} OR 
          L.rubro ILIKE $${paramCounter} OR
          L.nombre ILIKE $${paramCounter}
        )
      `;
      params.push(`%${filtro}%`);
    }

    // Ordenamos: Primero cercanía
    consulta += ` ORDER BY distancia_metros ASC`;

    const respuesta = await pool.query(consulta, params);
    res.json(respuesta.rows);

  } catch (error) {
    console.error("Error en GET /api/locales:", error);
    res.status(500).send('Error en el servidor');
  }
});

// RUTA 2: Buscar productos (CORREGIDA)
app.get('/api/buscar', async (req, res) => {
  const { q, lat, lng } = req.query; 
  
  if (!q) return res.status(400).json({ error: 'Falta el término de búsqueda' });
  
  // Validamos coordenadas de nuevo. 
  // OJO: Si quieres permitir buscar sin ubicación, avísame y cambiamos la lógica.
  if (!lat || !lng) {
      return res.status(400).json({ error: "Se requiere ubicación para buscar productos cercanos" });
  }

  try {
    const consulta = `
      SELECT 
        L.local_id,
        I.inventario_id,
        C.nombre_oficial, 
        C.descripcion,
        I.precio, 
        L.nombre as tienda,
        L.categoria,
        L.rubro,
        L.tipo_actividad,
        L.reputacion,
        L.whatsapp,
        L.foto_url as foto_local,
        C.foto_url as foto_producto,
        ST_X(L.ubicacion::geometry) as long, 
        ST_Y(L.ubicacion::geometry) as lat,
        ST_Distance(
          L.ubicacion::geometry, 
          ST_SetSRID(ST_MakePoint($2, $3), 4326)::geometry
        ) as distancia_metros
      FROM inventario_local I
      JOIN catalogo_global C ON I.global_id = C.global_id
      JOIN locales L ON I.local_id = L.local_id
      WHERE 
        (C.nombre_oficial ILIKE $1 OR L.nombre ILIKE $1 OR L.rubro ILIKE $1)
        AND
        ST_DWithin(
          L.ubicacion::geometry,
          ST_SetSRID(ST_MakePoint($2, $3), 4326)::geometry,
          10000 -- Radio fijo de 10km para búsqueda de productos (ajustable)
        )
      ORDER BY distancia_metros ASC
    `;
    
    // Parámetros: [Query, Longitud, Latitud]
    const respuesta = await pool.query(consulta, [`%${q}%`, parseFloat(lng), parseFloat(lat)]);
    res.json(respuesta.rows);
  } catch (error) {
    console.error("Error en GET /api/buscar:", error);
    res.status(500).json({ error: 'Error al buscar' });
  }
});

// ==========================================
// MÓDULO DE GESTIÓN (PANEL DEL VENDEDOR)
// ==========================================

// ==========================================
// RUTA 6: VER MIS PRODUCTOS + ESTADO DE MISIONES 🏆
// ==========================================
app.get('/api/mi-negocio/productos', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. PRIMERO: Obtener datos del Local (Vital para la barra de Misiones)
    const localRes = await pool.query(
      'SELECT local_id, misiones_puntos, estado_manual, plan_tipo FROM locales WHERE usuario_id = $1',
      [usuario.id]
    );

    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const datosLocal = localRes.rows[0];

    // 2. SEGUNDO: Obtener Productos (Mejorado para aceptar productos manuales y globales)
    // Usamos LEFT JOIN para que no desaparezcan los productos que creaste manualmente
    const productosQuery = `
      SELECT 
        I.inventario_id,
        COALESCE(I.nombre, C.nombre_oficial) as nombre_oficial, -- Si tiene nombre manual, úsalo
        COALESCE(I.descripcion, C.descripcion) as descripcion,
        COALESCE(I.foto_url, C.foto_url) as foto_url,           -- Si tiene foto manual, úsala
        I.precio,
        I.stock,
        I.tipo_item
      FROM inventario_local I
      JOIN locales L ON I.local_id = L.local_id
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id
      WHERE L.usuario_id = $1
      ORDER BY I.inventario_id DESC
    `;
    
    const productosRes = await pool.query(productosQuery, [usuario.id]);

    // 3. RESPUESTA COMBINADA (Status + Items)
    res.json({
      status: {
        local_id: datosLocal.local_id,
        misiones_puntos: datosLocal.misiones_puntos || 0, // Aquí va el progreso 0-100
        estado_manual: datosLocal.estado_manual || 'AUTO',
        plan_tipo: datosLocal.plan_tipo
      },
      items: productosRes.rows
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener inventario' });
  }
});

// ==========================================
// RUTA 7: ACTUALIZAR NEGOCIO (HÍBRIDO: GPS O PRODUCTOS)
// ==========================================
app.put('/api/mi-negocio/actualizar', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  // Extraemos TODO lo posible del body
  const { 
    // Para GPS
    lat, long,
    // Para Productos
    inventario_id, nuevo_precio, nuevo_stock, nueva_foto, nuevo_nombre, nuevo_desc 
  } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // ---------------------------------------------------------
    // CASO A: ACTUALIZAR UBICACIÓN GPS (PIN DEL MAPA)
    // ---------------------------------------------------------
    if (lat && long) {
      // MAGIA POSTGIS: (Longitud primero, Latitud segundo)
      const queryGPS = `
        UPDATE locales 
        SET ubicacion = ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography
        WHERE usuario_id = $3
      `;
      await pool.query(queryGPS, [parseFloat(long), parseFloat(lat), usuario.id]);
      
      return res.json({ mensaje: 'Ubicación actualizada correctamente' });
    }

    // ---------------------------------------------------------
    // CASO B: ACTUALIZAR PRODUCTO (TU CÓDIGO ANTERIOR)
    // ---------------------------------------------------------
    if (inventario_id) {
      // 1. Actualizamos INVENTARIO LOCAL (Precio/Stock)
      const updateInventario = `
        UPDATE inventario_local 
        SET precio = $1, stock = $2
        WHERE inventario_id = $3
      `;
      await pool.query(updateInventario, [nuevo_precio, nuevo_stock, inventario_id]);

      // 2. Actualizamos CATALOGO GLOBAL (Nombre, Descripción, Foto)
      const getGlobal = await pool.query('SELECT global_id FROM inventario_local WHERE inventario_id = $1', [inventario_id]);
      
      if (getGlobal.rows.length > 0) {
        const globalId = getGlobal.rows[0].global_id;
        
        let queryCatalogo = `
          UPDATE catalogo_global 
          SET nombre_oficial = $1, descripcion = $2 
          WHERE global_id = $3
        `;
        await pool.query(queryCatalogo, [nuevo_nombre, nueva_desc, globalId]);

        if (nueva_foto) {
          await pool.query('UPDATE catalogo_global SET foto_url = $1 WHERE global_id = $2', [nueva_foto, globalId]);
        }
      }

      return res.json({ mensaje: 'Producto actualizado correctamente' });
    }

    // Si no enviaron ni coordenadas ni ID de producto
    res.status(400).json({ error: 'Datos insuficientes para actualizar' });

  } catch (error) {
    console.error("Error en update híbrido:", error);
    res.status(500).json({ error: 'Error al actualizar' });
  }
});

// ==========================================
// MÓDULO DE AUTENTICACIÓN (SEGURIDAD)
// ==========================================

// RUTA 3: REGISTRO AVANZADO (CON CÓDIGO DE SOCIO Y LEVEL UP AUTOMÁTICO)
app.post('/api/auth/registro', async (req, res) => {
  const { nombre, email, password, tipo, nombre_tienda, categoria, whatsapp, direccion, tipo_actividad, rubro, lat, long, codigo_socio } = req.body;

  if (!email || !password || !nombre || !tipo) {
    return res.status(400).json({ error: 'Faltan datos obligatorios' });
  }

  if ((tipo === 'Minorista' || tipo === 'Mayorista') && !nombre_tienda) {
    return res.status(400).json({ error: 'Los vendedores deben indicar el Nombre de la Tienda' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN'); 

    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(password, salt);

    const userQuery = `
      INSERT INTO usuarios (nombre_completo, email, password_hash, tipo, nivel_confianza)
      VALUES ($1, $2, $3, $4, 0)
      RETURNING usuario_id, nombre_completo, email, tipo
    `;
    const userRes = await client.query(userQuery, [nombre, email, passwordEncriptada, tipo]);
    const nuevoUsuario = userRes.rows[0];

    // Variable para guardar el ID del socio si se usó código
    let socioIdEncontrado = null; 

    if (tipo === 'Minorista' || tipo === 'Mayorista') {
      
      if (codigo_socio) {
        const socioRes = await client.query('SELECT socio_id, usuario_id FROM socios WHERE codigo_referido = $1', [codigo_socio]);
        
        if (socioRes.rows.length > 0) {
          const datosSocio = socioRes.rows[0];
          
          if (datosSocio.usuario_id === nuevoUsuario.usuario_id) {
             console.warn("Intento de auto-referencia en registro.");
          } else {
             socioIdEncontrado = datosSocio.socio_id; 
          }
        } else {
          throw new Error(`El código de socio "${codigo_socio}" no existe. Verifica si lo escribiste bien.`);
        }
      }

      const latitudFinal = lat || -45.86;
      const longitudFinal = long || -67.48;

      let fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/3081/3081559.png'; 
      if (tipo_actividad === 'SERVICIO') {
          fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/1063/1063376.png'; 
      }

      const localQuery = `
        INSERT INTO locales 
        (usuario_id, nombre, categoria, ubicacion, whatsapp, permite_retiro, permite_delivery, direccion_fisica, tipo_actividad, rubro, foto_url, referido_por_socio_id)
        VALUES ($1, $2, $3, ST_SetSRID(ST_MakePoint($4, $5), 4326), $6, $7, $8, $9, $10, $11, $12, $13)
      `;
    
      const permiteDelivery = tipo_actividad === 'PRODUCTO'; 
    
      await client.query(localQuery, [
        nuevoUsuario.usuario_id, 
        nombre_tienda, 
        categoria || 'General', 
        longitudFinal, 
        latitudFinal,
        whatsapp,
        true, 
        permiteDelivery,
        direccion || 'Sin dirección',
        tipo_actividad || 'PRODUCTO',
        rubro || 'General',
        fotoDefecto,
        socioIdEncontrado 
      ]);
    }

    await client.query('COMMIT'); 

    // --- NUEVO: SI HUBO SOCIO, RECALCULAMOS SU NIVEL AUTOMÁTICAMENTE ---
    if (socioIdEncontrado) {
       // Ejecutamos en segundo plano (sin await para no demorar la respuesta)
       actualizarNivelSocio(socioIdEncontrado);
    }
    // -------------------------------------------------------------------

    res.json({ mensaje: 'Registro exitoso', usuario: nuevoUsuario });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    if (error.message.includes("código de socio")) {
        return res.status(400).json({ error: error.message });
    }
    if (error.code === '23505') {
      return res.status(400).json({ error: 'El email ya está registrado' });
    }
    res.status(500).json({ error: 'Error en el servidor al registrar' });
  } finally {
    client.release();
  }
});

// RUTA 4: LOGIN (INICIAR SESIÓN)
// RUTA 4: LOGIN (CORREGIDA - AHORA ENVÍA LA FOTO)
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Buscar al USUARIO
    const userQuery = 'SELECT * FROM usuarios WHERE email = $1';
    const userRes = await pool.query(userQuery, [email]);

    if (userRes.rows.length === 0) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }
    const usuario = userRes.rows[0];

    // 2. Validar Password
    const validPassword = await bcrypt.compare(password, usuario.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Contraseña incorrecta' });
    }

    // 3. Buscar Perfil Profesional
    const localQuery = 'SELECT * FROM locales WHERE usuario_id = $1';
    const localRes = await pool.query(localQuery, [usuario.usuario_id]);
    
    const tienePerfilProfesional = localRes.rows.length > 0;
    const datosLocal = tienePerfilProfesional ? localRes.rows[0] : null;

    // 4. Generar Token
    const token = jwt.sign(
      { id: usuario.usuario_id, tipo: usuario.tipo }, 
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // 5. Responder (AQUÍ ESTABA EL FALTANTE)
    res.json({ 
      mensaje: 'Bienvenido',
      token: token,
      usuario: { 
        id: usuario.usuario_id, 
        nombre: usuario.nombre_completo,
        email: usuario.email,
        tipo: usuario.tipo,
        foto_url: usuario.foto_url // <--- ¡ESTA ES LA LÍNEA MÁGICA QUE FALTABA! 📸
      },
      perfil_profesional: tienePerfilProfesional ? {
        local_id: datosLocal.local_id,
        nombre_fantasia: datosLocal.nombre,
        tipo_actividad: datosLocal.tipo_actividad,
        foto_url: datosLocal.foto_url
      } : null
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error de login' });
  }
});

// RUTA 8: MIS COMPRAS (HISTORIAL)
app.get('/api/transaccion/mis-compras', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // Traemos: Qué compró, A quién, Cuánto pagó, Cuándo y el Estado.
    const consulta = `
      SELECT 
        T.transaccion_id,
        T.fecha_operacion,
        T.estado,
        T.cantidad,
        T.monto_total,
        T.tipo_entrega,
        T.aviso_llegada,
        C.nombre_oficial as producto,
        C.foto_url,
        L.nombre as tienda,
        L.whatsapp,
        L.local_id, -- Necesario para ir al perfil
        CASE WHEN CAL.transaccion_id IS NOT NULL THEN true ELSE false END as ya_califico
      FROM transacciones_p2p T
      JOIN locales L ON T.vendedor_id = L.usuario_id
      JOIN catalogo_global C ON T.producto_global_id = C.global_id
      LEFT JOIN calificaciones CAL ON T.transaccion_id = CAL.transaccion_id -- <--- EL TRUCO
      WHERE T.comprador_id = $1
      ORDER BY T.fecha_operacion DESC
    `;
    
    const respuesta = await pool.query(consulta, [usuario.id]);
    res.json(respuesta.rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener historial' });
  }
});

// ==========================================
// RUTA 5: COMPRA MÚLTIPLE (CARRITO) - CON SNAPSHOT, CUPONES Y SOCIOS 🤝
// ==========================================
app.post('/api/transaccion/comprar', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { local_id, items, tipo_entrega, usar_cupon } = req.body;
  
  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    const comprador_id = usuario.id;
    const nombreComprador = usuario.nombre || "Un cliente"; 

    // 1. Generamos UUID para agrupar la orden
    const compraUuid = crypto.randomUUID(); 

    await client.query('BEGIN');

    // 2. Buscamos al vendedor Y DATOS DEL SOCIO (PADRINO)
    // --- ACTUALIZACIÓN: Traemos referido_por_socio_id y porcentaje_ganancia ---
    const localRes = await client.query(`
      SELECT 
        L.usuario_id, 
        L.referido_por_socio_id,
        S.porcentaje_ganancia -- El nivel del socio (5%, 7.5%, etc)
      FROM locales L
      LEFT JOIN socios S ON L.referido_por_socio_id = S.socio_id
      WHERE L.local_id = $1
    `, [local_id]);

    if (localRes.rows.length === 0) throw new Error('Local no encontrado');
    
    const vendedor_id = localRes.rows[0].usuario_id;
    const socioId = localRes.rows[0].referido_por_socio_id; // ID del Socio
    // Si tiene socio, usamos su porcentaje de la BD, si no, 0. (Default 5.00 si es null)
    const porcentajeSocio = socioId ? parseFloat(localRes.rows[0].porcentaje_ganancia || 5.00) : 0;

    if (comprador_id === vendedor_id) {
      throw new Error('No puedes realizar compras en tu propio negocio.');
    }

    // ============================================================
    // 3. LÓGICA DE CANJE DE CUPÓN 🎟️ (Sin cambios, se mantiene tu lógica)
    // ============================================================
    let infoPremio = ""; 
    let tituloNotif = "¡Nueva Orden Entrante! 📦";

    if (usar_cupon === true) {
      const checkCupón = await client.query(
        'SELECT cupones_disponibles FROM progreso_fidelizacion WHERE usuario_id = $1 AND local_id = $2 FOR UPDATE',
        [comprador_id, local_id]
      );

      if (checkCupón.rows.length > 0 && checkCupón.rows[0].cupones_disponibles > 0) {
        await client.query(
          'UPDATE progreso_fidelizacion SET cupones_disponibles = cupones_disponibles - 1 WHERE usuario_id = $1 AND local_id = $2',
          [comprador_id, local_id]
        );
        
        const premioRes = await client.query('SELECT premio_descripcion FROM config_fidelizacion WHERE local_id = $1', [local_id]);
        const nombrePremio = premioRes.rows[0]?.premio_descripcion || "Premio Sorpresa";
        
        infoPremio = `\n🎁 DEBES ENTREGAR PREMIO: ${nombrePremio}`;
        tituloNotif = "¡Venta con PREMIO CANJEADO! 🎁";

        // Insertamos el premio ($0 costo, $0 comisión)
        const insertPremio = `
            INSERT INTO transacciones_p2p 
            (comprador_id, vendedor_id, producto_global_id, cantidad, monto_total, estado, tipo_entrega, compra_uuid, nombre_snapshot, foto_snapshot, comision_plataforma)
            VALUES ($1, $2, NULL, 1, 0, 'APROBADO', $3, $4, $5, $6, 0)
        `;
        const fotoRegalo = "https://cdn-icons-png.flaticon.com/512/4213/4213958.png"; 

        await client.query(insertPremio, [
            comprador_id, vendedor_id, tipo_entrega, compraUuid,
            `🎁 PREMIO: ${nombrePremio}`, fotoRegalo
        ]);
        
      } else {
        throw new Error("Error: No tienes cupones disponibles.");
      }
    }

    // ============================================================
    // 4. ITEMS PAGADOS (Con cálculo de comisión individual) 💰
    // ============================================================
    let montoTotalPedido = 0; 
    let comisionTotalPlataforma = 0; // Acumulador para saber cuánto ganamos nosotros
    let ultimoTransaccionId = null;  // Para vincular el historial

    for (const item of items) {
        // A. Validar Stock
        const stockQuery = `SELECT stock, global_id, tipo_item, nombre, foto_url FROM inventario_local WHERE inventario_id = $1 FOR UPDATE`;
        const stockRes = await client.query(stockQuery, [item.inventario_id]);
        
        if (stockRes.rows.length === 0) throw new Error(`Producto no disponible`);
        const datosReales = stockRes.rows[0];

        if (datosReales.tipo_item === 'PRODUCTO_STOCK') {
            if (datosReales.stock < item.cantidad) throw new Error(`Stock insuficiente para ${datosReales.nombre}`);
            await client.query('UPDATE inventario_local SET stock = stock - $1 WHERE inventario_id = $2', [item.cantidad, item.inventario_id]);
        }

        // B. Cálculos Monetarios
        const totalItem = item.precio * item.cantidad;
        montoTotalPedido += totalItem;

        // Calculamos el 1% de CercaMío para este item específico
        const comisionItem = Math.round((totalItem * 0.01) * 100) / 100;
        comisionTotalPlataforma += comisionItem;

        // C. Insertar Transacción (Agregamos comision_plataforma)
        const insertTx = `
            INSERT INTO transacciones_p2p 
            (comprador_id, vendedor_id, producto_global_id, cantidad, monto_total, estado, tipo_entrega, compra_uuid, nombre_snapshot, foto_snapshot, comision_plataforma)
            VALUES ($1, $2, $3, $4, $5, 'APROBADO', $6, $7, $8, $9, $10)
            RETURNING transaccion_id
        `;
        
        const txRes = await client.query(insertTx, [
            comprador_id, 
            vendedor_id, 
            datosReales.global_id, 
            item.cantidad, 
            totalItem, 
            tipo_entrega,
            compraUuid,
            datosReales.nombre,   
            datosReales.foto_url,
            comisionItem // <--- Guardamos cuánto ganamos en este item
        ]);

        ultimoTransaccionId = txRes.rows[0].transaccion_id;
    }

    // ============================================================
    // 5. REPARTO DE GANANCIAS AL SOCIO (REVENUE SHARE) 🤝
    // ============================================================
    if (socioId && comisionTotalPlataforma > 0) {
       
       // Ganancia Socio = Nuestra Ganancia * (Su Porcentaje / 100)
       // Ejemplo: Ganamos $100 * (5% del socio) = $5 para él.
       const gananciaSocio = Math.round((comisionTotalPlataforma * (porcentajeSocio / 100)) * 100) / 100;

       if (gananciaSocio > 0) {
         // A. Acreditar en Billetera
         await client.query(`UPDATE socios SET saldo_acumulado = saldo_acumulado + $1 WHERE socio_id = $2`, [gananciaSocio, socioId]);

         // B. Auditoría
         await client.query(`
            INSERT INTO historial_comisiones 
            (socio_id, transaccion_origen_id, local_origen_id, monto_comision, porcentaje_aplicado, base_calculo_plataforma)
            VALUES ($1, $2, $3, $4, $5, $6)
         `, [socioId, ultimoTransaccionId, local_id, gananciaSocio, porcentajeSocio, comisionTotalPlataforma]);
         
         console.log(`✅ Socio #${socioId} ganó $${gananciaSocio} (Base CercaMío: $${comisionTotalPlataforma})`);
       }
    }

    await client.query('COMMIT');

    // 6. Notificar
    const mensajeVendedor = `${nombreComprador} realizó un pedido de ${items.length} items pagados. Total: $${montoTotalPedido}.${infoPremio}`;
    enviarNotificacion(vendedor_id, tituloNotif, mensajeVendedor);

    // Opcional: Notificar al Socio si ganó algo
    if (socioId) {
        const sUser = await pool.query('SELECT usuario_id FROM socios WHERE socio_id = $1', [socioId]);
        if (sUser.rows.length > 0) {
           // enviarNotificacion(sUser.rows[0].usuario_id, "¡Kaching! 🤑", "Sumaste saldo por ventas de tus referidos.");
        }
    }

    res.json({ mensaje: 'Compra realizada con éxito', orden_id: compraUuid });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(400).json({ error: error.message || 'Error en la transacción' });
  } finally {
    client.release();
  }
});

// RUTA 9: CONVERTIRSE EN VENDEDOR (CON CÓDIGO DE SOCIO Y LEVEL UP AUTOMÁTICO)
app.post('/api/auth/convertir-vendedor', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { nombre_tienda, categoria, whatsapp, direccion, tipo_actividad, rubro, lat, long, codigo_socio } = req.body;

  const client = await pool.connect();
  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    await client.query('BEGIN');

    let socioIdEncontrado = null;

    if (codigo_socio) {
      const socioRes = await client.query('SELECT socio_id, usuario_id FROM socios WHERE codigo_referido = $1', [codigo_socio]);
      
      if (socioRes.rows.length > 0) {
        const datosSocio = socioRes.rows[0];
        
        if (datosSocio.usuario_id === usuario.id) {
           throw new Error("¡No puedes usar tu propio código de socio para tu tienda!");
        }
        
        socioIdEncontrado = datosSocio.socio_id;
      } else {
        throw new Error(`El código de socio "${codigo_socio}" no es válido.`);
      }
    }

    const nuevoTipoUsuario = (tipo_actividad === 'SERVICIO') ? 'Profesional' : categoria;

    await client.query(
      'UPDATE usuarios SET tipo = $1 WHERE usuario_id = $2',
      [nuevoTipoUsuario, usuario.id]
    );

    const latitudFinal = lat || -45.86;
    const longitudFinal = long || -67.48;

    let fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/3081/3081559.png';
    if (tipo_actividad === 'SERVICIO') {
        fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/1063/1063376.png';
    }

    const localQuery = `
      INSERT INTO locales 
      (usuario_id, nombre, categoria, ubicacion, whatsapp, permite_retiro, permite_delivery, direccion_fisica, tipo_actividad, rubro, foto_url, referido_por_socio_id)
      VALUES ($1, $2, $3, ST_SetSRID(ST_MakePoint($4, $5), 4326), $6, TRUE, FALSE, $7, $8, $9, $10, $11)
    `;
    
    await client.query(localQuery, [
      usuario.id, 
      nombre_tienda, 
      categoria, 
      longitudFinal, 
      latitudFinal,  
      whatsapp,
      direccion,
      tipo_actividad || 'PRODUCTO',
      rubro || 'General',
      fotoDefecto,
      socioIdEncontrado
    ]);

    await client.query('COMMIT');

    // --- NUEVO: SI HUBO SOCIO, RECALCULAMOS SU NIVEL ---
    if (socioIdEncontrado) {
       actualizarNivelSocio(socioIdEncontrado);
    }
    // ---------------------------------------------------

    res.json({ mensaje: '¡Felicidades! Perfil profesional creado y vinculado.' });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    
    if (error.message.includes("código") || error.message.includes("propio")) {
       return res.status(400).json({ error: error.message });
    }
    
    res.status(500).json({ error: 'Error al actualizar cuenta' });
  } finally {
    client.release();
  }
});

// ==========================================
// RUTA 10: VER VENTAS ENTRANTES (CON AVISO DE LLEGADA 🚗)
// ==========================================
app.get('/api/mi-negocio/ventas', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    const consulta = `
      SELECT 
        T.compra_uuid,
        MAX(T.fecha_operacion) as fecha,
        MAX(T.estado) as estado_global,
        MAX(T.tipo_entrega) as tipo_entrega,
        
        -- NUEVO: Detecta si el cliente avisó que está viniendo
        -- Si al menos un ítem de la orden tiene el aviso, devuelve true
        BOOL_OR(T.aviso_llegada) as aviso_llegada,

        SUM(T.monto_total) as total_orden,
        SUM(T.cantidad) as total_items,
        U.nombre_completo as comprador,
        U.usuario_id as comprador_id,
        
        json_agg(json_build_object(
            'nombre', COALESCE(T.nombre_snapshot, C.nombre_oficial, 'Producto Manual'),
            'cantidad', T.cantidad,
            'foto', COALESCE(T.foto_snapshot, C.foto_url),
            'transaccion_id', T.transaccion_id,
            'precio_unitario', (T.monto_total / NULLIF(T.cantidad, 0)) 
        )) as productos

      FROM transacciones_p2p T
      JOIN usuarios U ON T.comprador_id = U.usuario_id
      LEFT JOIN catalogo_global C ON T.producto_global_id = C.global_id
      
      WHERE T.vendedor_id = $1
      GROUP BY T.compra_uuid, U.usuario_id, U.nombre_completo
      ORDER BY MAX(T.fecha_operacion) DESC
    `;
    
    const respuesta = await pool.query(consulta, [usuario.id]);
    res.json(respuesta.rows);

  } catch (error) {
    console.error("Error en ventas:", error);
    res.status(500).json({ error: 'Error al obtener ventas' });
  }
});

// ==========================================
// RUTA 11: CAMBIAR ESTADO (CON LÓGICA ANTI-DOBLE BENEFICIO 🛡️)
// ==========================================
app.put('/api/mi-negocio/ventas/estado', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { compra_uuid, nuevo_estado } = req.body; 

  try {
    const usuario = jwt.verify(token, JWT_SECRET); // Vendedor

    // 1. Buscamos el local_id
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const local_id = localRes.rows[0].local_id;

    // 2. Actualizamos estado
    const updateQuery = `
      UPDATE transacciones_p2p 
      SET estado = $1 
      WHERE compra_uuid = $2 AND vendedor_id = $3
      RETURNING comprador_id;
    `;
    const result = await pool.query(updateQuery, [nuevo_estado, compra_uuid, usuario.id]);

    if (result.rowCount === 0) {
      return res.status(403).json({ error: 'No se pudo actualizar la orden' });
    }

    const compradorId = result.rows[0].comprador_id;

    // 3. PREPARAMOS NOTIFICACIÓN BASE
    let tituloNotif = "Actualización de pedido";
    let mensajeNotif = `Tu pedido está: ${nuevo_estado}`;

    if (nuevo_estado === 'EN CAMINO') {
      mensajeNotif = "¡Tu pedido está en camino! 🚚";
    } else if (nuevo_estado === 'LISTO') {
      mensajeNotif = "¡Listo para retirar! Te esperamos en el local 🛍️";
    }

    // ============================================================
    // 4. LÓGICA DE FIDELIZACIÓN (SOLO AL ENTREGAR) 🎟️
    // ============================================================
    if (nuevo_estado === 'ENTREGADO') {
      tituloNotif = "Pedido Entregado";
      
      // A. VERIFICAMOS SI ESTA ORDEN FUE UN CANJE DE PREMIO
      // Buscamos si hay algún item en esta orden que sea un premio (producto_global_id NULL)
      const checkCanje = await pool.query(
        'SELECT 1 FROM transacciones_p2p WHERE compra_uuid = $1 AND producto_global_id IS NULL',
        [compra_uuid]
      );
      
      const esCanje = checkCanje.rows.length > 0;

      if (esCanje) {
        // --- CASO A: ES UN CANJE (NO SUMA PUNTOS) ---
        mensajeNotif = "¡Esperamos que disfrutes tu premio! 🎁 Gracias por tu fidelidad. Te esperamos en la próxima para seguir sumando.";
      
      } else {
        // --- CASO B: ES COMPRA NORMAL (INTENTA SUMAR PUNTOS) ---
        mensajeNotif = "Gracias por tu compra. ¡Disfrútalo! ⭐";

        // B.1 Buscamos reglas activas
        const rulesRes = await pool.query(
          'SELECT meta_sellos, monto_minimo, premio_descripcion FROM config_fidelizacion WHERE local_id = $1 AND estado = TRUE',
          [local_id]
        );

        if (rulesRes.rows.length > 0) {
          const reglas = rulesRes.rows[0];

          // B.2 Calculamos total ($)
          const totalRes = await pool.query(
            'SELECT SUM(monto_total) as total FROM transacciones_p2p WHERE compra_uuid = $1',
            [compra_uuid]
          );
          const totalCompra = parseFloat(totalRes.rows[0].total || 0);

          // B.3 Verificamos mínimo
          if (totalCompra >= parseFloat(reglas.monto_minimo)) {
            
            // B.4 SUMAR SELLO
            const progresoQuery = `
              INSERT INTO progreso_fidelizacion (usuario_id, local_id, sellos_acumulados, cupones_disponibles)
              VALUES ($1, $2, 1, 0)
              ON CONFLICT (usuario_id, local_id)
              DO UPDATE SET sellos_acumulados = progreso_fidelizacion.sellos_acumulados + 1
              RETURNING sellos_acumulados, cupones_disponibles;
            `;
            const progresoRes = await pool.query(progresoQuery, [compradorId, local_id]);
            
            let { sellos_acumulados } = progresoRes.rows[0];

            // B.5 ¿LLEGÓ A LA META?
            if (sellos_acumulados >= reglas.meta_sellos) {
              await pool.query(`
                UPDATE progreso_fidelizacion 
                SET sellos_acumulados = 0, 
                    cupones_disponibles = cupones_disponibles + 1 
                WHERE usuario_id = $1 AND local_id = $2
              `, [compradorId, local_id]);

              tituloNotif = "¡PREMIO GANADO! 🏆";
              mensajeNotif = `¡Completaste la tarjeta! Ganaste: ${reglas.premio_descripcion}. Úsalo en tu próxima compra.`;
            } else {
              tituloNotif = "¡Sumaste un Sello! 🎟️";
              mensajeNotif = `Llevas ${sellos_acumulados}/${reglas.meta_sellos} para ganar: ${reglas.premio_descripcion}.`;
            }
          }
        }
      }
    }
    // ============================================================

    enviarNotificacion(compradorId, tituloNotif, mensajeNotif);
    res.json({ mensaje: 'Estado actualizado', notificacion: mensajeNotif });

  } catch (error) {
    console.error("Error update estado:", error);
    res.status(500).json({ error: 'Error al actualizar estado' });
  }
});

// RUTA 12: SUBIR IMAGEN A LA NUBE
// 'imagen' es el nombre del campo que enviará el celular
app.post('/api/upload', upload.single('imagen'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No se envió ninguna imagen' });
    }

    // 1. Subimos el archivo a Cloudinary
    const resultado = await cloudinary.uploader.upload(req.file.path);

    // 2. Devolvemos la URL segura (https) al celular
    res.json({ url: resultado.secure_url });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al subir imagen' });
  }
});

// RUTA 13: CREAR PRODUCTO/SERVICIO (ALTA)
app.post('/api/mi-negocio/crear-item', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  // Recibimos todos los datos del formulario
  const { 
    nombre, 
    descripcion, 
    precio, 
    foto_url, 
    tipo_item, // 'PRODUCTO_STOCK', 'PRODUCTO_PEDIDO', 'SERVICIO'
    stock_inicial 
  } = req.body;

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    await client.query('BEGIN');

    // 1. Buscar el ID del local del usuario
    const localRes = await client.query('SELECT local_id, categoria FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) throw new Error('No tienes un local registrado');
    const localId = localRes.rows[0].local_id;
    const categoriaLocal = localRes.rows[0].categoria; // Para saber la categoría del producto

    // 2. Insertar en CATALOGO GLOBAL
    // Usamos un código de barras ficticio aleatorio para evitar choques por ahora
    const randomEAN = Math.floor(Math.random() * 1000000000).toString();
    
    const catalogoQuery = `
      INSERT INTO catalogo_global (nombre_oficial, descripcion, foto_url, categoria, codigo_barras)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING global_id
    `;
    // Usamos la categoría del local como categoría del producto por defecto
    const catRes = await client.query(catalogoQuery, [nombre, descripcion, foto_url, categoriaLocal, randomEAN]);
    const globalId = catRes.rows[0].global_id;

    // 3. Insertar en INVENTARIO LOCAL
    // Si es Servicio o Por Pedido, el stock es irrelevante (ponemos 999 o null), si es stock fisico usamos el dato.
    let stockFinal = stock_inicial;
    if (tipo_item !== 'PRODUCTO_STOCK') {
        stockFinal = 9999; // Stock infinito lógico
    }

    const invQuery = `
      INSERT INTO inventario_local (local_id, global_id, precio, stock, tipo_item)
      VALUES ($1, $2, $3, $4, $5)
    `;
    await client.query(invQuery, [localId, globalId, precio, stockFinal, tipo_item]);

    await client.query('COMMIT');
    res.json({ mensaje: 'Ítem creado exitosamente' });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ error: 'Error al crear ítem' });
  } finally {
    client.release();
  }
});

// RUTA 14: ELIMINAR ÍTEM
app.delete('/api/mi-negocio/eliminar/:id', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  const inventario_id = req.params.id;

  try {
    // Borramos del inventario local
    // (Nota: Si ya tiene ventas registradas, esto podría dar error de llave foránea.
    // Lo ideal sería un "Soft Delete" (activo = false), pero para el MVP usamos Delete real).
    const deleteQuery = 'DELETE FROM inventario_local WHERE inventario_id = $1';
    await pool.query(deleteQuery, [inventario_id]);

    res.json({ mensaje: 'Ítem eliminado' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'No se puede eliminar (quizás tiene ventas asociadas)' });
  }
});

// ==========================================
// RUTA 15: CALIFICAR VENDEDOR (FOTO + BLINDAJE SEGURIDAD)
// ==========================================
app.post('/api/transaccion/calificar', upload.single('foto'), async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  // Datos del formulario
  const { transaccion_id, puntaje, comentario } = req.body;
  // Foto de Cloudinary (si existe)
  const fotoUrl = req.file ? req.file.path : null;

  try {
    // Decodificamos el token para saber quién intenta calificar
    const token = authHeader.split(' ')[1];
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. SEGURIDAD: Buscamos quién es el vendedor de esta transacción
    const txQuery = 'SELECT vendedor_id FROM transacciones_p2p WHERE transaccion_id = $1';
    const txRes = await pool.query(txQuery, [transaccion_id]);

    if (txRes.rows.length === 0) {
      return res.status(404).json({ error: 'Transacción no encontrada' });
    }

    const vendedor_id = txRes.rows[0].vendedor_id;

    // 2. BLINDAJE: Comparamos IDs
    // Si el usuario logueado (usuario.id) es igual al vendedor (vendedor_id), BLOQUEAMOS.
    if (usuario.id === vendedor_id) {
       return res.status(403).json({ error: '⚠️ No puedes calificar tu propia venta. Acción bloqueada.' });
    }

    // 3. INSERTAR (Solo si pasó el blindaje)
    await pool.query(
      'INSERT INTO calificaciones (transaccion_id, puntaje, comentario, foto_url) VALUES ($1, $2, $3, $4)',
      [transaccion_id, puntaje, comentario, fotoUrl]
    );

    // 4. ACTUALIZAR ESTADO DE TRANSACCIÓN (Opcional, para que el frontend sepa que ya calificó)
    // Esto es útil para deshabilitar el botón "Calificar" en el historial
    // await pool.query("UPDATE transacciones_p2p SET estado = 'CALIFICADO' WHERE transaccion_id = $1", [transaccion_id]);

    res.json({ mensaje: '¡Gracias por tu opinión!' });

  } catch (error) {
    console.error(error);
    // Código de error Postgres para "Duplicate Key" (si intenta calificar 2 veces lo mismo)
    if (error.code === '23505') {
        return res.status(400).json({ error: 'Ya calificaste esta compra anteriormente.' });
    }
    res.status(500).json({ error: 'Error al guardar la calificación' });
  }
});

// RUTA 16: PERFIL PÚBLICO (CON FIDELIZACIÓN 🎟️)
app.get('/api/perfil-publico/:id', async (req, res) => {
  const local_id = req.params.id;
  
  // Leemos el token para saber si es favorito (Opcional)
  const authHeader = req.headers['authorization'];
  let usuarioId = null;
  if (authHeader) {
    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      usuarioId = decoded.id;
    } catch(e) {}
  }

  try {
    // 1. DATOS DEL LOCAL
    const queryLocal = `
      SELECT 
        usuario_id, local_id, nombre, categoria, rubro, foto_url, reputacion, 
        direccion_fisica, whatsapp, hora_apertura, hora_cierre, dias_atencion,
        estado_manual, permite_delivery, permite_retiro,
        pago_efectivo, pago_transferencia, pago_tarjeta
      FROM locales 
      WHERE local_id = $1
    `;
    
    const localRes = await pool.query(queryLocal, [local_id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });

    // 2. PRODUCTOS (HÍBRIDO: MANUAL + GLOBAL)
    const queryProductos = `
      SELECT 
        I.inventario_id, 
        COALESCE(I.nombre, C.nombre_oficial) as nombre_oficial, 
        COALESCE(I.foto_url, C.foto_url) as foto_url, 
        COALESCE(I.descripcion, C.descripcion) as descripcion,
        I.precio, 
        I.stock, 
        I.tipo_item
      FROM inventario_local I 
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id 
      WHERE I.local_id = $1
    `;

    const prodRes = await pool.query(queryProductos, [local_id]);

    // 3. RESEÑAS
    const reviewRes = await pool.query(`
      SELECT 
        C.puntaje, 
        C.comentario,
        C.foto_url,
        TO_CHAR(C.fecha_resena, 'DD/MM/YYYY') as fecha 
      FROM calificaciones C 
      JOIN transacciones_p2p T ON C.transaccion_id = T.transaccion_id 
      WHERE T.vendedor_id = (SELECT usuario_id FROM locales WHERE local_id = $1)
      ORDER BY C.fecha_resena DESC 
      LIMIT 10
    `, [local_id]);

    // 4. FAVORITO Y PROPIEDAD
    let esFavorito = false;
    let esPropio = false;
    
    if (usuarioId) {
      const favCheck = await pool.query('SELECT 1 FROM favoritos WHERE usuario_id = $1 AND local_id = $2', [usuarioId, local_id]);
      esFavorito = favCheck.rows.length > 0;

      // CHEQUEO DE PROPIEDAD
      if (localRes.rows[0].usuario_id === usuarioId) {
         esPropio = true;
      }
    }

    // 5. FIDELIZACIÓN (NUEVO AGREGADO 🎟️)
    let datosFidelidad = null;
    
    const queryFidelidad = `
      SELECT 
        C.meta_sellos,
        C.premio_descripcion,
        C.monto_minimo,
        C.estado as es_activo, -- <--- AHORA TRAEMOS EL ESTADO
        COALESCE(P.sellos_acumulados, 0) as mis_sellos,
        COALESCE(P.cupones_disponibles, 0) as mis_cupones
      FROM config_fidelizacion C
      LEFT JOIN progreso_fidelizacion P 
        ON C.local_id = P.local_id AND P.usuario_id = $2
      WHERE C.local_id = $1 -- <--- QUITAMOS EL FILTRO "AND estado = TRUE"
    `;
    
    const fidelidadRes = await pool.query(queryFidelidad, [local_id, usuarioId]);
    
    if (fidelidadRes.rows.length > 0) {
      datosFidelidad = fidelidadRes.rows[0];
    }

    // RESPUESTA FINAL
    res.json({
      info: localRes.rows[0],
      productos: prodRes.rows,
      reseñas: reviewRes.rows,
      es_favorito: esFavorito,
      es_propio: esPropio,
      fidelizacion: datosFidelidad // <--- Objeto con reglas y sellos (o null)
    });

  } catch (error) {
    console.error("Error en perfil público:", error);
    res.status(500).json({ error: 'Error al cargar perfil' });
  }
});

// ==========================================
// RUTA 17: TOGGLE FAVORITO (CON MISIONES ESCALONADAS 🏆)
// ==========================================
app.post('/api/favoritos/toggle', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  const { local_id } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. Toggle Favorito (Estándar)
    const check = await pool.query(
      'SELECT favorito_id FROM favoritos WHERE usuario_id = $1 AND local_id = $2', 
      [usuario.id, local_id]
    );

    let accion = '';
    if (check.rows.length > 0) {
      await pool.query('DELETE FROM favoritos WHERE usuario_id = $1 AND local_id = $2', [usuario.id, local_id]);
      accion = 'borrado';
    } else {
      await pool.query('INSERT INTO favoritos (usuario_id, local_id) VALUES ($1, $2)', [usuario.id, local_id]);
      accion = 'agregado';
    }

    // =================================================================
    // 2. LÓGICA DE MISIONES ESCALONADAS (20 -> 60 -> 100)
    // =================================================================
    if (accion === 'agregado') {
        // A. Anti-Fraude: Solo cuentan usuarios que compraron alguna vez
        const checkCompras = await pool.query(
            'SELECT 1 FROM transacciones_p2p WHERE comprador_id = $1 AND estado = $2 LIMIT 1', 
            [usuario.id, 'APROBADO']
        );

        if (checkCompras.rows.length > 0) {
            // B. Sumar Punto
            const updateRes = await pool.query(
                'UPDATE locales SET misiones_puntos = misiones_puntos + 1 WHERE local_id = $1 RETURNING misiones_puntos, usuario_id', 
                [local_id]
            );
            
            const puntos = updateRes.rows[0].misiones_puntos;
            const idVendedor = updateRes.rows[0].usuario_id;
            
            // C. Evaluar Escalones de Premios 🎁
            let mesesRegalo = 0;
            let mensajePremio = "";

            if (puntos === 20) {
                mesesRegalo = 1;
                mensajePremio = "¡Nivel 1 Completado! (20 Fans). Ganaste 1 Mes Premium GRATIS.";
            } else if (puntos === 60) {
                mesesRegalo = 2;
                mensajePremio = "¡Nivel 2 Completado! (60 Fans). Ganaste 2 Meses Premium GRATIS.";
            } else if (puntos === 100) {
                mesesRegalo = 3;
                mensajePremio = "¡Nivel MÁXIMO Completado! (100 Fans). Ganaste 3 Meses Premium GRATIS.";
            }

            // D. Si alcanzó un hito, aplicamos el premio
            if (mesesRegalo > 0) {
                // Query dinámica para sumar X meses
                const intervaloSQL = `${mesesRegalo} months`; // Ej: '2 months'
                
                await pool.query(`
                    UPDATE locales 
                    SET 
                      plan_tipo = 'PREMIUM',
                      plan_vencimiento = CASE 
                        WHEN plan_vencimiento > NOW() THEN plan_vencimiento + INTERVAL '${intervaloSQL}' 
                        ELSE NOW() + INTERVAL '${intervaloSQL}' 
                      END
                    WHERE local_id = $1
                `, [local_id]);

                console.log(`🏆 Local ${local_id} alcanzó ${puntos} puntos. Premio: ${mesesRegalo} meses.`);
                
                // Notificar al Vendedor
                enviarNotificacion(idVendedor, "¡Misión Cumplida! 🚀", mensajePremio);
            }
        }
    }
    // =================================================================

    res.json({ 
        estado: accion === 'agregado', 
        mensaje: accion === 'agregado' ? 'Guardado en favoritos' : 'Eliminado de favoritos' 
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar favorito' });
  }
});

// RUTA 18: LISTAR MIS FAVORITOS
app.get('/api/favoritos/mis-guardados', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    const consulta = `
      SELECT L.local_id, L.nombre, L.categoria, L.rubro, L.foto_url, L.reputacion
      FROM favoritos F
      JOIN locales L ON F.local_id = L.local_id
      WHERE F.usuario_id = $1
      ORDER BY F.fecha_agregado DESC
    `;
    const respuesta = await pool.query(consulta, [usuario.id]);
    res.json(respuesta.rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener favoritos' });
  }
});

// RUTA 19: ANALYTICS (TABLERO FINANCIERO)
app.get('/api/mi-negocio/analytics', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. KPI PRINCIPALES (Totales generales)
    // Usamos COALESCE para que devuelva 0 si es null
    const kpiQuery = `
      SELECT 
        COALESCE(SUM(monto_total), 0) as ingresos_totales,
        COUNT(*) as cantidad_ventas,
        COALESCE(AVG(monto_total), 0) as ticket_promedio
      FROM transacciones_p2p 
      WHERE vendedor_id = $1 AND estado != 'CANCELADO'
    `;
    const kpiRes = await pool.query(kpiQuery, [usuario.id]);

    // 2. PRODUCTOS MÁS VENDIDOS (Ranking)
    const topQuery = `
      SELECT 
        C.nombre_oficial, 
        SUM(T.cantidad) as total_unidades,
        SUM(T.monto_total) as total_dinero
      FROM transacciones_p2p T
      JOIN catalogo_global C ON T.producto_global_id = C.global_id
      WHERE T.vendedor_id = $1 AND T.estado != 'CANCELADO'
      GROUP BY C.nombre_oficial
      ORDER BY total_unidades DESC
      LIMIT 5
    `;
    const topRes = await pool.query(topQuery, [usuario.id]);

    res.json({
      kpis: kpiRes.rows[0],
      top_productos: topRes.rows
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al calcular analytics' });
  }
});

// ==========================================
// RUTA 20: ACTUALIZAR CONFIGURACIÓN COMPLETA (DATOS + PAGOS + VACACIONES)
// ==========================================
app.put('/api/mi-negocio/actualizar-todo', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  // Recibimos TODO el paquete de datos del formulario Flutter
  const { 
    nombre, direccion, whatsapp, rubro,
    hora_apertura, hora_cierre, dias_atencion,
    permite_delivery, permite_retiro,
    pago_efectivo, pago_transferencia, pago_tarjeta,
    // NUEVOS CAMPOS:
    en_vacaciones, notif_nuevas_ventas, notif_preguntas
  } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    const updateQuery = `
      UPDATE locales 
      SET 
        nombre = $1,
        direccion_fisica = $2,
        whatsapp = $3,
        hora_apertura = $4,
        hora_cierre = $5,
        dias_atencion = $6,
        rubro = $7,
        permite_delivery = $8,
        permite_retiro = $9,
        pago_efectivo = $10,
        pago_transferencia = $11,
        pago_tarjeta = $12,
        -- NUEVAS COLUMNAS
        en_vacaciones = $13,
        notif_nuevas_ventas = $14,
        notif_preguntas = $15,
        -- LÓGICA INTELIGENTE: Si vacaciones=TRUE, forzamos estado a 'CERRADO'
        estado_manual = CASE WHEN $13 = TRUE THEN 'CERRADO' ELSE estado_manual END
      WHERE usuario_id = $16
    `;
    
    await pool.query(updateQuery, [
      nombre, direccion, whatsapp, 
      hora_apertura, hora_cierre, dias_atencion,
      rubro, permite_delivery, permite_retiro,
      pago_efectivo, pago_transferencia, pago_tarjeta,
      en_vacaciones, notif_nuevas_ventas, notif_preguntas, // Params 13, 14, 15
      usuario.id // ID al final ($16)
    ]);

    res.json({ mensaje: 'Configuración y preferencias guardadas' });

  } catch (error) {
    console.error("Error actualizando todo:", error);
    res.status(500).json({ error: 'Error al guardar configuración' });
  }
});

// RUTA 21: CAMBIAR ESTADO MANUAL (ABRIR/CERRAR AHORA)
app.put('/api/mi-negocio/estado-manual', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { nuevo_estado } = req.body; // 'AUTO', 'ABIERTO', 'CERRADO'

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    await pool.query(
      'UPDATE locales SET estado_manual = $1 WHERE usuario_id = $2',
      [nuevo_estado, usuario.id]
    );

    res.json({ mensaje: 'Estado actualizado' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cambiar estado' });
  }
});

// ==========================================
// RUTA 22: LEER MI CONFIGURACIÓN (CON ESTADO MP)
// ==========================================
app.get('/api/mi-negocio/config', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    const consulta = `
      SELECT 
        nombre, 
        direccion_fisica, 
        whatsapp, 
        hora_apertura, 
        hora_cierre, 
        dias_atencion,
        rubro,
        permite_delivery,
        permite_retiro,
        pago_efectivo,
        pago_transferencia,
        pago_tarjeta,
        en_vacaciones,
        notif_nuevas_ventas,
        notif_preguntas,

        -- 👇 ESTA ES LA LÍNEA MÁGICA 👇
        -- Devuelve true si ya vinculó, false si no
        (mp_access_token IS NOT NULL) as mp_vinculado
        
      FROM locales WHERE usuario_id = $1
    `;
    
    const respuesta = await pool.query(consulta, [usuario.id]);

    if (respuesta.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });

    res.json(respuesta.rows[0]);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al leer configuración' });
  }
});

// ==========================================
// RUTA 23: CREAR/ACTUALIZAR OFERTA FLASH (24hs)
// ==========================================
app.post('/api/mi-negocio/oferta-flash', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { titulo, descripcion } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    // 1. Obtenemos el ID del local del usuario
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'No tienes un local registrado' });
    const local_id = localRes.rows[0].local_id;

    // 2. Lógica "Upsert" (Si ya tiene una, la sobrescribimos, si no, creamos)
    // La oferta dura 24 horas a partir de AHORA
    const query = `
      INSERT INTO ofertas_flash (local_id, titulo, descripcion, fecha_fin, activa)
      VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours', TRUE)
      ON CONFLICT (oferta_id) DO UPDATE -- (Esto requiere un constraint, pero usaremos lógica simple abajo)
      -- Simplificación: Borramos las viejas y creamos una nueva
    `;

    // A. Desactivamos cualquier oferta anterior de este local
    await pool.query('UPDATE ofertas_flash SET activa = FALSE WHERE local_id = $1', [local_id]);

    // B. Creamos la nueva
    await pool.query(`
      INSERT INTO ofertas_flash (local_id, titulo, descripcion, fecha_fin, activa)
      VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours', TRUE)
    `, [local_id, titulo, descripcion]);

    res.json({ mensaje: '¡Oferta Flash activada por 24 horas! 🔥' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear oferta' });
  }
});

// ======================================================
// RUTA: ACTUALIZAR TOKEN DE NOTIFICACIONES (FCM)
// ======================================================
app.post('/api/users/update-fcm-token', async (req, res) => {
  // Recibimos el ID del usuario y el token de Firebase
  const { userId, fcmToken } = req.body;

  // 1. Validaciones básicas
  if (!userId) {
    return res.status(400).json({ error: 'Falta el ID del usuario' });
  }
  if (!fcmToken) {
    return res.status(400).json({ error: 'Falta el Token FCM' });
  }

  try {
    // 2. Actualizamos la tabla 'usuarios' usando 'usuario_id'
    const query = `
      UPDATE usuarios 
      SET fcm_token = $1 
      WHERE usuario_id = $2
      RETURNING usuario_id;
    `;
    
    const result = await pool.query(query, [fcmToken, userId]);

    // 3. Verificamos si se encontró el usuario
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado con ese ID' });
    }

    console.log(`✅ Token FCM actualizado para usuario ${userId}`);
    res.json({ success: true, message: 'Notificaciones activadas' });

  } catch (error) {
    console.error('❌ Error guardando FCM Token:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ==========================================
// RUTA 24: OBTENER LISTA DE CATEGORÍAS (Para el Frontend)
// ==========================================
app.get('/api/categorias', async (req, res) => {
  try {
    // Devolvemos ordenado por tipo y nombre
    const result = await pool.query('SELECT * FROM categorias_config ORDER BY tipo, nombre');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Error cargando categorías' });
  }
});

// ==========================================
// RUTA 25: CREAR SOLICITUD VECINAL (El Cerebro)
// ==========================================
app.post('/api/solicitudes/crear', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { categoria_nombre, mensaje, lat, long } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. Obtener Configuración de la Categoría (Radio Base)
    const configRes = await pool.query('SELECT radio_base_metros FROM categorias_config WHERE nombre = $1', [categoria_nombre]);
    
    // Si no existe la categoría, usamos un default de 3km
    let radioBusqueda = configRes.rows.length > 0 ? configRes.rows[0].radio_base_metros : 3000;

    // 2. INTELIGENCIA DE DENSIDAD: ¿Hay locales en ese radio?
    // Contamos locales que coincidan con el rubro y estén cerca
    const checkLocales = `
      SELECT COUNT(*) as cantidad 
      FROM locales 
      WHERE (rubro ILIKE $1 OR categoria ILIKE $1)
      AND ST_DWithin(
        ubicacion::geometry, 
        ST_SetSRID(ST_MakePoint($2, $3), 4326)::geometry, 
        $4
      )
    `;
    
    let localesFound = await pool.query(checkLocales, [`%${categoria_nombre}%`, long, lat, radioBusqueda]);
    let cantidad = parseInt(localesFound.rows[0].cantidad);
    let expansionAutomatica = false;

    // 3. SI NO HAY LOCALES CERCA -> EXPANSIÓN AUTOMÁTICA
    if (cantidad === 0) {
      radioBusqueda = radioBusqueda * 2; // Duplicamos el radio
      expansionAutomatica = true;
      console.log(`⚠️ Poca densidad para ${categoria_nombre}. Expandiendo a ${radioBusqueda}m`);
    }

    // 4. GUARDAR SOLICITUD EN DB
    const insertQuery = `
      INSERT INTO solicitudes_vecinales (usuario_id, categoria_nombre, mensaje, ubicacion, radio_actual)
      VALUES ($1, $2, $3, ST_SetSRID(ST_MakePoint($4, $5), 4326), $6)
      RETURNING solicitud_id
    `;
    const solRes = await pool.query(insertQuery, [usuario.id, categoria_nombre, mensaje, long, lat, radioBusqueda]);
    const solicitudId = solRes.rows[0].solicitud_id;

    // 5. NOTIFICAR A LOS VENDEDORES (Búsqueda Inversa)
    // Buscamos a los dueños de los locales que matchean
    const vendedoresQuery = `
      SELECT U.usuario_id, U.fcm_token 
      FROM locales L
      JOIN usuarios U ON L.usuario_id = U.usuario_id
      WHERE (L.rubro ILIKE $1 OR L.categoria ILIKE $1)
      AND ST_DWithin(L.ubicacion::geometry, ST_SetSRID(ST_MakePoint($2, $3), 4326)::geometry, $4)
    `;
    
    const destinatarios = await pool.query(vendedoresQuery, [`%${categoria_nombre}%`, long, lat, radioBusqueda]);

    // Enviamos push a cada uno
    destinatarios.rows.forEach(vendedor => {
      if (vendedor.fcm_token) {
        enviarNotificacion(
          vendedor.usuario_id, // Función que ya tienes
          `📢 Alguien busca: ${categoria_nombre}`,
          `Un vecino necesita: "${mensaje}". Toca para responder.`
        );
      }
    });

    res.json({ 
      mensaje: 'Solicitud publicada', 
      radio_usado: radioBusqueda,
      locales_notificados: destinatarios.rows.length,
      expansion_automatica: expansionAutomatica
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al crear solicitud' });
  }
});

// ==========================================
// TAREA AUTOMÁTICA: CICLO DE VIDA SOLICITUDES
// ==========================================
cron.schedule('*/5 * * * *', async () => {
  console.log('⏰ Cron Job: Gestionando ciclo de vida solicitudes...');

  try {
    // --- ESCENARIO 1: PASARON 15 MINUTOS (Ofrecer Expansión) ---
    // Buscamos solicitudes 'ABIERTA' creadas hace >15 min sin respuestas
    const huerfanas = await pool.query(`
      SELECT S.solicitud_id, S.usuario_id 
      FROM solicitudes_vecinales S
      LEFT JOIN respuestas_solicitud R ON S.solicitud_id = R.solicitud_id
      WHERE S.fecha_creacion < NOW() - INTERVAL '15 minutes'
      AND S.estado = 'ABIERTA' 
      AND R.respuesta_id IS NULL
    `);

    for (const sol of huerfanas.rows) {
      // 1. Notificamos con DATA para que la app sepa qué abrir
      await enviarNotificacion(
        sol.usuario_id,
        "🤔 ¿Nadie respondió todavía?",
        "Toca aquí para ampliar el radio de búsqueda y llegar a más vecinos.",
        { 
          tipo: 'EXPANDIR_SOLICITUD', 
          solicitud_id: sol.solicitud_id.toString() 
        }
      );
      // 2. Cambiamos estado para no volver a notificar esto mismo
      await pool.query("UPDATE solicitudes_vecinales SET estado = 'ESPERANDO_EXPANSION' WHERE solicitud_id = $1", [sol.solicitud_id]);
    }

    // --- ESCENARIO 2: PASARON 15 MINUTOS DESDE LA EXPANSIÓN (Cierre Definitivo) ---
    // Buscamos solicitudes 'EXPANDIDA' que se modificaron hace >15 min y siguen sin respuesta
    // (Usamos fecha_creacion o una columna updated_at si tuvieras, usaremos fecha_creacion + 30 min aprox)
    const fallidas = await pool.query(`
      SELECT S.solicitud_id, S.usuario_id 
      FROM solicitudes_vecinales S
      LEFT JOIN respuestas_solicitud R ON S.solicitud_id = R.solicitud_id
      WHERE S.fecha_creacion < NOW() - INTERVAL '35 minutes' -- 15 iniciales + 20 de margen
      AND S.estado = 'EXPANDIDA' 
      AND R.respuesta_id IS NULL
    `);

    for (const sol of fallidas.rows) {
      await enviarNotificacion(
        sol.usuario_id,
        "😔 Búsqueda Finalizada",
        "No encontramos comercios disponibles esta vez. Intenta más tarde."
      );
      // Cerramos definitivamente
      await pool.query("UPDATE solicitudes_vecinales SET estado = 'CERRADA_SIN_EXITO' WHERE solicitud_id = $1", [sol.solicitud_id]);
    }

  } catch (error) {
    console.error('Error en Cron Job:', error);
  }
});

// ==========================================
// TAREA AUTOMÁTICA: CIERRE DE SOLICITUDES (24hs)
// ==========================================
// Se ejecuta cada hora (minuto 0)
cron.schedule('0 * * * *', async () => {
  console.log('🧹 Cron Job: Cerrando solicitudes viejas (>24hs)...');

  try {
    // Actualizamos a 'VENCIDA' las que tengan más de 24hs y sigan ABIERTAS
    const result = await pool.query(`
      UPDATE solicitudes_vecinales 
      SET estado = 'VENCIDA' 
      WHERE fecha_creacion < NOW() - INTERVAL '24 hours' 
      AND estado IN ('ABIERTA', 'PENDIENTE_EXPANSION')
    `);

    if (result.rowCount > 0) {
      console.log(`✅ Se vencieron ${result.rowCount} solicitudes antiguas.`);
    }
  } catch (error) {
    console.error('Error cerrando solicitudes:', error);
  }
});

// ==========================================
// RUTA 26: VER OPORTUNIDADES (Para el Vendedor)
// ==========================================
app.get('/api/mi-negocio/oportunidades', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. Obtenemos datos del local del vendedor
    const localRes = await pool.query('SELECT local_id, rubro, categoria, ubicacion FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'No tienes local' });
    const local = localRes.rows[0];

    // 2. Buscamos solicitudes ABIERTAS que coincidan con su rubro y estén dentro del radio
    // Nota: Usamos ST_DWithin usando la ubicación del LOCAL y la ubicación de la SOLICITUD
    const query = `
      SELECT 
        S.solicitud_id, 
        S.mensaje, 
        S.categoria_nombre, 
        TO_CHAR(S.fecha_creacion, 'DD/MM HH:MI') as fecha,
        -- Calculamos distancia real
        ST_Distance(S.ubicacion::geometry, $1::geometry)::int as distancia_metros,
        -- Verificamos si ya respondimos
        (SELECT COUNT(*) FROM respuestas_solicitud R WHERE R.solicitud_id = S.solicitud_id AND R.vendedor_id = $2) as ya_respondi
      FROM solicitudes_vecinales S
      WHERE S.estado = 'ABIERTA'
      AND (S.categoria_nombre ILIKE $3 OR S.categoria_nombre ILIKE $4) -- Coincide rubro/categoria
      AND ST_DWithin(S.ubicacion::geometry, $1::geometry, S.radio_actual) -- Dentro del radio que pidió el usuario
      ORDER BY S.fecha_creacion DESC
    `;

    // Pasamos la ubicación del local directa del objeto DB
    const oportunidades = await pool.query(query, [local.ubicacion, usuario.id, `%${local.rubro}%`, `%${local.categoria}%`]);
    
    res.json(oportunidades.rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al buscar oportunidades' });
  }
});

// ==========================================
// RUTA 27: RESPONDER SOLICITUD (Vendedor -> Comprador)
// ==========================================
app.post('/api/mi-negocio/responder-solicitud', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { solicitud_id, mensaje, precio_estimado } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    // Obtener ID del local
    const localRes = await pool.query('SELECT local_id, nombre FROM locales WHERE usuario_id = $1', [usuario.id]);
    const local = localRes.rows[0];

    // Guardar respuesta
    await pool.query(
      'INSERT INTO respuestas_solicitud (solicitud_id, vendedor_id, local_id, mensaje, precio_estimado) VALUES ($1, $2, $3, $4, $5)',
      [solicitud_id, usuario.id, local.local_id, mensaje, precio_estimado || null]
    );

    // Obtener datos del comprador para notificarle
    const solicitudRes = await pool.query('SELECT usuario_id FROM solicitudes_vecinales WHERE solicitud_id = $1', [solicitud_id]);
    const compradorId = solicitudRes.rows[0].usuario_id;

    // NOTIFICAR AL COMPRADOR
    enviarNotificacion(
      compradorId,
      `💬 ¡Respuesta de ${local.nombre}!`,
      `${mensaje}. Toca para ver detalle.`
    );

    res.json({ mensaje: 'Respuesta enviada' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al responder' });
  }
});

// ==========================================
// RUTA 28: MIS CONSULTAS (Para el Comprador)
// ==========================================
app.get('/api/solicitudes/mis-consultas', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // Traemos las solicitudes y anidamos las respuestas en un array JSON
    const query = `
      SELECT 
        S.solicitud_id, 
        S.categoria_nombre, 
        S.mensaje, 
        S.estado,
        TO_CHAR(S.fecha_creacion, 'DD/MM HH:MI') as fecha,
        (
          SELECT json_agg(json_build_object(
            'tienda', L.nombre,
            'whatsapp', L.whatsapp,
            'direccion', L.direccion_fisica,
            'mensaje', R.mensaje,
            'precio', R.precio_estimado,
            'foto_local', L.foto_url,
            'fecha_resp', TO_CHAR(R.fecha_respuesta, 'HH:MI')
          ))
          FROM respuestas_solicitud R
          JOIN locales L ON R.local_id = L.local_id
          WHERE R.solicitud_id = S.solicitud_id
        ) as respuestas
      FROM solicitudes_vecinales S
      WHERE S.usuario_id = $1
      ORDER BY S.fecha_creacion DESC
    `;

    const result = await pool.query(query, [usuario.id]);
    res.json(result.rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cargar mis consultas' });
  }
});

// ==========================================
// RUTA 28: EXPANDIR RADIO DE SOLICITUD
// ==========================================
app.post('/api/solicitudes/expandir', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  const { solicitud_id } = req.body;

  try {
    // 1. Obtenemos la solicitud actual
    const solRes = await pool.query('SELECT * FROM solicitudes_vecinales WHERE solicitud_id = $1', [solicitud_id]);
    if (solRes.rows.length === 0) return res.status(404).json({ error: 'No encontrada' });
    const solicitud = solRes.rows[0];

    // 2. Duplicamos el radio
    const nuevoRadio = solicitud.radio_actual * 2;

    // 3. Actualizamos en DB
    await pool.query(
      "UPDATE solicitudes_vecinales SET radio_actual = $1, estado = 'EXPANDIDA' WHERE solicitud_id = $2",
      [nuevoRadio, solicitud_id]
    );

    // 4. NOTIFICAMOS A LOS NUEVOS VENDEDORES (Radio ampliado)
    // Nota: Esto volverá a notificar a los cercanos, pero es aceptable como recordatorio.
    // Si quieres evitarlo, la query SQL sería compleja (ST_DWithin nuevo AND NOT ST_DWithin viejo).
    // Por ahora, notificamos al nuevo radio completo.
    const vendedoresQuery = `
      SELECT U.usuario_id, U.fcm_token 
      FROM locales L
      JOIN usuarios U ON L.usuario_id = U.usuario_id
      WHERE (L.rubro ILIKE $1 OR L.categoria ILIKE $1)
      AND ST_DWithin(L.ubicacion::geometry, $2::geometry, $3)
    `;
    
    // Necesitamos convertir la ubicación de la solicitud para la query
    // Como está en geography en DB, la casteamos. Ojo: necesitamos lat/long originales si no.
    // Simplificación: Usamos la geometría guardada en DB directamente.
    
    const destinatarios = await pool.query(vendedoresQuery, 
      [`%${solicitud.categoria_nombre}%`, solicitud.ubicacion, nuevoRadio]
    );

    destinatarios.rows.forEach(vendedor => {
      if (vendedor.fcm_token) {
        enviarNotificacion(vendedor.usuario_id, `📢 (Radio Ampliado) Alguien busca: ${solicitud.categoria_nombre}`, `Vecino necesita: "${solicitud.mensaje}"`);
      }
    });

    res.json({ mensaje: 'Búsqueda ampliada exitosamente' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al expandir' });
  }
});

// ==========================================
// RUTA 29: SUBIR HISTORIA (CON RESTRICCIÓN FREE/PREMIUM)
// ==========================================
app.post('/api/mi-negocio/historia', upload.single('imagen'), async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  const { caption } = req.body;
  
  if (!req.file) return res.status(400).json({ error: 'Falta la imagen' });
  const fotoUrl = req.file.path;

  try {
    const token = authHeader.split(' ')[1];
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. Obtenemos datos del local y su plan
    const localRes = await pool.query('SELECT local_id, plan_tipo FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'No tienes local' });
    
    const local = localRes.rows[0];
    const esPremium = local.plan_tipo === 'PREMIUM';

    // 2. EL PORTERO: Verificación de Límites 🛡️
    if (!esPremium) {
      // Si es FREE, contamos cuántas subió en los últimos 7 días
      const conteoRes = await pool.query(`
        SELECT COUNT(*) as total 
        FROM historias 
        WHERE local_id = $1 
        AND fecha_creacion > NOW() - INTERVAL '7 days'
      `, [local.local_id]);

      const historiasSemana = parseInt(conteoRes.rows[0].total);

      if (historiasSemana >= 1) {
        // Límite alcanzado: Rechazamos y borramos la imagen subida (opcional limpiar Cloudinary aquí)
        return res.status(403).json({ 
          error: 'Límite alcanzado', 
          mensaje: 'Los usuarios Free solo pueden subir 1 historia por semana. ¡Pásate a Premium para ilimitadas!' 
        });
      }
    }

    // 3. Si pasó el portero, guardamos
    await pool.query(
      'INSERT INTO historias (local_id, media_url, caption) VALUES ($1, $2, $3)',
      [local.local_id, fotoUrl, caption]
    );

    res.json({ mensaje: '¡Historia publicada con éxito! Durará 24hs.' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al subir historia' });
  }
});

// RUTA 30: OBTENER HISTORIAS ACTIVAS DE UN LOCAL
app.get('/api/locales/:id/historias', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT media_url, tipo_media, caption, fecha_creacion 
      FROM historias 
      WHERE local_id = $1 AND fecha_expiracion > NOW()
      ORDER BY fecha_creacion ASC
    `, [req.params.id]);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: 'Error al cargar historias' });
  }
});

// ==========================================
// RUTA 31: FEED EXPLORAR (ALGORITMO HIPERLOCAL)
// ==========================================
app.get('/api/historias/feed', async (req, res) => {
  const { lat, lng, radio = 10000 } = req.query; // 10km a la redonda

  if (!lat || !lng) return res.status(400).json({ error: 'Ubicación requerida' });

  try {
    const query = `
      SELECT 
        H.historia_id,
        H.media_url,
        H.caption,
        H.tipo_media,
        H.fecha_creacion,
        -- Datos del Local (Para el Header de la tarjeta)
        L.local_id,
        L.nombre as nombre_local,
        L.foto_url as foto_local,
        L.rubro,
        L.plan_tipo,
        -- Cálculo de Distancia Real (PostGIS)
        ST_Distance(
          L.ubicacion::geometry, 
          ST_SetSRID(ST_MakePoint($1, $2), 4326)::geometry
        ) as distancia_metros
      FROM historias H
      JOIN locales L ON H.local_id = L.local_id
      WHERE 
        H.fecha_expiracion > NOW() -- Solo historias vivas
        AND ST_DWithin(
          L.ubicacion::geometry, 
          ST_SetSRID(ST_MakePoint($1, $2), 4326)::geometry, 
          $3
        )
      ORDER BY 
        (CASE WHEN L.plan_tipo = 'PREMIUM' THEN 0 ELSE 1 END) ASC, -- Premium primero
        H.fecha_creacion DESC -- Las más nuevas arriba
      LIMIT 20;
    `;

    const result = await pool.query(query, [parseFloat(lng), parseFloat(lat), parseFloat(radio)]);
    res.json(result.rows);

  } catch (error) {
    console.error("Error Feed:", error);
    res.status(500).json({ error: 'Error cargando feed' });
  }
});

// ==========================================
// RUTA 32: GUARDAR CONFIG FIDELIZACIÓN (VENDEDOR)
// ==========================================
app.post('/api/mi-negocio/fidelizacion', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  // Recibimos los datos del formulario
  // estado: true/false (Activo/Inactivo)
  // monto_minimo: El valor del ticket para sumar sello
  const { meta_sellos, premio, monto_minimo, estado } = req.body;

  // Validaciones básicas
  if (!premio) return res.status(400).json({ error: 'Debes definir un premio' });
  if (meta_sellos < 1) return res.status(400).json({ error: 'Mínimo 1 sello' });

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    // 1. Obtener ID del Local
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'No tienes local' });
    const local_id = localRes.rows[0].local_id;

    // 2. UPSERT (Insertar o Actualizar si ya existe)
    // ON CONFLICT (local_id) funciona porque definimos local_id como UNIQUE en la tabla
    const query = `
      INSERT INTO config_fidelizacion (local_id, meta_sellos, premio_descripcion, monto_minimo, estado)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (local_id) 
      DO UPDATE SET
        meta_sellos = EXCLUDED.meta_sellos,
        premio_descripcion = EXCLUDED.premio_descripcion,
        monto_minimo = EXCLUDED.monto_minimo,
        estado = EXCLUDED.estado,
        fecha_creacion = NOW() -- Actualizamos fecha para saber que hubo cambios
      RETURNING *;
    `;

    const result = await pool.query(query, [
      local_id, 
      meta_sellos, 
      premio, 
      parseFloat(monto_minimo) || 0, 
      estado
    ]);

    res.json({ 
      mensaje: 'Sistema de fidelización actualizado', 
      config: result.rows[0] 
    });

  } catch (error) {
    console.error("Error guardando fidelización:", error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ==========================================
// RUTA 33: LEER MI CONFIG FIDELIZACIÓN
// ==========================================
app.get('/api/mi-negocio/fidelizacion', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    // Traemos la config uniendo con la tabla de locales para filtrar por usuario
    const query = `
      SELECT C.* 
      FROM config_fidelizacion C
      JOIN locales L ON C.local_id = L.local_id
      WHERE L.usuario_id = $1
    `;
    
    const result = await pool.query(query, [usuario.id]);

    if (result.rows.length === 0) {
      // Si no tiene config, devolvemos un objeto "vacío" o null para que el frontend sepa
      return res.json({ existe: false });
    }

    res.json({ existe: true, config: result.rows[0] });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error cargando configuración' });
  }
});

// ==========================================
// RUTA 34: AVISO DE LLEGADA (CLICK & COLLECT) 📢 - ACTUALIZADA
// ==========================================
app.post('/api/transaccion/avisar-llegada', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { transaccion_id } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET); // Comprador

    // 1. Buscamos datos de la transacción para saber quién es el vendedor
    const txRes = await pool.query(
      `SELECT vendedor_id, estado, tipo_entrega, compra_uuid 
       FROM transacciones_p2p WHERE transaccion_id = $1`, 
      [transaccion_id]
    );

    if (txRes.rows.length === 0) return res.status(404).json({ error: 'Pedido no encontrado' });
    const pedido = txRes.rows[0];

    // 2. Validaciones de Lógica
    if (pedido.tipo_entrega !== 'RETIRO') {
      return res.status(400).json({ error: 'Este pedido es con envío, no puedes avisar llegada.' });
    }
    
    if (pedido.estado === 'ENTREGADO' || pedido.estado === 'CANCELADO') {
      return res.status(400).json({ error: 'El pedido ya fue finalizado.' });
    }

    // 3. PERSISTENCIA EN BASE DE DATOS (NUEVO) 💾
    // Marcamos el flag para que la UI recuerde que ya se avisó
    await pool.query(
      'UPDATE transacciones_p2p SET aviso_llegada = TRUE WHERE transaccion_id = $1',
      [transaccion_id]
    );

    // 4. Notificar al Vendedor
    const nombreCliente = usuario.nombre || "El cliente";
    const refPedido = pedido.compra_uuid ? pedido.compra_uuid.split('-')[0].toUpperCase() : transaccion_id;

    await enviarNotificacion(
      pedido.vendedor_id,
      "🚗 CLIENTE EN CAMINO", 
      `${nombreCliente} está yendo a buscar el pedido #${refPedido}. ¡Déjalo listo en el mostrador!`
    );

    res.json({ mensaje: 'Aviso de camino enviado' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al enviar aviso' });
  }
});


// ==========================================
// RUTA DE PAGOS: CHECKOUT MARKETPLACE (CON METADATA) 💸
// ==========================================
app.post('/api/pagos/crear-preferencia', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  // Frontend nos manda items y el ID del local donde compra
  const { items, local_id, tipo_entrega } = req.body; 

  if (!local_id) return res.status(400).json({ error: 'Falta el ID del local' });

  try {
    // 0. Identificar al COMPRADOR (para guardarlo en metadata)
    const token = authHeader.split(' ')[1];
    const usuarioComprador = jwt.verify(token, JWT_SECRET);

    // 1. BUSCAR CREDENCIALES DEL VENDEDOR EN NEON
    const queryLocal = 'SELECT mp_access_token, nombre, usuario_id FROM locales WHERE local_id = $1';
    const localRes = await pool.query(queryLocal, [local_id]);

    if (localRes.rows.length === 0) {
      return res.status(404).json({ error: 'Local no encontrado' });
    }

    const sellerData = localRes.rows[0];
    const sellerToken = sellerData.mp_access_token;

    // VALIDACIÓN CRÍTICA: ¿El vendedor vinculó su cuenta?
    if (!sellerToken) {
      return res.status(400).json({ 
        error: `El local "${sellerData.nombre}" aún no ha configurado sus pagos. Avísale para que lo active.` 
      });
    }

    // 2. CALCULAR TOTAL Y PREPARAR ITEMS PARA MP
    let totalVenta = 0;
    
    // Creamos un array ligero para guardar en metadata (JSON)
    // Solo guardamos IDs y Cantidades para reconstruir la orden luego
    const itemsParaMetadata = items.map(i => ({
      id: i.inventario_id, // ID del producto en tu BD
      cant: Number(i.cantidad),
      precio: Number(i.precio),
      title: i.nombre // Opcional, útil para debug
    }));

    const itemsMP = items.map(item => {
      const precio = Number(item.precio);
      const cantidad = Number(item.cantidad);
      totalVenta += precio * cantidad;
      
      return {
        id: item.inventario_id.toString(),
        title: item.nombre,
        quantity: cantidad,
        unit_price: precio,
        currency_id: 'ARS',
      };
    });

    // TU GANANCIA: 1% (Ajustable)
    const comisionCercaMio = Math.round((totalVenta * 0.01) * 100) / 100; // 1%

    // 3. CONFIGURAR CLIENTE CON TOKEN DEL VENDEDOR
    const sellerClient = new MercadoPagoConfig({ accessToken: sellerToken });
    const preference = new Preference(sellerClient);

    // 4. CREAR PREFERENCIA CON FEE Y METADATA (¡LO IMPORTANTE!)
    const body = {
      items: itemsMP,
      marketplace_fee: comisionCercaMio, 
      
      // --- AQUÍ ESTÁ LA MAGIA ---
      // Guardamos todo lo necesario para procesar la orden en el futuro
      metadata: {
        comprador_id: usuarioComprador.id,
        vendedor_id: sellerData.usuario_id, // El ID de usuario del dueño del local
        local_id: local_id,
        tipo_entrega: tipo_entrega || 'RETIRO', // Default
        items_json: JSON.stringify(itemsParaMetadata) // Guardamos el array como texto
      },
      // ---------------------------

      back_urls: {
        success: "cercamio://payment-result", 
        failure: "cercamio://payment-result",
        pending: "cercamio://payment-result"
      },
      auto_return: "approved",
      statement_descriptor: "CERCAMIO APP",
      notification_url: "https://cercamio-backend.onrender.com/api/pagos/webhook" 
    };

    const result = await preference.create({ body });

    // 5. DEVOLVER LINK
    res.json({ 
      id: result.id, 
      link_pago: result.init_point 
    });

  } catch (error) {
    console.error("Error Split Payment:", error);
    res.status(500).json({ error: 'Error al procesar el pago con el vendedor' });
  }
});

// ==========================================
// RUTA 35: GENERAR LINK DE VINCULACIÓN (OAUTH) - ACTUALIZADO
// ==========================================
app.get('/api/pagos/auth-url', async (req, res) => { // <--- Ahora es async
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    // 1. Identificamos al vendedor
    const usuario = jwt.verify(token, JWT_SECRET);
    
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'No tienes un local registrado' });
    
    const localId = localRes.rows[0].local_id;

    // 2. Configuración MP (Revisa que tu APP_ID sea el correcto del panel)
    const appId = '7458384450787340'; 
    const redirectUri = 'https://cercamio-backend.onrender.com/api/pagos/callback';
    
    // 3. EL TRUCO: Pasamos el ID del local en el parámetro 'state'
    // Así cuando vuelva, sabremos quién es.
    const state = localId.toString(); 

    const url = `https://auth.mercadopago.com.ar/authorization?client_id=${appId}&response_type=code&platform_id=mp&state=${state}&redirect_uri=${redirectUri}`;

    res.json({ url: url });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error generando link' });
  }
});

// ==========================================
// RUTA 36: CALLBACK Y GUARDADO DE CREDENCIALES
// ==========================================
app.get('/api/pagos/callback', async (req, res) => {
  const { code, state } = req.query; // 'state' trae el local_id que mandamos antes

  if (!code || !state) {
    return res.send("Error: Datos incompletos desde Mercado Pago.");
  }

  try {
    // 1. Canjeamos el código por las credenciales del vendedor
    const response = await fetch('https://api.mercadopago.com/oauth/token', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        // Tu token de ADMIN (Producción) para autorizar el canje
        'Authorization': 'Bearer APP_USR-7458384450787340-120216-78724c3a5f2c37e72886e52c26816cc0-161693502' 
      },
      body: JSON.stringify({
        client_secret: 'TBMpvQ5C8yYtzMJFsvFyJLMwnQBlub3W', // Tu Client Secret
        client_id: '7458384450787340',
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'https://cercamio-backend.onrender.com/api/pagos/callback'
      })
    });

    const data = await response.json();

    if (data.access_token) {
      // 2. ¡ÉXITO! Guardamos las llaves en la base de datos
      // data.access_token = El token para cobrar a nombre del vendedor
      // data.user_id = El ID de usuario de MP del vendedor
      // data.refresh_token = Para renovar en 6 meses
      
      const updateQuery = `
        UPDATE locales 
        SET 
          mp_access_token = $1,
          mp_user_id = $2,
          mp_refresh_token = $3
        WHERE local_id = $4
      `;

      await pool.query(updateQuery, [
        data.access_token, 
        data.user_id, 
        data.refresh_token, 
        state // El local_id que recuperamos
      ]);

      console.log(`✅ Local ${state} vinculado exitosamente con Mercado Pago.`);

      // 3. HTML de Éxito bonito para el celular
      res.send(`
        <div style="font-family: sans-serif; text-align: center; padding: 20px;">
          <h1 style="color: #4CAF50;">¡Cuenta Vinculada! 🎉</h1>
          <p>Has conectado tu Mercado Pago exitosamente.</p>
          <p>Tus ventas ahora se acreditarán en tu cuenta.</p>
          <br>
          <a href="https://google.com" style="padding: 10px 20px; background: #2196F3; color: white; text-decoration: none; border-radius: 5px;">Volver a la App</a>
        </div>
      `);
    } else {
      console.error("Error MP OAuth:", data);
      res.send(`<h1>Error</h1><p>${data.message || 'No se pudo vincular.'}</p>`);
    }

  } catch (error) {
    console.error(error);
    res.status(500).send("Error interno del servidor");
  }
});

// ==========================================
// RUTA 37: WEBHOOK (PROCESAMIENTO AUTOMÁTICO DE PAGOS) 🤖
// ==========================================
app.post('/api/pagos/webhook', async (req, res) => {
  const { type, data } = req.body;

  // Solo procesamos notificaciones de tipo 'payment'
  if (type === 'payment') {
    try {
      const paymentId = data.id;
      console.log(`🔔 Webhook recibido. Pago ID: ${paymentId}`);

      // 1. IDEMPOTENCIA: ¿Ya procesamos este pago antes?
      const checkDuplicado = await pool.query('SELECT 1 FROM transacciones_p2p WHERE mp_payment_id = $1', [paymentId.toString()]);
      if (checkDuplicado.rows.length > 0) {
        console.log("⚠️ Pago ya registrado. Ignorando duplicado.");
        return res.status(200).send("OK");
      }

      // 2. CONSULTAR ESTADO DEL PAGO A MERCADO PAGO
      // Usamos el cliente del Admin (Platform) para leer el pago
      const paymentClient = new Payment(client); 
      const paymentData = await paymentClient.get({ id: paymentId });

      // 3. SI ESTÁ APROBADO, GUARDAMOS
      if (paymentData.status === 'approved') {
        const meta = paymentData.metadata;
        
        // Recuperamos los datos que "pegamos" al crear la preferencia
        // MP transforma las keys a snake_case (ej: itemsJSON -> items_json)
        const compradorId = meta.comprador_id;
        const vendedorId = meta.vendedor_id;
        const itemsComprados = JSON.parse(meta.items_json); 
        const tipoEntrega = meta.tipo_entrega;
        const totalPagado = paymentData.transaction_amount;

        // Generamos un UUID único para agrupar estos items en una sola "Orden"
        const compraUuid = crypto.randomUUID();

        console.log(`✅ Pago Aprobado. Procesando orden para vendedor ${vendedorId}...`);

        const clientDb = await pool.connect();
        
        try {
          await clientDb.query('BEGIN');

          for (const item of itemsComprados) {
             // A. BUSCAR DATOS REALES PARA EL SNAPSHOT
             // El 'item.id' viene de la preferencia, que es tu 'inventario_id'
             const queryProducto = `
                SELECT global_id, nombre, foto_url, tipo_item, stock 
                FROM inventario_local 
                WHERE inventario_id = $1 FOR UPDATE
             `;
             const prodRes = await clientDb.query(queryProducto, [item.id]);
             
             // Si el producto fue borrado justo después de comprar (raro, pero posible)
             // usamos valores fallback para no romper la venta
             const datosReales = prodRes.rows.length > 0 ? prodRes.rows[0] : {
                global_id: null,
                nombre: item.title, // El título que mandó MP
                foto_url: null,
                tipo_item: 'PRODUCTO_STOCK',
                stock: 0
             };

             // B. DESCONTAR STOCK (Si aplica)
             if (datosReales.tipo_item === 'PRODUCTO_STOCK') {
                await clientDb.query(
                  'UPDATE inventario_local SET stock = stock - $1 WHERE inventario_id = $2', 
                  [item.cant, item.id]
                );
             }

             // C. INSERTAR TRANSACCIÓN (Igual que tu ruta manual)
             const insertTx = `
                INSERT INTO transacciones_p2p 
                (
                  comprador_id, 
                  vendedor_id, 
                  producto_global_id, 
                  cantidad, 
                  monto_total, 
                  estado, 
                  tipo_entrega, 
                  mp_payment_id, 
                  fecha_operacion,
                  compra_uuid,      -- Tu agrupador
                  nombre_snapshot,  -- Tu snapshot de nombre
                  foto_snapshot     -- Tu snapshot de foto
                )
                VALUES ($1, $2, $3, $4, $5, 'APROBADO', $6, $7, NOW(), $8, $9, $10)
             `;
             
             await clientDb.query(insertTx, [
                compradorId, 
                vendedorId, 
                datosReales.global_id, // Usamos el ID global real de la base
                item.cant, 
                item.precio * item.cant, 
                tipoEntrega,
                paymentId.toString(),
                compraUuid,            // El UUID generado arriba
                datosReales.nombre,    // Snapshot Nombre
                datosReales.foto_url   // Snapshot Foto
             ]);
          }

          await clientDb.query('COMMIT');
          
          // 5. NOTIFICAR AL VENDEDOR
          const mensaje = `¡Pago de MP acreditado! Total: $${totalPagado}. Entrega: ${tipoEntrega}`;
          enviarNotificacion(vendedorId, "¡Nueva Venta Online! 💳", mensaje);

        } catch (dbError) {
          await clientDb.query('ROLLBACK');
          console.error("❌ Error guardando en BD (Webhook):", dbError);
          // Importante: No devolver error 500 si es un fallo lógico nuestro,
          // porque MP seguirá enviando el webhook infinitamente.
        } finally {
          clientDb.release();
        }
      }
    } catch (error) {
      console.error("❌ Error procesando Webhook:", error);
      return res.status(500).send("Error interno");
    }
  }

  res.status(200).send("OK");
});

// RUTA: DESVINCULAR MERCADO PAGO
app.post('/api/mi-negocio/desvincular-mp', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // Borramos los tokens de MP en la base de datos
    await pool.query(`
      UPDATE locales 
      SET mp_access_token = NULL, mp_refresh_token = NULL, mp_user_id = NULL
      WHERE usuario_id = $1
    `, [usuario.id]);

    res.json({ mensaje: 'Cuenta desvinculada correctamente' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al desvincular' });
  }
});

// ==========================================
// RUTA 38: HACER PREGUNTA (Q&A PÚBLICO)
// ==========================================
app.post('/api/preguntas/crear', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { local_id, pregunta } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. Guardar Pregunta
    await pool.query(
      'INSERT INTO preguntas (local_id, usuario_id, pregunta) VALUES ($1, $2, $3)',
      [local_id, usuario.id, pregunta]
    );

    // 2. Obtener datos para notificar al Vendedor
    const localRes = await pool.query('SELECT usuario_id, nombre FROM locales WHERE local_id = $1', [local_id]);
    if (localRes.rows.length > 0) {
      const vendedorId = localRes.rows[0].usuario_id;
      const nombreLocal = localRes.rows[0].nombre;
      
      // Notificación Push al Vendedor
      enviarNotificacion(
        vendedorId, 
        `💬 Nueva pregunta en ${nombreLocal}`,
        `${usuario.nombre || 'Un cliente'} preguntó: "${pregunta}"`
      );
    }

    res.json({ mensaje: 'Pregunta enviada' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al preguntar' });
  }
});

// ==========================================
// RUTA 39: RESPONDER PREGUNTA (VENDEDOR)
// ==========================================
app.post('/api/mi-negocio/responder-pregunta', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { pregunta_id, respuesta } = req.body;

  try {
    const vendedor = jwt.verify(token, JWT_SECRET);

    // 1. Validar que la pregunta corresponda a un local de este vendedor
    // Y actualizamos la respuesta + fecha
    const updateQuery = `
      UPDATE preguntas P
      SET respuesta = $1, fecha_respuesta = NOW()
      FROM locales L
      WHERE P.local_id = L.local_id 
      AND L.usuario_id = $2 
      AND P.pregunta_id = $3
      RETURNING P.usuario_id, L.nombre as nombre_local;
    `;

    const result = await pool.query(updateQuery, [respuesta, vendedor.id, pregunta_id]);

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'No tienes permiso o la pregunta no existe' });
    }

    // 2. Notificar al Usuario que hizo la pregunta
    const { usuario_id, nombre_local } = result.rows[0];
    
    enviarNotificacion(
      usuario_id,
      `Te respondieron de ${nombre_local} 💬`,
      `Respuesta: "${respuesta}"`
    );

    res.json({ mensaje: 'Respuesta publicada' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al responder' });
  }
});

// ==========================================
// RUTA 40: OBTENER PREGUNTAS DE UN LOCAL
// ==========================================
app.get('/api/preguntas/local/:id', async (req, res) => {
  const local_id = req.params.id;
  const { limit } = req.query; // Puede ser 3 o undefined (todas)

  try {
    let consulta = `
      SELECT 
        P.pregunta_id,
        P.pregunta,
        P.respuesta,
        P.fecha_pregunta,
        P.fecha_respuesta,
        U.nombre_completo as usuario_nombre
      FROM preguntas P
      JOIN usuarios U ON P.usuario_id = U.usuario_id
      WHERE P.local_id = $1
      ORDER BY P.fecha_pregunta DESC
    `;

    // Si piden límite (ej: las 3 últimas para el perfil)
    if (limit) {
      consulta += ` LIMIT ${parseInt(limit)}`;
    }

    const respuesta = await pool.query(consulta, [local_id]);
    res.json(respuesta.rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error cargando preguntas' });
  }
});

// ==========================================
// RUTA 41: OBTENER MIS PREGUNTAS (VENDEDOR)
// ==========================================
app.get('/api/mi-negocio/mis-preguntas', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const vendedor = jwt.verify(token, JWT_SECRET);

    // Traemos las preguntas uniendo con Locales (para saber que son mios) y Usuarios (para saber quién preguntó)
    const consulta = `
      SELECT 
        P.pregunta_id,
        P.pregunta,
        P.respuesta,
        P.fecha_pregunta,
        P.fecha_respuesta,
        P.local_id,
        L.nombre as nombre_local,
        U.nombre_completo as usuario_nombre,
        -- Calculamos si está pendiente (true/false)
        (P.respuesta IS NULL) as es_pendiente
      FROM preguntas P
      JOIN locales L ON P.local_id = L.local_id
      JOIN usuarios U ON P.usuario_id = U.usuario_id
      WHERE L.usuario_id = $1
      ORDER BY P.fecha_pregunta DESC
    `;

    const result = await pool.query(consulta, [vendedor.id]);
    res.json(result.rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener preguntas' });
  }
});

// ==========================================
// RUTA 42: SOLICITAR VERIFICACIÓN DE EMAIL
// ==========================================
app.post('/api/auth/send-verification', async (req, res) => {
  const { email } = req.body;
  const codigo = generarCodigo();

  try {
    // Guardamos el código en la BD
    const result = await pool.query(
      'UPDATE usuarios SET verification_code = $1 WHERE email = $2 RETURNING usuario_id',
      [codigo, email]
    );

    if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    // Enviamos el email
    await enviarEmail(email, 'Verifica tu cuenta CercaMío', `Tu código de verificación es: ${codigo}`);

    res.json({ mensaje: 'Código enviado' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al procesar' });
  }
});

// ==========================================
// RUTA 43: CONFIRMAR CÓDIGO DE EMAIL
// ==========================================
app.post('/api/auth/verify-email', async (req, res) => {
  const { email, codigo } = req.body;

  try {
    const user = await pool.query('SELECT verification_code FROM usuarios WHERE email = $1', [email]);
    
    if (user.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    if (user.rows[0].verification_code !== codigo) {
      return res.status(400).json({ error: 'Código incorrecto' });
    }

    // Código correcto: Marcamos verificado y borramos el código
    await pool.query(
      'UPDATE usuarios SET email_verified = TRUE, verification_code = NULL WHERE email = $1',
      [email]
    );

    res.json({ mensaje: '¡Cuenta verificada exitosamente!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al verificar' });
  }
});

// ==========================================
// RUTA 44: OLVIDÉ MI CONTRASEÑA (Solicitud)
// ==========================================
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const codigo = generarCodigo();

  try {
    const result = await pool.query(
      'UPDATE usuarios SET recovery_code = $1 WHERE email = $2 RETURNING usuario_id',
      [codigo, email]
    );

    if (result.rowCount === 0) return res.status(404).json({ error: 'Email no registrado' });

    await enviarEmail(email, 'Recuperar Contraseña - CercaMío', `Usa este código para restablecer tu clave: ${codigo}`);

    res.json({ mensaje: 'Si el email existe, se envió el código.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ==========================================
// RUTA 45: RESTABLECER CONTRASEÑA (Nuevo Password)
// ==========================================
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, codigo, nuevaPassword } = req.body;

  try {
    // 1. Validar código
    const user = await pool.query('SELECT recovery_code FROM usuarios WHERE email = $1', [email]);
    if (user.rows.length === 0 || user.rows[0].recovery_code !== codigo) {
      return res.status(400).json({ error: 'Código inválido o expirado' });
    }

    // 2. Hashear nueva contraseña (IMPORTANTE: Asegúrate de tener bcrypt importado)
    const bcrypt = require('bcryptjs'); // O 'bcrypt', según lo que uses arriba
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(nuevaPassword, salt);

    // 3. Actualizar y borrar código
    await pool.query(
      'UPDATE usuarios SET password_hash = $1, recovery_code = NULL WHERE email = $2',
      [hash, email]
    );

    res.json({ mensaje: 'Contraseña actualizada. Ya puedes iniciar sesión.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cambiar contraseña' });
  }
});

// RUTA 46: OBTENER MI PERFIL COMPLETO
app.get('/api/users/me', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    const query = `
      SELECT 
        nombre_completo, email, foto_url, telefono, 
        TO_CHAR(fecha_nacimiento, 'YYYY-MM-DD') as fecha_nacimiento,
        direccion, barrio, ciudad, provincia, pais, email_verified, telefono_verificado
      FROM usuarios WHERE usuario_id = $1
    `;
    const result = await pool.query(query, [usuario.id]);
    
    if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener perfil' });
  }
});

// RUTA 47: ACTUALIZAR PERFIL (CON FOTO Y CAPITALIZACIÓN)
app.put('/api/users/update', upload.single('foto'), async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  // Desestructuramos para tener claridad
  const { nombre, telefono, fecha_nacimiento, direccion, barrio, ciudad, provincia, pais } = req.body;
  
  // Foto: Si subió una nueva, usamos esa.
  const nuevaFotoUrl = req.file ? req.file.path : null;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    // Función auxiliar para capitalizar (si no la tienes definida afuera, la definimos aquí o úsala desde afuera)
    const capitalizar = (txt) => txt ? txt.toLowerCase().split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') : "";
    const nombreFormateado = capitalizar(nombre);

    // Limpiamos la fecha (si viene vacía, enviamos null)
    const fechaFinal = fecha_nacimiento || null;

    if (nuevaFotoUrl) {
      // CASO A: CON FOTO NUEVA (10 Parámetros)
      const queryConFoto = `
        UPDATE usuarios SET 
          nombre_completo = $1, 
          telefono = $2, 
          fecha_nacimiento = $3, 
          direccion = $4, 
          barrio = $5, 
          ciudad = $6, 
          provincia = $7, 
          pais = $8,
          foto_url = $9 
        WHERE usuario_id = $10
      `;
      
      await pool.query(queryConFoto, [
        nombreFormateado, 
        telefono, 
        fechaFinal, 
        direccion, 
        barrio, 
        ciudad, 
        provincia, 
        pais, 
        nuevaFotoUrl, // $9
        usuario.id    // $10
      ]);

    } else {
      // CASO B: SIN FOTO (9 Parámetros - No tocamos foto_url)
      const querySinFoto = `
        UPDATE usuarios SET 
          nombre_completo = $1, 
          telefono = $2, 
          fecha_nacimiento = $3, 
          direccion = $4, 
          barrio = $5, 
          ciudad = $6, 
          provincia = $7, 
          pais = $8
        WHERE usuario_id = $9
      `;

      await pool.query(querySinFoto, [
        nombreFormateado, 
        telefono, 
        fechaFinal, 
        direccion, 
        barrio, 
        ciudad, 
        provincia, 
        pais, 
        usuario.id    // $9
      ]);
    }

    res.json({ mensaje: 'Perfil actualizado', nombre: nombreFormateado });

  } catch (error) {
    console.error("Error ruta 61:", error);
    res.status(500).json({ error: 'Error al actualizar perfil' });
  }
});

// ==========================================
// MÓDULO SOPORTE Y AYUDA 🆘
// ==========================================

// RUTA: OBTENER FAQ
app.get('/api/soporte/faq', async (req, res) => {
  try {
    const query = 'SELECT * FROM faqs ORDER BY orden ASC';
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("Error FAQ:", error);
    res.status(500).json({ error: 'Ups, no pudimos cargar las preguntas.' });
  }
});

// RUTA: CREAR TICKET
app.post('/api/soporte/crear-ticket', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { motivo, mensaje } = req.body;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    const query = `
      INSERT INTO soporte_tickets (usuario_id, motivo, mensaje)
      VALUES ($1, $2, $3)
      RETURNING ticket_id
    `;
    
    await pool.query(query, [usuario.id, motivo, mensaje]);

    res.json({ mensaje: '¡Recibido! Nuestro equipo analizará tu caso.' });

  } catch (error) {
    console.error("Error Ticket:", error);
    res.status(500).json({ error: 'No se pudo enviar el ticket. Intenta de nuevo.' });
  }
});

// ==========================================
// MÓDULO SOCIOS (PARTNERS) 🤝
// ==========================================

// 1. Configuración Multer para DNI (2 archivos)
const uploadDNI = upload.fields([
  { name: 'dni_frente', maxCount: 1 }, 
  { name: 'dni_dorso', maxCount: 1 }
]);

// 2. RUTA: CONSULTAR ESTADO DE SOCIO
app.get('/api/socios/me', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    // Verificamos si existe en la tabla socios
    const query = `
      SELECT socio_id, codigo_referido, estado, saldo_acumulado, cbu_alias 
      FROM socios WHERE usuario_id = $1
    `;
    const result = await pool.query(query, [usuario.id]);

    if (result.rows.length === 0) {
      // No es socio -> Devolvemos false para que la App muestre la Landing
      return res.json({ es_socio: false, estado: null });
    }

    // Si es socio -> Devolvemos datos
    res.json({ es_socio: true, data: result.rows[0] });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al consultar estado de socio' });
  }
});

// 3. RUTA: SOLICITAR ALTA (SUBIR DNI)
app.post('/api/socios/solicitar', uploadDNI, async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { cbu_alias, nombre_real } = req.body;
  
  const files = req.files;
  if (!files || !files['dni_frente'] || !files['dni_dorso']) {
    return res.status(400).json({ error: 'Faltan las fotos del DNI' });
  }

  // Cloudinary ya subió las fotos, aquí tenemos los links
  const dniFrenteUrl = files['dni_frente'][0].path;
  const dniDorsoUrl = files['dni_dorso'][0].path;

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // Generar Código (Ej: NOM-123)
    const nombreBase = (nombre_real || "SOCIO").substring(0, 3).toUpperCase().replace(/[^A-Z]/g, "X");
    const rand = Math.floor(100 + Math.random() * 900);
    const codigoGenerado = `${nombreBase}-${rand}`;

    const insertQuery = `
      INSERT INTO socios (usuario_id, codigo_referido, cbu_alias, dni_frente_url, dni_dorso_url, estado)
      VALUES ($1, $2, $3, $4, $5, 'PENDIENTE')
      RETURNING codigo_referido
    `;

    await pool.query(insertQuery, [
      usuario.id, codigoGenerado, cbu_alias, dniFrenteUrl, dniDorsoUrl
    ]);

    res.json({ mensaje: 'Solicitud enviada', codigo: codigoGenerado });

  } catch (error) {
    if (error.code === '23505') return res.status(400).json({ error: 'Ya tienes una solicitud en curso.' });
    console.error("Error alta socio:", error);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ===========================================

// ==========================================
// RUTA 48: DASHBOARD DEL SOCIO (CON GAMIFICACIÓN Y RETIROS 💸)
// ==========================================
app.get('/api/socios/dashboard', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. OBTENER DATOS SOCIO
    const socioQuery = `SELECT socio_id, codigo_referido, estado, saldo_acumulado, cbu_alias, porcentaje_ganancia FROM socios WHERE usuario_id = $1`;
    const socioRes = await pool.query(socioQuery, [usuario.id]);

    if (socioRes.rows.length === 0) return res.status(404).json({ error: 'No eres socio aún' });
    const socio = socioRes.rows[0];

    // 2. OBTENER FLOTA (Contamos locales)
    const flotaQuery = `
      SELECT L.local_id, L.nombre, L.rubro, L.foto_url, L.fecha_registro,
        COUNT(T.transaccion_id) as total_ventas_historicas,
        MAX(T.fecha_operacion) as ultima_venta
      FROM locales L
      LEFT JOIN transacciones_p2p T ON L.usuario_id = T.vendedor_id
      WHERE L.referido_por_socio_id = $1
      GROUP BY L.local_id
      ORDER BY L.fecha_registro DESC
    `;
    const flotaRes = await pool.query(flotaQuery, [socio.socio_id]);
    
    const totalLocales = flotaRes.rows.length;
    const localesActivos = flotaRes.rows.filter(l => parseInt(l.total_ventas_historicas) > 0).length;

    // 3. LÓGICA DE GAMIFICACIÓN (Niveles) 🏆
    const niveles = [
      { nombre: "BRONCE", meta: 0, ganancia: 5.0 },
      { nombre: "PLATA", meta: 10, ganancia: 7.5 },
      { nombre: "ORO", meta: 30, ganancia: 10.0 },
      { nombre: "PLATINO", meta: 60, ganancia: 12.5 },
      { nombre: "DIAMANTE", meta: 100, ganancia: 15.0 }
    ];

    let nivelActual = niveles[0];
    let nivelSiguiente = niveles[1];
    
    for (let i = 0; i < niveles.length; i++) {
      if (totalLocales >= niveles[i].meta) {
        nivelActual = niveles[i];
        nivelSiguiente = (i + 1 < niveles.length) ? niveles[i + 1] : null; 
      }
    }

    let progreso = 0.0;
    let faltan = 0;
    let mensajeMotivacional = "¡Eres una leyenda! Has alcanzado el máximo nivel. 👑";

    if (nivelSiguiente) {
      const rango = nivelSiguiente.meta - nivelActual.meta;
      const avanceEnRango = totalLocales - nivelActual.meta;
      progreso = avanceEnRango / rango;
      faltan = nivelSiguiente.meta - totalLocales;
      mensajeMotivacional = `¡Vamos! Solo te faltan ${faltan} locales para ser ${nivelSiguiente.nombre} y ganar ${nivelSiguiente.ganancia}%`;
    }

    // 4. OBTENER ÚLTIMOS RETIROS (NUEVO BLOQUE) 💸
    // Esto es lo que faltaba para completar el circuito de Cash Out
    const retirosRes = await pool.query(
      `SELECT monto, estado, TO_CHAR(fecha_solicitud, 'DD/MM/YY') as fecha 
       FROM solicitudes_retiro 
       WHERE socio_id = $1 
       ORDER BY fecha_solicitud DESC LIMIT 5`,
      [socio.socio_id]
    );

    // 5. RESPUESTA FINAL
    res.json({
      perfil: {
        codigo: socio.codigo_referido,
        saldo: socio.saldo_acumulado,
        estado: socio.estado,
        alias: socio.cbu_alias
      },
      gamification: {
        nivel_actual: nivelActual.nombre,
        porcentaje_actual: socio.porcentaje_ganancia, 
        nivel_siguiente: nivelSiguiente ? nivelSiguiente.nombre : "MAX",
        meta_siguiente: nivelSiguiente ? nivelSiguiente.meta : totalLocales,
        progreso_decimal: progreso, 
        mensaje: mensajeMotivacional,
        faltan_locales: faltan
      },
      metricas: {
        total_locales: totalLocales,
        locales_activos: localesActivos
      },
      flota: flotaRes.rows,
      retiros: retirosRes.rows // <--- Enviamos el historial al Frontend
    });

  } catch (error) {
    console.error("Error Dashboard Socio:", error);
    res.status(500).json({ error: 'Error al cargar tu tablero' });
  }
});

// ==========================================
// FUNCIÓN AUXILIAR: CALCULAR NIVEL DE SOCIO 📈
// ==========================================
const actualizarNivelSocio = async (socioId) => {
  try {
    // 1. Contamos cuántos locales activos tiene este socio
    const countRes = await pool.query(
      'SELECT COUNT(*) FROM locales WHERE referido_por_socio_id = $1', 
      [socioId]
    );
    
    const cantidadLocales = parseInt(countRes.rows[0].count);
    
    // 2. Definimos la escalera de éxito (Tus reglas)
    let nuevoPorcentaje = 5.00; // Nivel Base (Bronce)
    let nombreNivel = "BRONCE";

    if (cantidadLocales >= 100) {
      nuevoPorcentaje = 15.00;
      nombreNivel = "DIAMANTE";
    } else if (cantidadLocales >= 60) {
      nuevoPorcentaje = 12.50; // Ajusté un intermedio
      nombreNivel = "PLATINO";
    } else if (cantidadLocales >= 30) {
      nuevoPorcentaje = 10.00;
      nombreNivel = "ORO";
    } else if (cantidadLocales >= 10) {
      nuevoPorcentaje = 7.50;
      nombreNivel = "PLATA";
    }

    // 3. Actualizamos en la base de datos
    await pool.query(
      'UPDATE socios SET porcentaje_ganancia = $1 WHERE socio_id = $2',
      [nuevoPorcentaje, socioId]
    );

    console.log(`📈 Socio #${socioId} actualizado: ${cantidadLocales} locales -> Nivel ${nombreNivel} (${nuevoPorcentaje}%)`);
    
    // Opcional: Podrías enviar notificación si subió de nivel
    // if (subioNivel) enviarNotificacion(...)

  } catch (error) {
    console.error("Error actualizando nivel socio:", error);
  }
};

// ==========================================
// RUTA 49: SOLICITAR RETIRO DE FONDOS 💸
// ==========================================
app.post('/api/socios/retirar', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const MONTO_MINIMO = 1000; // Configurable

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, JWT_SECRET);
    
    await client.query('BEGIN');

    // 1. Obtener datos del socio bloqueando la fila (FOR UPDATE) para evitar doble click
    const socioRes = await client.query(
      'SELECT socio_id, saldo_acumulado, cbu_alias FROM socios WHERE usuario_id = $1 FOR UPDATE',
      [usuario.id]
    );

    if (socioRes.rows.length === 0) throw new Error('No eres socio');
    const socio = socioRes.rows[0];
    const saldoActual = parseFloat(socio.saldo_acumulado);

    // 2. Validaciones
    if (saldoActual < MONTO_MINIMO) {
      throw new Error(`El monto mínimo para retirar es $${MONTO_MINIMO}`);
    }

    if (!socio.cbu_alias) {
      throw new Error('No tienes un CBU/Alias configurado');
    }

    // 3. MOVIMIENTO DE FONDOS (Atomicidad)
    // A. Restamos el saldo
    await client.query(
      'UPDATE socios SET saldo_acumulado = saldo_acumulado - $1 WHERE socio_id = $2',
      [saldoActual, socio.socio_id]
    );

    // B. Creamos el ticket de retiro
    await client.query(
      'INSERT INTO solicitudes_retiro (socio_id, monto, cbu_destino) VALUES ($1, $2, $3)',
      [socio.socio_id, saldoActual, socio.cbu_alias]
    );

    await client.query('COMMIT');

    // 4. Notificar (Opcional: Mandar email al admin avisando que hay que pagar)
    console.log(`💸 Solicitud de retiro: Socio #${socio.socio_id} pide $${saldoActual}`);

    res.json({ mensaje: 'Solicitud enviada. Tu dinero está en proceso.' });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(400).json({ error: error.message || 'Error al procesar retiro' });
  } finally {
    client.release();
  }
});


// ENCENDEMOS EL SERVIDOR
app.listen(port, () => {
  console.log(`🚀 SERVIDOR ACTUALIZADO - VERSIÓN CON SOCIOS ACTIVA - Puerto ${port}`);
});

