// 1. IMPORTAMOS LAS LIBRERÍAS
require('dotenv').config(); // <--- ESTO SIEMPRE PRIMERO
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const cron = require('node-cron');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const axios = require('axios');
const xlsx = require('xlsx');

// 2. CONFIGURACIÓN DE IMÁGENES (CLOUDINARY + MULTER)
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

// A) Storage PÚBLICO (Reseñas, Productos)
const storagePublico = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'cercamio_public', 
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
  },
});

// B) Storage PRIVADO (DNI / Documentación) 🔒
const storagePrivado = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'cercamio_documentacion_privada',
    type: 'private', // Bloquea acceso público
    access_mode: 'authenticated',
    allowed_formats: ['jpg', 'png', 'jpeg', 'pdf'],
  },
});

const upload = multer({ storage: storagePublico }); 
const uploadPrivado = multer({ storage: storagePrivado }); 

// C) Storage en MEMORIA (Para Excel temporal) 🧠
// No guardamos en disco ni en nube, solo en RAM para procesar rápido
const storageMemoria = multer.memoryStorage();
const uploadMemoria = multer({ storage: storageMemoria });

// 3. MERCADO PAGO (Solo importamos clases, instanciamos en las rutas)
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');

// 4. CONFIGURACIÓN DE EMAIL (ENVIALOSIMPLE TRANSACCIONAL) 📧
const transporter = nodemailer.createTransport({
  host: 'smtp.envialosimple.email', // Tal cual la foto
  port: 587, 
  secure: false, // 587 usa STARTTLS, por eso secure va en false
  auth: {
    user: process.env.EMAIL_USER, // Leerá el usuario largo 'xb69...' de Render
    pass: process.env.EMAIL_PASS  // Leerá la password larga 'k89P...' de Render
  },
  tls: {
    // La foto dice "Requiere TLS 1.3 o superior", forzamos eso por seguridad
    minVersion: 'TLSv1.3',
    rejectUnauthorized: false 
  }
});

// Función auxiliar
const enviarEmail = async (destinatario, asunto, texto, html) => {
  console.log(`📨 Enviando email a: ${destinatario}`);
  try {
    await transporter.sendMail({
      from: '"Equipo CercaMío" <soporte@cercamio.app>', // 👁️ AQUÍ SÍ VA TU EMAIL REAL COMO REMITENTE
      to: destinatario,
      subject: asunto,
      text: texto,
      html: html
    });
    console.log('✅ Email enviado.');
    return true;
  } catch (error) {
    console.error("⚠️ Falló envío de email:", error.message);
    return false;
  }
};

// 5. FUNCIONES AUXILIARES SIMPLES
const generarCodigo = () => Math.floor(100000 + Math.random() * 900000).toString();
const capitalizarNombre = (texto) => {
  if (!texto) return "";
  return texto.toLowerCase().split(' ').map(p => p.charAt(0).toUpperCase() + p.slice(1)).join(' ');
};

// ==========================================
// FUNCIÓN AUXILIAR: NOTIFICACIONES HÍBRIDAS (DB + FCM) 🔔
// ==========================================
const enviarNotificacion = async (usuarioIdDestino, titulo, mensaje, dataPayload = {}) => {
  try {
    // 1. GUARDAR EN BASE DE DATOS (HISTORIAL PERMANENTE) 💾
    // Hacemos esto primero para que quede registro aunque falle el envío Push
    const payloadJson = dataPayload || {};
    const tipo = payloadJson.tipo || 'SISTEMA'; // Si no viene tipo, es aviso de sistema

    // Insertamos en la tabla 'notificaciones'
    await pool.query(
      `INSERT INTO notificaciones (usuario_id, titulo, mensaje, tipo, data_payload) 
       VALUES ($1, $2, $3, $4, $5)`,
      [usuarioIdDestino, titulo, mensaje, tipo, payloadJson]
    );

    // 2. BUSCAR TOKEN DEL USUARIO (Tu lógica original)
    const query = 'SELECT fcm_token FROM usuarios WHERE usuario_id = $1';
    const res = await pool.query(query, [usuarioIdDestino]);

    // Si no existe el usuario o no tiene token, terminamos aquí (pero ya guardamos en DB)
    if (res.rows.length === 0 || !res.rows[0].fcm_token) {
      return; 
    }

    const fcmToken = res.rows[0].fcm_token;

    // 3. PREPARAR MENSAJE PARA FIREBASE
    // Firebase requiere que los valores de 'data' sean Strings obligatoriamente
    const payloadString = {};
    for (let key in payloadJson) {
        payloadString[key] = String(payloadJson[key]);
    }

    const message = {
      notification: { title: titulo, body: mensaje },
      token: fcmToken,
      data: payloadString // Datos convertidos para FCM
    };

    // 4. ENVIAR PUSH
    await admin.messaging().send(message);
    // console.log(`📲 Notificación enviada a usuario ${usuarioIdDestino}`);

  } catch (error) {
    console.error('⚠️ Error sistema notificaciones:', error.message);

    // --- AUTO-LIMPIEZA DE TOKENS MUERTOS (Tu lógica original conservada) ---
    if (error.code === 'messaging/registration-token-not-registered' || 
        error.code === 'messaging/invalid-argument') {
       
       await pool.query('UPDATE usuarios SET fcm_token = NULL WHERE usuario_id = $1', [usuarioIdDestino]);
       console.log(`🗑️ Token inválido eliminado para usuario ${usuarioIdDestino}`);
    }
  }
};

// ==========================================
// 🔐 MIDDLEWARE DE AUTENTICACIÓN (FALTABA ESTO)
// ==========================================
const verificarToken = (req, res, next) => {
  // 1. Buscamos el header "Authorization: Bearer <token>"
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  // 2. Si no hay token, error 401
  if (!token) return res.status(401).json({ error: 'Acceso denegado: Token requerido' });

  try {
    // 3. Verificamos firma con el Secreto
    const verificado = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = verificado; // Guardamos datos del usuario en la request
    next(); // Continuamos a la ruta
  } catch (error) {
    res.status(400).json({ error: 'Token inválido o expirado' });
  }
};

// ==========================================
// 🛡️ MIDDLEWARE: SOLO ADMINS
// ==========================================
const verificarAdmin = async (req, res, next) => {
  // 1. Ya pasó por verificarToken, así que tenemos req.usuario.id
  try {
    const query = 'SELECT rol FROM usuarios WHERE usuario_id = $1';
    const result = await pool.query(query, [req.usuario.id]);
    
    if (result.rows.length === 0) return res.status(401).json({ error: 'Usuario no existe' });
    
    const rol = result.rows[0].rol;
    
    // 2. Validamos el ROL
    if (rol === 'SUPER_ADMIN' || rol === 'SOPORTE' || rol === 'MARKETING') {
      req.usuario.rol = rol; // Guardamos el rol para usarlo luego
      next(); // Pase, jefe.
    } else {
      return res.status(403).json({ error: 'Acceso denegado: Requieres permisos de Administrador' });
    }
  } catch (error) {
    console.error("Error verificando admin:", error);
    res.status(500).json({ error: 'Error de servidor' });
  }
};

// 6. CONFIGURAMOS LA APP EXPRESS
const app = express();
const port = process.env.PORT || 3000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET; // Lee del .env

// 7. FIREBASE ADMIN
const admin = require('firebase-admin');
const fs = require('fs'); 
const rutaLocal = './serviceAccountKey.json';
const rutaRender = '/etc/secrets/serviceAccountKey.json';

let serviceAccount;
try {
  if (fs.existsSync(rutaRender)) {
    serviceAccount = require(rutaRender);
    console.log('🔒 Firebase: Usando credenciales de Render.');
  } else if (fs.existsSync(rutaLocal)) {
    serviceAccount = require(rutaLocal);
    console.log('💻 Firebase: Usando credenciales locales.');
  }
  
  if (serviceAccount && !admin.apps.length) {
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  }
} catch (error) {
  console.error('❌ Error Firebase:', error.message);
}

// ==========================================
// 8. MIDDLEWARES & SEGURIDAD WEB (CORS) 🛡️
// ==========================================
const whitelist = [
  'https://cercamio.app',           // Landing Page Oficial
  'https://panel.cercamio.app',     // Panel Vendedor
  'https://admin.cercamio.app',     // Panel Admin
  'https://api.cercamio.app',       // Auto-referencia
  'http://localhost:5173',          // Tu entorno local (Vite)
  'http://localhost:3000'           // Tu entorno local (Node)
];

app.use(cors({
  origin: function (origin, callback) {
    // Permitir requests sin origen (como Apps móviles Flutter, Postman o Server-to-Server)
    if (!origin) return callback(null, true);
    
    if (whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`⛔ Bloqueado por CORS: ${origin}`);
      callback(new Error('Bloqueado por CORS: Origen no permitido'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true // Permite cookies/tokens seguros
}));

app.use(express.json());

// 9. BASE DE DATOS (NEON)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Lee del .env
  ssl: { require: true, rejectUnauthorized: false },
  
  // --- OPTIMIZACIÓN DE CONEXIONES ---
  max: 20, // Máximo de conexiones simultáneas (Ideal para plan Launch)
  idleTimeoutMillis: 30000, // Cerrar conexión si lleva 30s sin usarse (Ahorra recursos)
  connectionTimeoutMillis: 10000, // Esperar hasta 10s a que la DB despierte (Antes tiraba error a los 2s)
});

// Manejador de errores del Pool (Para que no tumbe el servidor si se cae la DB)
pool.on('error', (err, client) => {
  console.error('❌ Error inesperado en cliente de base de datos:', err);
  // No salimos del proceso, dejamos que intente reconectar en la próxima
});

// Test de conexión
pool.connect()
  .then(() => console.log('✅ Conectado a Neon DB'))
  .catch(err => console.error('❌ Error DB:', err.message));

app.get('/ping', (req, res) => res.send('pong'));

// Ruta de prueba básica
app.get('/', (req, res) => {
  res.send('¡Hola! El servidor de CercaMío está funcionando 🚀');
});



// ==========================================
// 🔗 DEEP LINKING (VERIFICACIÓN ANDROID)
// ==========================================
app.get('/.well-known/assetlinks.json', (req, res) => {
  res.json([
    {
      "relation": ["delegate_permission/common.handle_all_urls"],
      "target": {
        "namespace": "android_app",
        "package_name": "com.cercamio.app", // ⚠️ CONFIRMA QUE ESTE SEA TU ID EN build.gradle
        "sha256_cert_fingerprints": [
           "66:EC:CF:28:65:75:F8:E6:FD:12:33:A7:6A:7A:44:4E:D9:2C:BB:FA:E2:04:D5:AE:8F:93:4F:4D:60:08:FF:F8" // ⚠️ PEGA AQUÍ TU SHA-256 DEL PASO 1
        ]
      }
    }
  ]);
});

// ==========================================
// RUTAS DE NOTIFICACIONES (HISTORIAL) 🔔
// ==========================================

// A. OBTENER MIS NOTIFICACIONES (Paginadas o últimas 50)
app.get('/api/notificaciones', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    const query = `
      SELECT * FROM notificaciones 
      WHERE usuario_id = $1 
      ORDER BY fecha_creacion DESC 
      LIMIT 50
    `;
    const result = await pool.query(query, [usuario.id]);

    // Contamos cuántas sin leer hay para el badge
    const countRes = await pool.query(
      'SELECT COUNT(*) FROM notificaciones WHERE usuario_id = $1 AND leida = FALSE', 
      [usuario.id]
    );
    
    res.json({
        lista: result.rows,
        sin_leer: parseInt(countRes.rows[0].count)
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener notificaciones' });
  }
});

// B. MARCAR COMO LEÍDA (Una o Todas)
app.put('/api/notificaciones/leer', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  const { notificacion_id, leer_todas } = req.body;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    if (leer_todas) {
        await pool.query('UPDATE notificaciones SET leida = TRUE WHERE usuario_id = $1', [usuario.id]);
    } else if (notificacion_id) {
        await pool.query('UPDATE notificaciones SET leida = TRUE WHERE notificacion_id = $1 AND usuario_id = $2', [notificacion_id, usuario.id]);
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar estado' });
  }
});

// C. ELIMINAR NOTIFICACIÓN (MANUAL) 🗑️
app.delete('/api/notificaciones/:id', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  const { id } = req.params;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // Solo borra si pertenece al usuario
    await pool.query('DELETE FROM notificaciones WHERE notificacion_id = $1 AND usuario_id = $2', [id, usuario.id]);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar' });
  }
});

// TAREA PROGRAMADA: LIMPIEZA DE NOTIFICACIONES VIEJAS (> 30 DÍAS)
// Se ejecuta todos los días a las 04:00 AM
cron.schedule('0 4 * * *', async () => {
  console.log('🧹 Iniciando limpieza de notificaciones antiguas...');
  try {
    const res = await pool.query(
      "DELETE FROM notificaciones WHERE fecha_creacion < NOW() - INTERVAL '30 days'"
    );
    console.log(`✅ Se eliminaron ${res.rowCount} notificaciones viejas.`);
  } catch (error) {
    console.error('❌ Error en limpieza de notificaciones:', error);
  }
});

// ==========================================
// RUTA 1: OBTENER LOCALES (GPS REAL + BÚSQUEDA VISUAL) 📍
// (OPTIMIZADO v10.1 - PostGIS Geography)
// ==========================================
app.get('/api/locales', async (req, res) => {
  // Recibimos coordenadas de la cámara (lat, lng) Y del usuario (user_lat, user_lng)
  const { filtro, lat, lng, user_lat, user_lng, radio = 5000 } = req.query; 

  try {
    if (!lat || !lng) {
      return res.status(400).json({ error: "Faltan coordenadas del centro del mapa" });
    }

    // Definimos el origen para calcular la distancia:
    // Si el celular mandó su GPS real (user_lat), usamos ese.
    // Si no (ej: permiso denegado), usamos el centro del mapa como fallback.
    const origenLat = user_lat || lat;
    const origenLng = user_lng || lng;

    let consulta = `
      SELECT 
        L.local_id, 
        L.nombre, 
        L.categoria, 
        L.plan_tipo,
        L.plan_vencimiento,
        L.modo_operacion, 
        L.reputacion, 
        COALESCE(L.foto_perfil, L.foto_url) as foto_url, 
        L.foto_portada, 
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
        
        (L.plan_tipo = 'PREMIUM' AND L.plan_vencimiento > NOW()) as es_premium,

        ST_X(L.ubicacion::geometry) as long, 
        ST_Y(L.ubicacion::geometry) as lat,
        
        -- 📏 CÁLCULO DE DISTANCIA REAL (CORREGIDO: Metros) 📏
        -- Usamos ::geography para calcular metros sobre la curvatura de la tierra
        ST_Distance(
          L.ubicacion::geography, 
          ST_SetSRID(ST_MakePoint($4, $5), 4326)::geography
        ) as distancia_metros,

        -- 1. OFERTA FLASH
        CASE 
          WHEN O.oferta_id IS NOT NULL THEN json_build_object(
            'titulo', O.titulo,
            'descripcion', O.descripcion,
            'fecha_fin', O.fecha_fin
          )
          ELSE NULL 
        END as oferta_flash,

        -- 2. OFERTA ESPECIAL
        (EXISTS (
          SELECT 1 FROM inventario_local I 
          WHERE I.local_id = L.local_id 
          AND I.categoria_interna = 'OFERTA_ESPECIAL'
          AND I.stock > 0
        )) as tiene_oferta_especial,

        -- 3. HISTORIAS
        (EXISTS (
          SELECT 1 FROM historias H 
          WHERE H.local_id = L.local_id 
          AND H.fecha_expiracion > NOW()
        )) as tiene_historias

      FROM locales L
      LEFT JOIN ofertas_flash O ON L.local_id = O.local_id AND O.activa = TRUE AND O.fecha_fin > NOW()

      WHERE 
        -- 🎯 FILTRO DE BÚSQUEDA (LO QUE VEO) 🎯
        -- Usamos ::geography para que el radio ($3) sea interpretado en METROS
        ST_DWithin(
          L.ubicacion::geography,
          ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography,
          $3
        )
    `;
    
    // Parámetros SQL:
    // $1, $2, $3 -> Filtran (Centro del Mapa + Radio)
    // $4, $5     -> Miden (GPS del Usuario)
    // Nota: PostGIS usa (Lng, Lat), por eso el orden es lng, lat
    let params = [
        parseFloat(lng), parseFloat(lat), parseFloat(radio),      // 1, 2, 3
        parseFloat(origenLng), parseFloat(origenLat)              // 4, 5
    ]; 
    
    let paramCounter = 6; // El próximo filtro arranca en $6

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

    // Ordenamos por Premium y luego por cercanía al usuario
    consulta += ` ORDER BY (L.plan_tipo = 'PREMIUM' AND L.plan_vencimiento > NOW()) DESC, distancia_metros ASC`;

    const respuesta = await pool.query(consulta, params);
    res.json(respuesta.rows);

  } catch (error) {
    console.error("Error en GET /api/locales:", error);
    res.status(500).send('Error en el servidor');
  }
});

// ==========================================
// RUTA 2: BUSCADOR AVANZADO (HÍBRIDO: PRODUCTOS + SERVICIOS) 🔍
// ==========================================
app.get('/api/buscar', async (req, res) => {
  const { q, lat, lng } = req.query; 
  
  if (!q) return res.status(400).json({ error: 'Falta el término de búsqueda' });
  
  // Validación de GPS
  if (!lat || !lng) {
      return res.status(400).json({ error: "Se requiere ubicación para buscar" });
  }

  try {
    const terminoBusqueda = `%${q}%`;

    const consulta = `
      SELECT 
        L.local_id,
        I.inventario_id,
        
        -- DATOS INTELIGENTES
        COALESCE(I.nombre, C.nombre_oficial) as nombre_oficial, 
        COALESCE(I.descripcion, C.descripcion) as descripcion,
        COALESCE(I.foto_url, C.foto_url) as foto_producto,
        
        I.precio, 
        
        -- 🔥 DATOS DE AGENDA (AGREGADOS)
        I.requiere_agenda,
        I.duracion_minutos,

        L.nombre as tienda,
        L.categoria,
        L.rubro,
        L.tipo_actividad,
        L.reputacion,
        L.whatsapp,
        
        -- FOTO DEL LOCAL
        COALESCE(L.foto_perfil, L.foto_url) as foto_local,

        ST_X(L.ubicacion::geometry) as long, 
        ST_Y(L.ubicacion::geometry) as lat,
        
        -- Distancia Real (Metros exactos usando Geography)
        ST_Distance(
          L.ubicacion::geography, 
          ST_SetSRID(ST_MakePoint($2, $3), 4326)::geography
        ) as distancia_metros

      FROM inventario_local I
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id
      JOIN locales L ON I.local_id = L.local_id
      
      WHERE 
        -- 1. FILTRO GEOESPACIAL (Radio 10km - Usando Geography para precisión)
        ST_DWithin(
          L.ubicacion::geography,
          ST_SetSRID(ST_MakePoint($2, $3), 4326)::geography,
          10000 
        )
        AND
        -- 2. FILTRO DE VISIBILIDAD (CORREGIDO)
        -- Debe tener precio Y (tener stock O ser servicio)
        I.precio > 0 
        AND (I.stock > 0 OR I.requiere_agenda = TRUE)
        
        AND
        -- 3. BÚSQUEDA INTELIGENTE
        (
          public.immutable_unaccent(COALESCE(I.nombre, C.nombre_oficial)) ILIKE public.immutable_unaccent($1)
          OR 
          public.immutable_unaccent(COALESCE(I.descripcion, C.descripcion)) ILIKE public.immutable_unaccent($1)
          OR
          public.immutable_unaccent(L.nombre) ILIKE public.immutable_unaccent($1)
          OR 
          public.immutable_unaccent(L.rubro) ILIKE public.immutable_unaccent($1)
        )

      -- ORDENAMIENTO
      ORDER BY distancia_metros ASC
      LIMIT 50
    `;
    
    const respuesta = await pool.query(consulta, [terminoBusqueda, parseFloat(lng), parseFloat(lat)]);
    
    res.json(respuesta.rows);

  } catch (error) {
    console.error("Error en GET /api/buscar:", error);
    res.status(500).json({ error: 'Error al buscar productos' });
  }
});

// ==========================================
// RUTA 6: VER MIS PRODUCTOS (HÍBRIDO + OFERTAS + AGENDA) 🏆
// ==========================================
app.get('/api/mi-negocio/productos', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // 1. Obtener datos del Local (Tu lógica de estado/misiones)
    const localRes = await pool.query(
      'SELECT local_id, misiones_puntos, estado_manual, plan_tipo FROM locales WHERE usuario_id = $1',
      [usuario.id]
    );

    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const datosLocal = localRes.rows[0];

    // 2. Obtener Productos (Ordenados por importancia)
    const productosQuery = `
      SELECT 
        I.inventario_id,
        COALESCE(I.nombre, C.nombre_oficial) as nombre_oficial, 
        COALESCE(I.descripcion, C.descripcion) as descripcion,
        COALESCE(I.foto_url, C.foto_url) as foto_url,
        COALESCE(I.codigo_barras, C.codigo_barras) as codigo_barras,
        
        I.precio,
        I.stock,
        I.tipo_item,
        
        -- Datos de Oferta
        I.categoria_interna,
        I.precio_regular,

        -- 🔥 DATOS DE AGENDA (AGREGADOS v13.1)
        I.requiere_agenda,
        I.duracion_minutos

      FROM inventario_local I
      JOIN locales L ON I.local_id = L.local_id
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id
      WHERE L.usuario_id = $1
      
      -- 🔥 ORDENAMIENTO INTELIGENTE:
      -- 1. Ofertas Flash primero (Urgente)
      -- 2. Ofertas Especiales segundo
      -- 3. Productos normales al final (por fecha)
      ORDER BY 
        CASE 
            WHEN I.categoria_interna = 'OFERTA_FLASH' THEN 1
            WHEN I.categoria_interna = 'OFERTA_ESPECIAL' THEN 2
            ELSE 3 
        END,
        I.inventario_id DESC
    `;
    
    const productosRes = await pool.query(productosQuery, [usuario.id]);

    res.json({
      status: {
        local_id: datosLocal.local_id,
        misiones_puntos: datosLocal.misiones_puntos || 0,
        estado_manual: datosLocal.estado_manual || 'AUTO',
        plan_tipo: datosLocal.plan_tipo
      },
      items: productosRes.rows // Ahora los items traen la info de agenda
    });

  } catch (error) {
    console.error("Error GET productos:", error);
    res.status(500).json({ error: 'Error al obtener inventario' });
  }
});

// ==========================================
// RUTA 7: ACTUALIZAR NEGOCIO (HÍBRIDO: PRODUCTOS + SERVICIOS + AGENDA) 🧠
// ==========================================
app.put('/api/mi-negocio/actualizar', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { 
    // Para GPS
    lat, long,
    // Para Productos
    inventario_id, 
    nuevo_precio, 
    nuevo_stock, 
    nuevo_foto, 
    nuevo_nombre, 
    nuevo_desc,
    codigo_barras,
    categoria_interna, // 'GENERAL', 'OFERTA_FLASH', etc.
    // 🔥 NUEVOS CAMPOS DE AGENDA (PASO 2)
    requiere_agenda, 
    duracion_minutos
  } = req.body;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // ---------------------------------------------------------
    // CASO A: ACTUALIZAR UBICACIÓN GPS (Sin cambios)
    // ---------------------------------------------------------
    if (lat && long) {
      const queryGPS = `
        UPDATE locales 
        SET ubicacion = ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography
        WHERE usuario_id = $3
      `;
      await pool.query(queryGPS, [parseFloat(long), parseFloat(lat), usuario.id]);
      
      return res.json({ mensaje: 'Ubicación actualizada correctamente' });
    }

    // ---------------------------------------------------------
    // CASO B: ACTUALIZAR PRODUCTO (PRECIOS + AGENDA)
    // ---------------------------------------------------------
    if (inventario_id) {
      
      // 1. OBTENER ESTADO ACTUAL (Para la lógica de Ofertas)
      const currentRes = await pool.query('SELECT precio, precio_regular, categoria_interna FROM inventario_local WHERE inventario_id = $1', [inventario_id]);
      
      if (currentRes.rows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
      const actual = currentRes.rows[0];

      // --- LÓGICA DE PRECIOS INTELIGENTE ---
      let precioFinal = nuevo_precio;
      let precioRegularFinal = actual.precio_regular; 
      let catFinal = categoria_interna || actual.categoria_interna; 

      // A. Si estamos ACTIVANDO una oferta
      if (catFinal !== 'GENERAL' && actual.categoria_interna === 'GENERAL') {
          precioRegularFinal = actual.precio;
      }
      
      // B. Si estamos QUITANDO una oferta
      else if (catFinal === 'GENERAL' && actual.categoria_interna !== 'GENERAL') {
          if (actual.precio_regular) {
              precioFinal = actual.precio_regular;
          }
          precioRegularFinal = null; 
      }

      // 2. ACTUALIZAMOS INVENTARIO LOCAL (AHORA CON AGENDA)
      // Usamos COALESCE para no romper nada si el frontend no manda los datos nuevos
      const updateInventario = `
        UPDATE inventario_local 
        SET 
          precio = $1, 
          stock = $2,
          codigo_barras = COALESCE($3, codigo_barras),
          categoria_interna = $4,
          precio_regular = $5,
          -- 🔥 ACTUALIZACIÓN DE AGENDA
          requiere_agenda = COALESCE($7, requiere_agenda),
          duracion_minutos = COALESCE($8, duracion_minutos)
        WHERE inventario_id = $6
      `;
      
      await pool.query(updateInventario, [
        precioFinal,        // $1
        nuevo_stock,        // $2
        codigo_barras,      // $3
        catFinal,           // $4
        precioRegularFinal, // $5
        inventario_id,      // $6 (WHERE)
        requiere_agenda,    // $7 (Nuevo)
        duracion_minutos    // $8 (Nuevo)
      ]);

      // 3. ACTUALIZAMOS CATALOGO GLOBAL (Sin cambios)
      const getGlobal = await pool.query('SELECT global_id FROM inventario_local WHERE inventario_id = $1', [inventario_id]);
      
      if (getGlobal.rows.length > 0) {
        const globalId = getGlobal.rows[0].global_id;
        
        let queryCatalogo = `
          UPDATE catalogo_global 
          SET nombre_oficial = COALESCE($1, nombre_oficial), descripcion = COALESCE($2, descripcion) 
          WHERE global_id = $3
        `;
        
        await pool.query(queryCatalogo, [nuevo_nombre, nuevo_desc, globalId]);

        if (nuevo_foto) {
          await pool.query('UPDATE catalogo_global SET foto_url = $1 WHERE global_id = $2', [nuevo_foto, globalId]);
          // Actualizamos local también por seguridad visual
          await pool.query('UPDATE inventario_local SET foto_url = $1 WHERE inventario_id = $2', [nuevo_foto, inventario_id]);
        }
      }

      return res.json({ mensaje: 'Producto/Servicio actualizado correctamente' });
    }

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

// ==========================================
// RUTA 4: LOGIN (CON ROL ADMIN 👑)
// ==========================================
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

    // 3. CHECKPOINT DE VERIFICACIÓN
    if (!usuario.email_verified) {
      return res.status(403).json({ 
        error: 'Tu cuenta no está verificada.',
        code: 'EMAIL_NOT_VERIFIED', 
        email: usuario.email 
      });
    }

    // 4. Buscar Perfil Profesional
    const localQuery = 'SELECT * FROM locales WHERE usuario_id = $1';
    const localRes = await pool.query(localQuery, [usuario.usuario_id]);
    
    const tienePerfilProfesional = localRes.rows.length > 0;
    const datosLocal = tienePerfilProfesional ? localRes.rows[0] : null;

    // 5. Generar Token (🔥 AHORA INCLUYE EL ROL)
    const token = jwt.sign(
      { 
        id: usuario.usuario_id, 
        tipo: usuario.tipo,
        rol: usuario.rol || 'USER' // Si es null, es USER
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '30d' }
    );

    // 6. Responder (🔥 DEVOLVEMOS EL ROL AL FRONTEND)
    res.json({ 
      mensaje: 'Bienvenido',
      token: token,
      usuario: { 
        id: usuario.usuario_id, 
        nombre: usuario.nombre_completo,
        email: usuario.email,
        tipo: usuario.tipo,
        foto_url: usuario.foto_url,
        rol: usuario.rol || 'USER' // <--- DATO VITAL PARA EL PANEL
      },
      perfil_profesional: tienePerfilProfesional ? {
        local_id: datosLocal.local_id,
        nombre_fantasia: datosLocal.nombre,
        tipo_actividad: datosLocal.tipo_actividad,
        foto_url: datosLocal.foto_url
      } : null
    });

  } catch (error) {
    console.error("Error Login:", error);
    res.status(500).json({ error: 'Error interno de login' });
  }
});

// ==========================================
// RUTA 49: LOGOUT (DESVINCULAR DISPOSITIVO) 🔌
// ==========================================
app.post('/api/auth/logout', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(200).send('OK'); // Si no hay token, no hacemos nada

  try {
    const token = authHeader.split(' ')[1];
    // Intentamos verificar. Si el token expiró, no importa, igual intentamos limpiar por ID si pudiéramos
    // Pero por seguridad JWT, decodificamos:
    const usuario = jwt.decode(token); // Usamos decode en vez de verify para no fallar si expiró
    
    if (usuario && usuario.id) {
       // BORRAMOS EL TOKEN DE LA BASE DE DATOS
       await pool.query('UPDATE usuarios SET fcm_token = NULL WHERE usuario_id = $1', [usuario.id]);
       console.log(`🔌 Token FCM eliminado para usuario ${usuario.id}`);
    }
    
    res.json({ mensaje: 'Sesión cerrada y dispositivo desvinculado' });

  } catch (error) {
    console.error("Error en logout:", error);
    res.status(200).send('OK'); // Respondemos OK para no trabar la app
  }
});

// RUTA 8: MIS COMPRAS (HISTORIAL COMPLETO CON OTP)
app.get('/api/transaccion/mis-compras', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET); // Asegúrate de usar process.env.JWT_SECRET

    const consulta = `
      SELECT 
        T.transaccion_id,
        T.fecha_operacion,
        T.estado,
        T.cantidad,
        T.monto_total,
        T.tipo_entrega,
        T.aviso_llegada,
        
        -- 🔥 DATOS NUEVOS PARA V11.0
        T.codigo_retiro,   -- Para mostrar el OTP al cliente
        T.motivo_rechazo,  -- Para explicar por qué se canceló

        -- 🔥 DATO CRÍTICO AGREGADO:
        -- Convertimos a ISO String para que Flutter detecte que es un servicio
        TO_CHAR(T.fecha_reserva_inicio, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as fecha_reserva_inicio,
        
        C.nombre_oficial as producto,
        C.foto_url,
        L.nombre as tienda,
        L.whatsapp,
        L.direccion_fisica, 
        ST_Y(L.ubicacion::geometry) as lat_local, 
        ST_X(L.ubicacion::geometry) as lng_local, 
        L.local_id, 
        CASE WHEN CAL.transaccion_id IS NOT NULL THEN true ELSE false END as ya_califico
      FROM transacciones_p2p T
      JOIN locales L ON T.vendedor_id = L.usuario_id
      JOIN catalogo_global C ON T.producto_global_id = C.global_id
      LEFT JOIN calificaciones CAL ON T.transaccion_id = CAL.transaccion_id 
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
// RUTA 5: COMPRA HÍBRIDA MAESTRA (STOCK + AGENDA + NOTIFICACIONES INTELIGENTES) 🛡️
// ==========================================
app.post('/api/transaccion/comprar', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { local_id, items, tipo_entrega, usar_cupon, cupon_id, monto_descuento } = req.body;
  
  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    const comprador_id = usuario.id;
    const nombreComprador = usuario.nombre || "Un cliente"; 

    // 1. Generamos UUID y OTP
    const compraUuid = crypto.randomUUID();
    const generarOTP = () => Math.random().toString(36).substring(2, 6).toUpperCase();
    const codigoRetiro = generarOTP(); 

    await client.query('BEGIN');

    // 2. Buscamos al vendedor
    const localRes = await client.query('SELECT usuario_id, nombre FROM locales WHERE local_id = $1', [local_id]);
    if (localRes.rows.length === 0) throw new Error('Local no encontrado');
    
    const vendedor_id = localRes.rows[0].usuario_id;
    const nombreLocal = localRes.rows[0].nombre;

    if (comprador_id === vendedor_id) throw new Error('No puedes comprarte a ti mismo.');

    // 3. LÓGICA DE CANJE DE CUPÓN 🎟️
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

        // Insertamos el premio
        await client.query(`
            INSERT INTO transacciones_p2p 
            (comprador_id, vendedor_id, producto_global_id, cantidad, monto_total, estado, tipo_entrega, compra_uuid, nombre_snapshot, foto_snapshot, comision_plataforma, codigo_retiro)
            VALUES ($1, $2, NULL, 1, 0, 'APROBADO', $3, $4, $5, $6, 0, $7)
        `, [comprador_id, vendedor_id, tipo_entrega, compraUuid, `🎁 PREMIO: ${nombrePremio}`, "https://cdn-icons-png.flaticon.com/512/4213/4213958.png", codigoRetiro]);
        
      } else {
        throw new Error("Error: No tienes cupones disponibles.");
      }
    }

    // 4. PROCESAMIENTO DE ITEMS
    let montoTotalPedido = 0; 
    let resumenAgenda = ""; // Acumulador de texto para turnos
    
    for (const item of items) {
        // A. Obtener datos reales y BLOQUEAR FILA (CORREGIDO: BLOQUEO ESPECÍFICO) 🛡️
        const queryProd = `
            SELECT 
                I.stock, I.global_id, I.tipo_item, 
                I.requiere_agenda, I.duracion_minutos,
                COALESCE(I.nombre, C.nombre_oficial, 'Producto') as nombre, 
                COALESCE(I.foto_url, C.foto_url) as foto_url
            FROM inventario_local I
            LEFT JOIN catalogo_global C ON I.global_id = C.global_id
            WHERE I.inventario_id = $1 
            FOR UPDATE OF I  -- <--- 🔥 AQUÍ ESTÁ EL CAMBIO (Solo bloqueamos la tabla 'I')
        `;
        const stockRes = await client.query(queryProd, [item.inventario_id]);
        
        if (stockRes.rows.length === 0) throw new Error(`Producto no disponible`);
        const datosReales = stockRes.rows[0];

        // B. Lógica según Tipo
        let fechaInicio = null;
        let fechaFin = null;

        if (datosReales.requiere_agenda) {
            // --- SERVICIO (AGENDA) ---
            if (!item.fecha_reserva) throw new Error(`El servicio ${datosReales.nombre} requiere reservar un horario.`);
            
            fechaInicio = new Date(item.fecha_reserva); 
            const duracionMs = (datosReales.duracion_minutos || 30) * 60000;
            fechaFin = new Date(fechaInicio.getTime() + duracionMs);

            // Validar Colisión
            const colisionRes = await client.query(`
                SELECT 1 FROM transacciones_p2p 
                WHERE vendedor_id = $1 AND estado NOT IN ('CANCELADO', 'RECHAZADO')
                AND ((fecha_reserva_inicio < $3 AND fecha_reserva_fin > $2))
            `, [vendedor_id, fechaInicio.toISOString(), fechaFin.toISOString()]);

            if (colisionRes.rows.length > 0) throw new Error(`El turno ${datosReales.nombre} ya fue ocupado.`);

            // 📝 Agregamos al resumen de agenda para el mensaje final
            // Usamos UTC para asegurar consistencia, o ajustamos timezone si es necesario
            const dia = fechaInicio.getDate().toString().padStart(2, '0');
            const mes = (fechaInicio.getMonth() + 1).toString().padStart(2, '0');
            const hora = fechaInicio.getHours().toString().padStart(2, '0');
            const min = fechaInicio.getMinutes().toString().padStart(2, '0');
            
            resumenAgenda += `\n📅 ${datosReales.nombre}: ${dia}/${mes} a las ${hora}:${min}hs`;

        } else if (datosReales.tipo_item === 'PRODUCTO_STOCK') {
            // --- PRODUCTO FÍSICO ---
            if (datosReales.stock < item.cantidad) throw new Error(`Stock insuficiente: ${datosReales.nombre}`);
            await client.query('UPDATE inventario_local SET stock = stock - $1 WHERE inventario_id = $2', [item.cantidad, item.inventario_id]);
        }

        // C. Insertar Transacción
        const insertTx = `
            INSERT INTO transacciones_p2p 
            (
                comprador_id, vendedor_id, producto_global_id, cantidad, monto_total, 
                estado, tipo_entrega, compra_uuid, nombre_snapshot, foto_snapshot, 
                comision_plataforma, codigo_retiro,
                fecha_reserva_inicio, fecha_reserva_fin,
                cupon_id, monto_descuento -- <--- 2 NUEVAS COLUMNAS
            )
            -- 🔥 CORRECCIÓN AQUÍ: Agregamos $15 y $16
            VALUES ($1, $2, $3, $4, $5, 'PENDIENTE_PAGO', $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        `;
        
        await client.query(insertTx, [
            comprador_id, 
            vendedor_id, 
            datosReales.global_id, 
            item.cantidad, 
            totalItem, 
            tipo_entrega,
            compraUuid,
            datosReales.nombre,   
            datosReales.foto_url,
            0, // Comisión 0
            codigoRetiro,
            fechaInicio, // $12
            fechaFin,    // $13
            cupon_id || null, // $15 (Si es undefined, pasa null)
            0 // $16 (Monto descuento: Ponemos 0 en el item individual, ya que el descuento es al total)
        ]);
    }

    // 5. QUEMAR CUPÓN (UNA SOLA VEZ POR PEDIDO) 🔥
    if (cupon_id) {
        await client.query('UPDATE cupones SET stock_usado = stock_usado + 1 WHERE cupon_id = $1', [cupon_id]);
        await client.query(`UPDATE cupones_wallet SET estado = 'USADO', fecha_uso = NOW() WHERE cupon_id = $1 AND usuario_id = $2`, [cupon_id, comprador_id]);
    }

    await client.query('COMMIT');

    // 6. NOTIFICACIONES HÍBRIDAS INTELIGENTES 🔔
    
    // A. MENSAJE AL VENDEDOR
    // Construimos el mensaje base con el monto y estado
    let cuerpoVendedor = `${nombreComprador} hizo un pedido por $${montoTotalPedido}. Estado: PENDIENTE DE COBRO.${infoPremio}`;
    
    // Si hay agenda, la anexamos
    if (resumenAgenda) {
        cuerpoVendedor += `\n\nTURNOS SOLICITADOS:${resumenAgenda}`;
    }
    
    enviarNotificacion(vendedor_id, tituloNotif, cuerpoVendedor, { tipo: 'VENTA', uuid: compraUuid });


    // B. MENSAJE AL COMPRADOR
    // Mensaje base confirmando el local
    let cuerpoComprador = `Tu pedido en ${nombreLocal} está registrado.`;
    
    // Si hay agenda, le recordamos sus turnos
    if (resumenAgenda) {
        cuerpoComprador += `\n\nGUARDÁ TU TURNO:${resumenAgenda}`;
    }
    
    // El código de retiro SIEMPRE va (para productos o servicios)
    cuerpoComprador += `\n\nCódigo: ${codigoRetiro}`;
    
    enviarNotificacion(comprador_id, "Pedido Realizado ⏳", cuerpoComprador, { tipo: 'COMPRA', uuid: compraUuid });

    res.json({ mensaje: 'Compra realizada con éxito', orden_id: compraUuid });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(400).json({ error: error.message || 'Error en la transacción' });
  } finally {
    client.release();
  }
});

// ==========================================
// RUTA 9: CONVERTIRSE EN VENDEDOR (V12.0 - NIVEL AUTOMÁTICO) 🛡️
// ==========================================
app.post('/api/auth/convertir-vendedor', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  // Recibimos los datos
  const { nombre_tienda, categoria, whatsapp, direccion, tipo_actividad, rubro, lat, long, codigo_socio } = req.body;

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    await client.query('BEGIN'); // Iniciamos transacción

    let socioIdEncontrado = null;

    // 1. VALIDAR CÓDIGO DE SOCIO
    if (codigo_socio) {
      const socioRes = await client.query('SELECT socio_id, usuario_id FROM socios WHERE codigo_referido = $1', [codigo_socio.trim().toUpperCase()]);
      
      if (socioRes.rows.length > 0) {
        const datosSocio = socioRes.rows[0];
        if (datosSocio.usuario_id === usuario.id) {
           throw new Error("¡No puedes usar tu propio código de socio!");
        }
        socioIdEncontrado = datosSocio.socio_id;
      } else {
        throw new Error(`El código "${codigo_socio}" no es válido.`);
      }
    }

    // 2. ACTUALIZAR TIPO DE USUARIO
    const nuevoTipoUsuario = (tipo_actividad === 'SERVICIO') ? 'Profesional' : categoria;
    await client.query(
      'UPDATE usuarios SET tipo = $1 WHERE usuario_id = $2',
      [nuevoTipoUsuario, usuario.id]
    );

    // 3. PREPARAR DATOS
    const latitudFinal = lat || -45.86;
    const longitudFinal = long || -67.48;
    
    let fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/3081/3081559.png'; // Tienda
    if (tipo_actividad === 'SERVICIO') {
        fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/1063/1063376.png'; // Profesional
    }

    // 4. INSERTAR LOCAL (Con casting Geography explícito por seguridad)
    const localQuery = `
      INSERT INTO locales 
      (usuario_id, nombre, categoria, ubicacion, whatsapp, permite_retiro, permite_delivery, direccion_fisica, tipo_actividad, rubro, foto_url, referido_por_socio_id)
      VALUES ($1, $2, $3, ST_SetSRID(ST_MakePoint($4, $5), 4326)::geography, $6, TRUE, FALSE, $7, $8, $9, $10, $11)
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

    await client.query('COMMIT'); // 🔒 TIENDA CREADA

    // 5. ACTUALIZAR NIVEL DEL PADRINO (CRÍTICO: HACERLO ANTES DE RESPONDER) 📈
    if (socioIdEncontrado) {
       try {
           // Esperamos a que se actualice el nivel para asegurar consistencia
           await actualizarNivelSocio(socioIdEncontrado); 
           console.log(`✅ Nivel de socio ${socioIdEncontrado} recalculado.`);
       } catch (lvlError) {
           console.error("⚠️ Error menor actualizando nivel socio:", lvlError.message);
           // No fallamos la request principal, solo logueamos el error
       }
    }

    // 6. RESPONDER
    console.log(`✅ Tienda creada para usuario ID: ${usuario.id}`);
    res.json({ mensaje: '¡Perfil profesional creado exitosamente!' });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Error creando tienda:", error);
    
    if (error.message && (error.message.includes("código") || error.message.includes("propio"))) {
       return res.status(400).json({ error: error.message });
    }
    
    if (!res.headersSent) {
        res.status(500).json({ error: 'Error al crear la tienda.' });
    }
  } finally {
    client.release();
  }
});

// ==========================================
// RUTA 10: VER VENTAS (CON FECHA ISO Y DATA PARA PARCIALES) 📅
// ==========================================
app.get('/api/mi-negocio/ventas', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    const consulta = `
      SELECT 
        T.compra_uuid,
        -- 🔥 CORRECCIÓN FECHA: Convertimos a String ISO exacto para evitar crasheos en Flutter
        TO_CHAR(MAX(T.fecha_operacion), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as fecha,
        
        MAX(T.estado) as estado_global,
        MAX(T.tipo_entrega) as tipo_entrega,
        BOOL_OR(T.aviso_llegada) as aviso_llegada,
        SUM(T.monto_total) as total_orden,
        SUM(T.cantidad) as total_items,
        U.nombre_completo as comprador,
        U.usuario_id as comprador_id,
        U.telefono as telefono_comprador,
        
        -- Agregamos datos vitales para el Rechazo Parcial dentro del JSON
        json_agg(json_build_object(
            'nombre', COALESCE(T.nombre_snapshot, C.nombre_oficial, 'Producto Manual'),
            'cantidad', T.cantidad,
            'foto', COALESCE(T.foto_snapshot, C.foto_url),
            'transaccion_id', T.transaccion_id, -- <--- ESTO ES VITAL PARA RECHAZO PARCIAL
            'monto_total', T.monto_total,       -- <--- Necesario para saber cuánto reembolsar
            'estado', T.estado,                  -- <--- Para saber si este ítem específico ya fue cancelado
            -- 🔥 DATO CRÍTICO AGREGADO:
            'fecha_reserva_inicio', TO_CHAR(T.fecha_reserva_inicio, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        )) as productos

      FROM transacciones_p2p T
      JOIN usuarios U ON T.comprador_id = U.usuario_id
      LEFT JOIN catalogo_global C ON T.producto_global_id = C.global_id
      
      WHERE T.vendedor_id = $1
      GROUP BY T.compra_uuid, U.usuario_id, U.nombre_completo, U.telefono
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
// RUTA 11: CAMBIAR ESTADO (MASTER: PARCIAL + TOTAL + FIDELIZACIÓN) 🛡️
// ==========================================
app.put('/api/mi-negocio/ventas/estado', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  // Recibimos parámetros:
  // - transaccion_id: Si es para rechazar UN producto específico.
  // - compra_uuid: Si es para gestionar TODA la orden.
  const { compra_uuid, transaccion_id, nuevo_estado, codigo_input, motivo } = req.body; 

  const client = await pool.connect(); 

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    await client.query('BEGIN'); // 🔴 INICIO TRANSACCIÓN

    // ==================================================================================
    // ✂️ CASO 1: RECHAZO PARCIAL (Un solo producto) - NUEVA LÓGICA
    // ==================================================================================
    if (transaccion_id && (nuevo_estado === 'CANCELADO' || nuevo_estado === 'RECHAZADO')) {
        
        // A. Buscar el item específico y verificar que pertenece al vendedor
        const itemRes = await client.query(`
            SELECT t.*, u.fcm_token as token_comprador
            FROM transacciones_p2p t
            JOIN usuarios u ON t.comprador_id = u.usuario_id
            WHERE t.transaccion_id = $1 AND t.vendedor_id = $2
            FOR UPDATE
        `, [transaccion_id, usuario.id]);

        if (itemRes.rows.length === 0) throw new Error('Producto no encontrado o no tienes permiso');
        const item = itemRes.rows[0];

        // B. Reembolso Parcial en Mercado Pago
        if (item.mp_payment_id) {
            try {
                console.log(`💸 Reembolsando parcialmente $${item.monto_total}...`);
                const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN_PROD });
                const paymentClient = new Payment(mpClient);
                
                // Refund parcial por el monto exacto del item
                await paymentClient.refund(item.mp_payment_id, { amount: parseFloat(item.monto_total) });
                console.log("✅ Reembolso parcial exitoso.");
            } catch (mpError) {
                console.error("⚠️ Error MP Partial Refund:", mpError);
                throw new Error("No se pudo procesar el reembolso en Mercado Pago.");
            }
        }

        // C. Actualizar DB (Solo esa fila)
        await client.query(
            'UPDATE transacciones_p2p SET estado = $1, motivo_rechazo = $2 WHERE transaccion_id = $3',
            [nuevo_estado, motivo || 'Sin Stock', transaccion_id]
        );

        // D. Notificar (Mensaje específico)
        const msgParcial = `El producto "${item.nombre_snapshot || 'Item'}" fue cancelado por falta de stock. Te hemos reembolsado $${item.monto_total}.`;
        enviarNotificacion(item.comprador_id, "Reembolso Parcial 💰", msgParcial);

        await client.query('COMMIT');
        return res.json({ mensaje: 'Producto cancelado y reembolsado correctamente' });
    }

    // ==================================================================================
    // 📦 CASO 2: GESTIÓN TOTAL DE LA ORDEN (TU LÓGICA ORIGINAL)
    // ==================================================================================

    // 1. OBTENER DATOS DE LA VENTA (Bloqueo de fila)
    const ventaRes = await client.query(`
      SELECT 
        t.*, 
        l.local_id,
        u.usuario_id as comprador_id 
      FROM transacciones_p2p t
      JOIN locales l ON t.vendedor_id = l.usuario_id
      JOIN usuarios u ON t.comprador_id = u.usuario_id
      WHERE t.compra_uuid = $1 AND t.vendedor_id = $2
      FOR UPDATE
    `, [compra_uuid, usuario.id]);

    if (ventaRes.rows.length === 0) {
      throw new Error('Venta no encontrada o no te pertenece');
    }
    const venta = ventaRes.rows[0]; // Usamos la primera fila como referencia del grupo
    const { local_id, comprador_id } = venta;

    // ------------------------------------------------------------
    // 🛡️ CASO A: ENTREGAR PEDIDO (VALIDACIÓN CÓDIGO OTP)
    // ------------------------------------------------------------
    if (nuevo_estado === 'ENTREGADO') {
       if (venta.codigo_retiro) {
          if (!codigo_input) throw new Error('Debes ingresar el código de retiro del cliente');
          if (codigo_input.trim().toUpperCase() !== venta.codigo_retiro) {
             throw new Error('⛔ CÓDIGO INCORRECTO. No entregues el producto.');
          }
       }
    }

    // ------------------------------------------------------------
    // 💸 CASO B: RECHAZAR TOTALMENTE (FULL REFUND)
    // ------------------------------------------------------------
    if (nuevo_estado === 'CANCELADO' || nuevo_estado === 'RECHAZADO') {
        console.log(`🛑 Cancelando venta total ${compra_uuid}...`);
        
        // B.1 Reembolso Total MP
        if (venta.mp_payment_id) {
            try {
                const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN_PROD });
                const paymentClient = new Payment(mpClient);
                await paymentClient.refund(venta.mp_payment_id);
                console.log("✅ Dinero devuelto al cliente (Total).");
            } catch (mpError) {
                console.error("⚠️ Error MP Refund Total:", mpError);
            }
        }

        // B.2 Anular Comisión de Socio
        await client.query(`
            UPDATE historial_comisiones 
            SET estado = 'ANULADA', monto_comision = 0 
            WHERE transaccion_origen_id = $1
        `, [venta.transaccion_id]);
    }

    // ------------------------------------------------------------
    // 2. ACTUALIZAR ESTADO EN DB (Afecta a todas las filas del UUID)
    // ------------------------------------------------------------
    // Nota: Solo actualizamos las que NO fueron canceladas parcialmente antes
    const updateQuery = `
      UPDATE transacciones_p2p 
      SET estado = $1, motivo_rechazo = $2
      WHERE compra_uuid = $3 AND estado != 'CANCELADO'
    `;
    await client.query(updateQuery, [nuevo_estado, motivo || null, compra_uuid]);

    // ------------------------------------------------------------
    // 3. PREPARAMOS NOTIFICACIÓN
    // ------------------------------------------------------------
    let tituloNotif = "Actualización de pedido";
    let mensajeNotif = `Tu pedido está: ${nuevo_estado}`;

    if (nuevo_estado === 'EN CAMINO') mensajeNotif = "¡Tu pedido está en camino! 🚚";
    else if (nuevo_estado === 'LISTO') mensajeNotif = "¡Listo para retirar! Te esperamos en el local 🛍️";
    else if (nuevo_estado === 'CANCELADO' || nuevo_estado === 'RECHAZADO') {
       tituloNotif = "Pedido Cancelado";
       mensajeNotif = "El pedido fue cancelado y tu dinero reembolsado.";
    }

    // ------------------------------------------------------------
    // 4. LÓGICA DE FIDELIZACIÓN (TU CÓDIGO ORIGINAL) 🎟️
    // ------------------------------------------------------------
    if (nuevo_estado === 'ENTREGADO') {
      tituloNotif = "Pedido Entregado";
      
      const checkCanje = await client.query(
        'SELECT 1 FROM transacciones_p2p WHERE compra_uuid = $1 AND producto_global_id IS NULL',
        [compra_uuid]
      );
      
      if (checkCanje.rows.length > 0) {
        mensajeNotif = "¡Esperamos que disfrutes tu premio! 🎁 Gracias por tu fidelidad.";
      } else {
        mensajeNotif = "Gracias por tu compra. ¡Disfrútalo! ⭐";

        const rulesRes = await client.query(
          'SELECT meta_sellos, monto_minimo, premio_descripcion FROM config_fidelizacion WHERE local_id = $1 AND estado = TRUE',
          [local_id]
        );

        if (rulesRes.rows.length > 0) {
          const reglas = rulesRes.rows[0];

          // B.2 Total (Excluyendo cancelados parciales)
          const totalRes = await client.query(
            "SELECT SUM(monto_total) as total FROM transacciones_p2p WHERE compra_uuid = $1 AND estado != 'CANCELADO'",
            [compra_uuid]
          );
          const totalCompra = parseFloat(totalRes.rows[0].total || 0);

          if (totalCompra >= parseFloat(reglas.monto_minimo)) {
            const progresoQuery = `
              INSERT INTO progreso_fidelizacion (usuario_id, local_id, sellos_acumulados, cupones_disponibles)
              VALUES ($1, $2, 1, 0)
              ON CONFLICT (usuario_id, local_id)
              DO UPDATE SET sellos_acumulados = progreso_fidelizacion.sellos_acumulados + 1
              RETURNING sellos_acumulados, cupones_disponibles;
            `;
            const progresoRes = await client.query(progresoQuery, [comprador_id, local_id]);
            let { sellos_acumulados } = progresoRes.rows[0];

            if (sellos_acumulados >= reglas.meta_sellos) {
              await client.query(`
                UPDATE progreso_fidelizacion 
                SET sellos_acumulados = 0, 
                    cupones_disponibles = cupones_disponibles + 1 
                WHERE usuario_id = $1 AND local_id = $2
              `, [comprador_id, local_id]);

              tituloNotif = "¡PREMIO GANADO! 🏆";
              mensajeNotif = `¡Completaste la tarjeta! Ganaste: ${reglas.premio_descripcion}.`;
            } else {
              tituloNotif = "¡Sumaste un Sello! 🎟️";
              mensajeNotif = `Llevas ${sellos_acumulados}/${reglas.meta_sellos} para ganar: ${reglas.premio_descripcion}.`;
            }
          }
        }
      }
    }

    await client.query('COMMIT'); // 🟢 FIN TRANSACCIÓN

    if (typeof enviarNotificacion === 'function') {
       enviarNotificacion(comprador_id, tituloNotif, mensajeNotif);
    }
    
    res.json({ mensaje: 'Estado actualizado', notificacion: mensajeNotif });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("Error update estado:", error.message);
    res.status(400).json({ error: error.message || 'Error al actualizar estado' });
  } finally {
    client.release();
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

// RUTA 13: CREAR PRODUCTO (CORREGIDA v10.2 📸)
app.post('/api/mi-negocio/crear-item', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { 
    nombre, descripcion, precio, foto_url, tipo_item, stock_inicial,
    codigo_barras 
  } = req.body;

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    await client.query('BEGIN');

    // 1. Obtener Local
    const localRes = await client.query('SELECT local_id, categoria FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) throw new Error('No tienes local');
    const { local_id, categoria } = localRes.rows[0];

    let globalId = null;

    // 2. LOGICA GLOBAL
    if (codigo_barras) {
        const checkGlobal = await client.query('SELECT global_id FROM catalogo_global WHERE codigo_barras = $1', [codigo_barras]);
        if (checkGlobal.rows.length > 0) {
            globalId = checkGlobal.rows[0].global_id; 
        } else {
            const insertGlobal = `
              INSERT INTO catalogo_global (nombre_oficial, descripcion, foto_url, categoria, codigo_barras, creado_por_usuario_id)
              VALUES ($1, $2, $3, $4, $5, $6) RETURNING global_id
            `;
            const resG = await client.query(insertGlobal, [nombre, descripcion, foto_url, categoria, codigo_barras, usuario.id]);
            globalId = resG.rows[0].global_id;
        }
    } else {
        const insertGlobal = `INSERT INTO catalogo_global (nombre_oficial, descripcion, foto_url, categoria) VALUES ($1, $2, $3, $4) RETURNING global_id`;
        const resG = await client.query(insertGlobal, [nombre, descripcion, foto_url, categoria]);
        globalId = resG.rows[0].global_id;
    }

    // 3. INSERTAR EN INVENTARIO LOCAL (AHORA GUARDAMOS LA FOTO TAMBIÉN)
    let stock = tipo_item === 'PRODUCTO_STOCK' ? stock_inicial : 9999;

    const insertLocal = `
      INSERT INTO inventario_local 
      (local_id, global_id, precio, stock, tipo_item, codigo_barras, foto_url) 
      VALUES ($1, $2, $3, $4, $5, $6, $7) -- <--- Agregamos $7
    `;
    
    // Pasamos foto_url al final
    await client.query(insertLocal, [local_id, globalId, precio, stock, tipo_item, codigo_barras, foto_url]);

    await client.query('COMMIT');
    res.json({ mensaje: 'Producto creado correctamente' });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("Error creando item:", error);
    res.status(500).json({ error: 'Error al crear producto' });
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

// ==========================================
// RUTA 16: PERFIL PÚBLICO (CON FOTOS, PORTADA, FIDELIZACIÓN Y OFERTAS 🏷️)
// ==========================================
app.get('/api/perfil-publico/:id', async (req, res) => {
  const local_id = req.params.id;
  
  // Leemos el token para saber si es favorito (Opcional)
  const authHeader = req.headers['authorization'];
  let usuarioId = null;
  if (authHeader) {
    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      usuarioId = decoded.id;
    } catch(e) {}
  }

  try {
    // 1. DATOS DEL LOCAL (ACTUALIZADO CON BRANDING)
    const queryLocal = `
      SELECT 
        usuario_id, local_id, nombre, categoria, rubro, 
        COALESCE(foto_perfil, foto_url) as foto_url,
        foto_portada, 
        reputacion, 
        direccion_fisica, whatsapp, hora_apertura, hora_cierre, dias_atencion,
        estado_manual, permite_delivery, permite_retiro,
        pago_efectivo, pago_transferencia, pago_tarjeta
      FROM locales 
      WHERE local_id = $1
    `;
    
    const localRes = await pool.query(queryLocal, [local_id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });

    // 2. PRODUCTOS (HÍBRIDO + ORDENAMIENTO OFERTAS)
    const queryProductos = `
      SELECT 
        I.inventario_id, 
        COALESCE(I.nombre, C.nombre_oficial) as nombre_oficial, 
        COALESCE(I.foto_url, C.foto_url) as foto_url, 
        COALESCE(I.descripcion, C.descripcion) as descripcion,
        I.precio, 
        I.stock, 
        I.tipo_item,
        
        -- Datos de Oferta
        I.categoria_interna,
        I.precio_regular,

        -- 🔥 DATOS DE AGENDA (FALTABAN AQUÍ) 🔥
        I.requiere_agenda,
        I.duracion_minutos

      FROM inventario_local I 
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id 
      WHERE I.local_id = $1
      AND I.stock > 0        -- FILTRO DE SEGURIDAD 1 (Hay mercadería)
      AND I.precio > 0
      
      -- Filtro Stock: Si es agenda (servicio), ignoramos stock. Si es producto, debe ser > 0
      AND (I.requiere_agenda = TRUE OR I.stock > 0)
      
      -- 🔥 ORDENAMIENTO ESTRATÉGICO 🔥
      -- 1. Ofertas Flash (Urgente)
      -- 2. Ofertas Especiales
      -- 3. Productos normales (lo más nuevo arriba)
      ORDER BY 
        CASE 
            WHEN I.categoria_interna = 'OFERTA_FLASH' THEN 1
            WHEN I.categoria_interna = 'OFERTA_ESPECIAL' THEN 2
            ELSE 3 
        END,
        I.inventario_id DESC
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

    // 5. FIDELIZACIÓN
    let datosFidelidad = null;
    
    const queryFidelidad = `
      SELECT 
        C.meta_sellos,
        C.premio_descripcion,
        C.monto_minimo,
        C.estado as es_activo,
        COALESCE(P.sellos_acumulados, 0) as mis_sellos,
        COALESCE(P.cupones_disponibles, 0) as mis_cupones
      FROM config_fidelizacion C
      LEFT JOIN progreso_fidelizacion P 
        ON C.local_id = P.local_id AND P.usuario_id = $2
      WHERE C.local_id = $1
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
      fidelizacion: datosFidelidad 
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

// RUTA 19: ANALYTICS (TABLERO FINANCIERO PREMIUM) 💎
app.get('/api/mi-negocio/analytics', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    const client = await pool.connect();
    try {
        // 1. OBTENER INFO DEL LOCAL Y PLAN
        const localRes = await client.query(`
            SELECT local_id, plan_tipo, plan_vencimiento 
            FROM locales WHERE usuario_id = $1
        `, [usuario.id]);
        
        if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
        
        const local = localRes.rows[0];
        // Verificamos si es Premium activo
        const esPremium = local.plan_tipo === 'PREMIUM' && new Date(local.plan_vencimiento) > new Date();

        // 2. KPI PRINCIPALES (Totales)
        const kpiQuery = `
          SELECT 
            COALESCE(SUM(monto_total), 0) as ingresos_totales,
            COUNT(*) as cantidad_ventas,
            COALESCE(AVG(monto_total), 0) as ticket_promedio
          FROM transacciones_p2p 
          WHERE vendedor_id = $1 AND estado = 'APROBADO'
        `;
        const kpiRes = await client.query(kpiQuery, [usuario.id]);

        // 3. GRÁFICO SEMANAL (Últimos 7 días) 📊
        // Devuelve: fecha (2023-10-25) y total vendido ese día
        const chartQuery = `
            SELECT 
                to_char(fecha_operacion, 'YYYY-MM-DD') as fecha,
                SUM(monto_total) as total
            FROM transacciones_p2p
            WHERE vendedor_id = $1 
              AND estado = 'APROBADO'
              AND fecha_operacion >= NOW() - INTERVAL '6 days'
            GROUP BY 1
            ORDER BY 1 ASC
        `;
        const chartRes = await client.query(chartQuery, [usuario.id]);

        // 4. RANKING PRODUCTOS (Usamos nombre_snapshot para historia fiel)
        const topQuery = `
          SELECT 
            nombre_snapshot as nombre_oficial, 
            SUM(cantidad) as total_unidades,
            SUM(monto_total) as total_dinero,
            foto_snapshot as foto_url
          FROM transacciones_p2p
          WHERE vendedor_id = $1 AND estado = 'APROBADO'
          GROUP BY nombre_snapshot, foto_snapshot
          ORDER BY total_unidades DESC
          LIMIT 5
        `;
        const topRes = await client.query(topQuery, [usuario.id]);

        // 5. INSIGHTS PREMIUM (Simulados o Reales)
        // Si no es premium, mandamos null o data parcial para que el front bloquee
        let insights = null;
        if (esPremium) {
            // Ejemplo: Hora pico (Query real)
            const horaPicoRes = await client.query(`
                SELECT EXTRACT(HOUR FROM fecha_operacion) as hora, COUNT(*) as cant
                FROM transacciones_p2p WHERE vendedor_id = $1 GROUP BY 1 ORDER BY 2 DESC LIMIT 1
            `, [usuario.id]);
            
            insights = {
                hora_pico: horaPicoRes.rows.length > 0 ? `${horaPicoRes.rows[0].hora}:00 hs` : "--",
                proyeccion_mes: kpiRes.rows[0].ingresos_totales * 1.2 // Algoritmo simple de proyección
            };
        }

        res.json({
          es_premium: esPremium,
          kpis: kpiRes.rows[0],
          chart_data: chartRes.rows,
          top_productos: topRes.rows,
          insights: insights
        });

    } finally {
        client.release();
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al calcular analytics' });
  }
});

// ==========================================
// RUTA 20: ACTUALIZAR CONFIGURACIÓN COMPLETA (CORREGIDA ✅)
// ==========================================
app.put('/api/mi-negocio/actualizar-todo', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { 
    nombre, direccion, whatsapp, rubro,
    hora_apertura, hora_cierre, dias_atencion,
    permite_delivery, permite_retiro,
    pago_efectivo, pago_transferencia, pago_tarjeta,
    en_vacaciones, notif_nuevas_ventas, notif_preguntas, 
    foto_perfil, foto_portada // Campos nuevos
  } = req.body;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

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
        en_vacaciones = $13,
        notif_nuevas_ventas = $14,
        notif_preguntas = $15,
        
        -- LÓGICA DE ESTADO (Aquí faltaba la coma) 👇
        estado_manual = CASE WHEN $13 = TRUE THEN 'CERRADO' ELSE estado_manual END, 
        
        -- FOTOS (Con COALESCE para no borrar si viene null)
        foto_perfil = COALESCE($17, foto_perfil),
        foto_portada = COALESCE($18, foto_portada)

      WHERE usuario_id = $16
      RETURNING nombre, foto_perfil, foto_portada, estado_manual, rubro
    `;
    
    // El orden del array debe coincidir EXACTAMENTE con los números $
    const result = await pool.query(updateQuery, [
      nombre, direccion, whatsapp,                        // $1, $2, $3
      hora_apertura, hora_cierre, dias_atencion,          // $4, $5, $6
      rubro, permite_delivery, permite_retiro,            // $7, $8, $9
      pago_efectivo, pago_transferencia, pago_tarjeta,    // $10, $11, $12
      en_vacaciones, notif_nuevas_ventas, notif_preguntas,// $13, $14, $15
      
      usuario.id,   // $16 (Va en el WHERE)
      foto_perfil,  // $17
      foto_portada  // $18
    ]);

    res.json({ mensaje: 'Configuración guardada', 
      perfil: result.rows[0] // <--- Esto permite al Frontend actualizarse sin recargar 
      });

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
// RUTA 22: LEER CONFIGURACIÓN (BLINDADA CON ALIAS) 🛡️
// ==========================================
app.get('/api/mi-negocio/config', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  try {
    const token = authHeader.split(' ')[1];
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // Usamos 'l.' para asegurarnos de que pedimos datos de la tabla LOCALES
    const consulta = `
      SELECT 
        l.local_id,
        l.nombre, 
        l.direccion_fisica as direccion, -- Alias para que Flutter lo entienda
        l.whatsapp, 
        l.rubro,
        l.hora_apertura, 
        l.hora_cierre, 
        l.dias_atencion,
        l.permite_delivery,
        l.permite_retiro,
        l.pago_efectivo,
        l.pago_transferencia,
        l.pago_tarjeta,
        l.en_vacaciones,
        l.notif_nuevas_ventas,
        l.notif_preguntas,
        l.foto_perfil,
        l.foto_portada,
        
        -- Verificamos si tiene token de MP
        (l.mp_access_token IS NOT NULL) as mp_vinculado
        
      FROM locales l 
      WHERE l.usuario_id = $1
    `;
    
    const respuesta = await pool.query(consulta, [usuario.id]);

    if (respuesta.rows.length === 0) {
        // Si no tiene local, devolvemos 404 pero manejado
        return res.status(404).json({ error: 'Local no encontrado' });
    }

    res.json(respuesta.rows[0]);

  } catch (error) {
    console.error("Error GET Config:", error);
    res.status(500).json({ error: 'Error al leer configuración' });
  }
});

// ==========================================
// RUTA 23: ENCENDER FUEGO (ACTIVACIÓN) 🔥
// ==========================================
app.post('/api/mi-negocio/oferta-flash', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'No tienes local' });
    const local_id = localRes.rows[0].local_id;

    // 1. Verificamos que tenga productos flash cargados (Seguridad)
    const checkProd = await pool.query("SELECT 1 FROM inventario_local WHERE local_id = $1 AND categoria_interna = 'OFERTA_FLASH'", [local_id]);
    
    if (checkProd.rowCount === 0) {
        return res.status(400).json({ error: 'No tienes productos marcados como Flash en tu inventario.' });
    }

    // 2. Apagamos anteriores
    await pool.query('UPDATE ofertas_flash SET activa = FALSE WHERE local_id = $1', [local_id]);

    // 3. Encendemos nueva (Título genérico automático)
    const tituloAuto = "¡OFERTAS FLASH DISPONIBLES!";
    const descAuto = "Toca para ver los productos en liquidación.";

    await pool.query(`
      INSERT INTO ofertas_flash (local_id, titulo, descripcion, fecha_fin, activa)
      VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours', TRUE)
    `, [local_id, tituloAuto, descAuto]);

    res.json({ mensaje: '¡Modo Fuego Activado! 🔥 Tu local ahora destaca en el mapa.' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al activar' });
  }
});

// ==========================================
// RUTA 23.2: VER PRODUCTOS CANDIDATOS A FLASH 🔥
// ==========================================
app.get('/api/mi-negocio/ofertas-flash-list', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // Buscamos productos que el usuario YA etiquetó como Flash
    const query = `
      SELECT I.nombre, I.precio, I.precio_regular, I.foto_url 
      FROM inventario_local I
      JOIN locales L ON I.local_id = L.local_id
      WHERE L.usuario_id = $1 
      AND I.categoria_interna = 'OFERTA_FLASH'
      AND I.stock > 0
    `;
    
    const result = await pool.query(query, [usuario.id]);
    
    // Verificamos si ya hay un fuego encendido (para mostrar tiempo restante si quisieras)
    const activeQuery = `
      SELECT fecha_fin FROM ofertas_flash 
      WHERE local_id = (SELECT local_id FROM locales WHERE usuario_id = $1) 
      AND activa = TRUE 
      AND fecha_fin > NOW()
    `;
    const activeRes = await pool.query(activeQuery, [usuario.id]);

    res.json({
      productos: result.rows,
      cantidad: result.rowCount,
      oferta_activa: activeRes.rows.length > 0,
      vence_en: activeRes.rows.length > 0 ? activeRes.rows[0].fecha_fin : null
    });

  } catch (error) {
    console.error("Error fetching flash items:", error);
    res.status(500).json({ error: 'Error al obtener ofertas' });
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
      `${mensaje}. Toca para ver detalle.`,
      { tipo: 'RESPUESTA_SOLICITUD' }
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
        enviarNotificacion(vendedor.usuario_id, `📢 (Radio Ampliado) Alguien busca: ${solicitud.categoria_nombre}`, `Vecino necesita: "${solicitud.mensaje}"`, { tipo: 'NUEVA_OPORTUNIDAD' });
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

// ==========================================
// RUTA 30: OBTENER HISTORIAS DE UN LOCAL (SOLO LISTA + ID) 📸
// ==========================================
app.get('/api/locales/:id/historias', async (req, res) => {
  const local_id = req.params.id;

  try {
    // Solo buscamos las historias activas
    const result = await pool.query(`
      SELECT 
        historia_id, -- 🔥 ESTO ES LO QUE FALTABA PARA EL CONTADOR
        media_url, 
        tipo_media, 
        caption, 
        fecha_creacion 
      FROM historias 
      WHERE local_id = $1 
      AND fecha_expiracion > NOW()
      ORDER BY fecha_creacion ASC
    `, [local_id]);

    // Devolvemos directamente el array, compatible con tu Frontend actual
    res.json(result.rows);

  } catch (e) {
    console.error("Error historias:", e);
    res.status(500).json({ error: 'Error al cargar historias' });
  }
});

// ==========================================
// RUTA 31: FEED EXPLORAR (CORREGIDA v10.4 - Metros Reales + Avatar)
// ==========================================
app.get('/api/historias/feed', async (req, res) => {
  const { lat, lng, radio = 10000 } = req.query; 

  if (!lat || !lng) return res.status(400).json({ error: 'Ubicación requerida' });

  try {
    const query = `
      SELECT 
        H.historia_id,
        H.media_url,
        H.caption,
        H.tipo_media,
        H.fecha_creacion,
        -- Datos del Local
        L.local_id,
        L.nombre as nombre_local,
        -- 🔥 CORRECCIÓN 1: Traemos foto_perfil (Avatar) en vez de foto_url genérica
        COALESCE(L.foto_perfil, L.foto_url) as foto_local, 
        L.rubro,
        L.plan_tipo,
        -- 🔥 CORRECCIÓN 2: Casteo a GEOGRAPHY para obtener METROS reales
        ST_Distance(
          L.ubicacion::geography, 
          ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography
        ) as distancia_metros
      FROM historias H
      JOIN locales L ON H.local_id = L.local_id
      WHERE 
        H.fecha_expiracion > NOW()
        -- Filtro espacial también en geography para precisión
        AND ST_DWithin(
          L.ubicacion::geography, 
          ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography, 
          $3
        )
      ORDER BY 
        (CASE WHEN L.plan_tipo = 'PREMIUM' THEN 0 ELSE 1 END) ASC,
        H.fecha_creacion DESC
      LIMIT 20;
    `;

    const result = await pool.query(query, [parseFloat(lng), parseFloat(lat), parseFloat(radio)]);
    res.json(result.rows);

  } catch (error) {
    console.error("Error Feed:", error);
    res.status(500).json({ error: 'Error cargando feed' });
  }
});

// RUTA: REPORTAR HISTORIA (MODO SEGURO: SOLO REGISTRA) 🛡️
app.post('/api/historias/:id/reportar', async (req, res) => {
  const { id } = req.params;
  const { motivo } = req.body; // Ej: 'INAPROPIADO', 'OFENSIVO'

  try {
    // Solo insertamos la denuncia en la "Buzón de Quejas"
    // No tocamos la historia original. Inocente hasta que se demuestre lo contrario.
    await pool.query(
      'INSERT INTO denuncias_historias (historia_id, motivo, fecha_denuncia) VALUES ($1, $2, NOW())',
      [id, motivo || 'GENERAL']
    );

    res.json({ success: true, mensaje: 'Reporte enviado a revisión.' });

  } catch (error) {
    console.error("Error reporte:", error);
    // Respondemos success aunque falle para no alertar al usuario malintencionado
    res.json({ success: true }); 
  }
});

// ==========================================
// MÓDULO AUDIENCIAS Y MARKETING (V14.0) 👁️
// ==========================================

// ==========================================
// RUTA 60: REGISTRAR VISTA (ANTI-EGO + SILENCIOSA) 👁️
// ==========================================
app.post('/api/historias/:id/visto', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !req.params.id) return res.status(200).send('OK');
  
  const { id } = req.params; 

  try {
    const token = authHeader.split(' ')[1];
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // 🔥 LOGICA ANTI-EGO (SQL AVANZADO):
    // Solo insertamos si el usuario que mira NO es el dueño del local de esa historia.
    const query = `
      INSERT INTO historias_vistas (historia_id, usuario_id)
      SELECT $1, $2
      WHERE NOT EXISTS (
        SELECT 1 
        FROM historias h 
        JOIN locales l ON h.local_id = l.local_id 
        WHERE h.historia_id = $1 
        AND l.usuario_id = $2 -- Si el usuario es el dueño, esto da true y el NOT EXISTS bloquea
      )
      ON CONFLICT (historia_id, usuario_id) DO NOTHING
    `;

    await pool.query(query, [id, usuario.id]);

    res.status(200).send('OK');
  } catch (error) {
    // Silencioso
    res.status(200).send('OK');
  }
});

// ==========================================
// RUTA 61: OBTENER AUDIENCIA (ESTRICTA: SOLO HISTORIAS ACTIVAS) 📊
// ==========================================
app.get('/api/mi-negocio/estadisticas/audiencia', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // 1. Obtener local y PLAN
    const localRes = await pool.query('SELECT local_id, plan_tipo FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'No tienes local' });
    
    const { local_id, plan_tipo } = localRes.rows[0];

    // 2. Consulta Maestra de Audiencia
    // 🔥 CAMBIO CLAVE: Filtramos por fecha_expiracion > NOW()
    // Solo contamos vistas de historias que AÚN son visibles en la app.
    const query = `
      SELECT DISTINCT ON (U.usuario_id)
        U.usuario_id,
        U.nombre_completo,
        U.foto_url,
        MAX(HV.fecha_vista) as fecha_vista,
        -- Check si ya es seguidor
        (SELECT COUNT(*) FROM favoritos F WHERE F.usuario_id = U.usuario_id AND F.local_id = $1) > 0 as es_seguidor,
        -- Check si ya contactado hoy
        (SELECT COUNT(*) FROM marketing_acciones MA WHERE MA.local_id = $1 AND MA.usuario_destino_id = U.usuario_id AND MA.fecha_accion > NOW() - INTERVAL '24 hours') > 0 as ya_contactado
      FROM historias_vistas HV
      JOIN historias H ON HV.historia_id = H.historia_id
      JOIN usuarios U ON HV.usuario_id = U.usuario_id
      WHERE H.local_id = $1
      AND H.fecha_expiracion > NOW() -- ⏳ SOLO HISTORIAS VIVAS (No vencidas)
      GROUP BY U.usuario_id, U.nombre_completo, U.foto_url
      ORDER BY U.usuario_id, fecha_vista DESC
    `;

    const result = await pool.query(query, [local_id]);

    res.json({
        es_premium: plan_tipo === 'PREMIUM',
        total_vistas: result.rowCount,
        espectadores: result.rows
    });

  } catch (error) {
    console.error("❌ Error audiencia:", error);
    res.status(500).json({ error: 'Error al cargar estadísticas' });
  }
});

// ==========================================
// RUTA 62: MARKETING & REGALO DE CUPONES (V15.0) 🎁
// ==========================================
app.post('/api/mi-negocio/marketing/accion', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  // Recibimos cupon_id (opcional, solo para MIMO)
  const { usuario_destino_id, tipo_accion, cupon_id } = req.body; 

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // 1. Obtener datos del local
    const localRes = await pool.query('SELECT local_id, nombre, plan_tipo FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const local = localRes.rows[0];

    // 🛑 VALIDACIÓN PREMIUM
    if (local.plan_tipo !== 'PREMIUM') {
        return res.status(403).json({ error: 'Función exclusiva para Socios Premium 💎' });
    }

    // 2. Registrar Acción (Anti-Spam)
    // Nota: Podrías querer validar aquí si ya se mandó hoy para no gastar saldo o molestar
    await pool.query(
        'INSERT INTO marketing_acciones (local_id, usuario_destino_id, tipo_accion) VALUES ($1, $2, $3)',
        [local.local_id, usuario_destino_id, tipo_accion]
    );

    // --- LÓGICA POR TIPO ---

    if (tipo_accion === 'INVITAR') {
        // Invitación simple a seguir el perfil
        enviarNotificacion(
            usuario_destino_id,
            `👋 ¡${local.nombre} te invita!`,
            "Les encantó que visitaras sus historias. Sigue al local para no perderte nada.",
            { tipo: 'PERFIL_LOCAL', id: local.local_id.toString() }
        );
    } 
    
    else if (tipo_accion === 'MIMO') {
        // Regalo de Cupón Real
        if (!cupon_id) return res.status(400).json({ error: 'Debes seleccionar un cupón para regalar.' });

        // A. Verificar que el cupón existe y es del local
        const cuponRes = await pool.query('SELECT * FROM cupones WHERE cupon_id = $1 AND local_id = $2', [cupon_id, local.local_id]);
        if (cuponRes.rows.length === 0) return res.status(404).json({ error: 'Cupón inválido' });
        const cupon = cuponRes.rows[0];

        // B. Insertar en la Billetera del Usuario (Wallet)
        // Usamos ON CONFLICT para no fallar si ya se lo regalamos antes (simplemente no hace nada o actualiza fecha)
        await pool.query(`
            INSERT INTO cupones_wallet (usuario_id, cupon_id, estado) 
            VALUES ($1, $2, 'DISPONIBLE')
            ON CONFLICT (usuario_id, cupon_id) 
            DO UPDATE SET fecha_asignacion = NOW(), estado = 'DISPONIBLE'
        `, [usuario_destino_id, cupon_id]);

        // C. Notificar con Payload Especial
        let textoDescuento = cupon.tipo_descuento === 'PORCENTAJE' ? `${cupon.valor_descuento}% OFF` : `$${cupon.valor_descuento} OFF`;
        
        enviarNotificacion(
            usuario_destino_id,
            `🎁 ¡Regalo de ${local.nombre}!`,
            `Te enviaron un cupón de ${textoDescuento}. Toca para guardarlo en tu billetera.`,
            { tipo: 'NUEVO_CUPON' } // Esto abrirá MisCuponesScreen
        );
    }

    res.json({ success: true, mensaje: 'Acción enviada con éxito' });

  } catch (error) {
    console.error("Error marketing:", error);
    res.status(500).json({ error: 'Error al procesar acción' });
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
// RUTA DE PAGOS: CHECKOUT MP (HÍBRIDO + VALIDACIÓN AGENDA) 🛡️
// ==========================================
app.post('/api/pagos/crear-preferencia', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  // items trae: { inventario_id, cantidad, precio, nombre, fecha_reserva? }
  const { items, local_id, tipo_entrega, cupon_id, monto_descuento } = req.body; 

  if (!local_id) return res.status(400).json({ error: 'Falta el ID del local' });

  try {
    const token = authHeader.split(' ')[1];
    const usuarioComprador = jwt.verify(token, process.env.JWT_SECRET);

    // 1. BUSCAR VENDEDOR
    const queryLocal = 'SELECT mp_access_token, nombre, usuario_id FROM locales WHERE local_id = $1';
    const localRes = await pool.query(queryLocal, [local_id]);

    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const sellerData = localRes.rows[0];
    const sellerToken = sellerData.mp_access_token;

    if (!sellerToken) return res.status(400).json({ error: `El local "${sellerData.nombre}" no tiene pagos activos.` });

    // 2. VALIDACIÓN DE AGENDA (DOUBLE CHECK) 🔥
    // Antes de generar el link, verificamos si los turnos siguen libres
    for (const item of items) {
        if (item.fecha_reserva) {
            // Buscamos duración en DB
            const prodRes = await pool.query('SELECT duracion_minutos, nombre FROM inventario_local WHERE inventario_id = $1', [item.inventario_id]);
            if (prodRes.rows.length > 0) {
                const prodDB = prodRes.rows[0];
                const fechaInicio = new Date(item.fecha_reserva);
                const duracion = (prodDB.duracion_minutos || 30) * 60000;
                const fechaFin = new Date(fechaInicio.getTime() + duracion);

                // Chequeo de colisión
                const colisionRes = await pool.query(`
                    SELECT 1 FROM transacciones_p2p 
                    WHERE vendedor_id = $1 AND estado NOT IN ('CANCELADO', 'RECHAZADO')
                    AND ((fecha_reserva_inicio < $3 AND fecha_reserva_fin > $2))
                `, [sellerData.usuario_id, fechaInicio.toISOString(), fechaFin.toISOString()]);

                if (colisionRes.rows.length > 0) {
                    return res.status(409).json({ error: `El turno ${prodDB.nombre} ya fue ocupado.` });
                }
            }
        }
    }

    // 3. GENERAR REFERENCIA
    const externalRef = `CM-${Date.now()}-${usuarioComprador.id}`;

    // 4. PREPARAR ITEMS
    let totalVenta = 0;
    
    // Metadata enriquecida (Incluye fecha_reserva para que el Webhook sepa bloquear)
    const itemsParaMetadata = items.map(i => ({
      id: i.inventario_id,
      cant: Number(i.cantidad),
      precio: Number(i.precio),
      title: i.nombre,
      fecha_reserva: i.fecha_reserva // <--- ESTO ES VITAL PARA EL WEBHOOK
    }));

    const itemsMP = items.map(item => {
      const precio = Number(item.precio);
      const cantidad = Number(item.cantidad);
      totalVenta += precio * cantidad;
      
      const descripcionItem = item.descripcion ? item.descripcion.substring(0, 250) : item.nombre;

      return {
        id: item.inventario_id.toString(),
        title: item.nombre,
        description: descripcionItem,
        category_id: 'others',
        quantity: cantidad,
        unit_price: precio,
        currency_id: 'ARS',
      };
    });

    // 🔥 APLICAR DESCUENTO EN MERCADO PAGO
    if (monto_descuento && monto_descuento > 0) {
        itemsMP.push({
            id: 'CUPON',
            title: 'Descuento Aplicado',
            description: 'Cupón de descuento CercaMío',
            category_id: 'coupon',
            quantity: 1,
            unit_price: -parseFloat(monto_descuento), // PRECIO NEGATIVO (Resta al total)
            currency_id: 'ARS'
        });
    }

    // Calcular comisión sobre el total REAL (post-descuento)
    // Recalculamos totalVenta restando el descuento para que la comisión sea justa
    const totalConDescuento = totalVenta - (parseFloat(monto_descuento) || 0);
    const comisionCercaMio = Math.round((totalConDescuento * 0.01) * 100) / 100;

    // 5. CONFIGURAR CLIENTE
    const sellerClient = new MercadoPagoConfig({ accessToken: sellerToken });
    const preference = new Preference(sellerClient);

    const body = {
      items: itemsMP,
      marketplace_fee: comisionCercaMio,
      external_reference: externalRef, 
      metadata: {
        comprador_id: usuarioComprador.id,
        vendedor_id: sellerData.usuario_id,
        local_id: local_id,
        tipo_entrega: tipo_entrega || 'RETIRO',
        nombre_local: sellerData.nombre, // Para notificación
        items_json: JSON.stringify(itemsParaMetadata) // Aquí viaja la fecha
      },
      back_urls: {
        success: "cercamio://payment-result", 
        failure: "cercamio://payment-result",
        pending: "cercamio://payment-result"
      },
      auto_return: "approved",
      notification_url: "https://api.cercamio.app/api/pagos/webhook",
      statement_descriptor: "CERCAMIO APP"
    };

    const result = await preference.create({ body });

    res.json({ id: result.id, link_pago: result.init_point });

  } catch (error) {
    console.error("Error Split Payment:", error);
    res.status(500).json({ error: 'Error procesando pago' });
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
    const redirectUri = 'https://api.cercamio.app/api/pagos/callback';
    
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
// RUTA 36: CALLBACK Y GUARDADO DE CREDENCIALES (CORREGIDO)
// ==========================================
app.get('/api/pagos/callback', async (req, res) => {
  const { code, state } = req.query; // 'state' es el local_id

  if (!code || !state) {
    return res.send("Error: Datos incompletos desde Mercado Pago.");
  }

  try {
    // 1. Canjeamos el código por las credenciales
    // USAMOS VARIABLES DE ENTORNO POR SEGURIDAD
    const response = await fetch('https://api.mercadopago.com/oauth/token', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN_PROD}` 
      },
      body: JSON.stringify({
        client_secret: process.env.MP_CLIENT_SECRET, // <--- AGREGAR A .ENV
        client_id: process.env.MP_CLIENT_ID,         // <--- AGREGAR A .ENV
        grant_type: 'authorization_code',
        code: code,
        // Esta URL debe coincidir EXACTAMENTE con la configurada en MP
        redirect_uri: 'https://api.cercamio.app/api/pagos/callback'
      })
    });

    const data = await response.json();

    if (data.access_token) {
      // 2. Guardamos en Base de Datos
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
        state 
      ]);

      console.log(`✅ Local ${state} vinculado exitosamente.`);

      // 3. RESPUESTA INTELIGENTE (Deep Link)
      // Esto hace que el celular abra la App automáticamente
      const deepLink = `cercamio://success?local_id=${state}`;

      res.send(`
        <html>
          <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
              body { font-family: sans-serif; text-align: center; padding: 40px; }
              .btn { 
                background-color: #009EE3; color: white; padding: 15px 30px; 
                text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px;
              }
            </style>
          </head>
          <body>
            <h1 style="color: #4CAF50;">¡Vinculación Exitosa! 🎉</h1>
            <p>Ya puedes recibir cobros en CercaMío.</p>
            <br><br>
            
            <!-- EL BOTÓN QUE ABRE LA APP -->
            <a href="${deepLink}" class="btn">VOLVER A LA APP</a>
            
            <!-- SCRIPT DE AUTO-REDIRECCIÓN -->
            <script>
              setTimeout(function() {
                window.location.href = "${deepLink}";
              }, 1000);
            </script>
          </body>
        </html>
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
// RUTA 37: WEBHOOK MAESTRO (VENTAS + SUSCRIPCIONES + SOCIOS) 💎
// ==========================================
app.post('/api/pagos/webhook', async (req, res) => {
  const { type, data } = req.body;

  if (type === 'payment') {
    try {
      const paymentId = data.id;
      
      const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN_PROD });
      const paymentClient = new Payment(client); 
      const paymentData = await paymentClient.get({ id: paymentId });

      if (paymentData.status === 'approved') {
        
        const externalRef = paymentData.external_reference; 
        console.log(`🔔 Webhook Aprobado. ID: ${paymentId} | Ref: ${externalRef}`);

        // ====================================================
        // CASO A: SUSCRIPCIÓN PREMIUM (SaaS) 💎
        // ====================================================
        if (externalRef && externalRef.startsWith('SUB-')) {
            const checkSusc = await pool.query('SELECT 1 FROM pagos_suscripciones WHERE mp_payment_id = $1', [paymentId.toString()]);

            if (checkSusc.rows.length > 0) return res.status(200).send("OK");

            const { local_id, dias_duracion } = paymentData.metadata;
            const diasAgregar = Number(dias_duracion) || 30; 
            const monto = paymentData.transaction_amount;

            const clientDb = await pool.connect();
            try {
                await clientDb.query('BEGIN');
                
                // Actualizar Vencimiento
                await clientDb.query(`
                  UPDATE locales SET plan_tipo = 'PREMIUM',
                  plan_vencimiento = CASE WHEN plan_vencimiento > NOW() THEN plan_vencimiento + make_interval(days => $2) ELSE NOW() + make_interval(days => $2) END
                  WHERE local_id = $1
                `, [local_id, diasAgregar]);

                // Registrar Pago
                await clientDb.query(`
                  INSERT INTO pagos_suscripciones (mp_payment_id, local_id, monto_pagado, dias_agregados) VALUES ($1, $2, $3, $4)
                `, [paymentId.toString(), local_id, monto, diasAgregar]);

                await clientDb.query('COMMIT');
                enviarNotificacion(paymentData.metadata.user_id_dueno, "¡Plan Activado! 🚀", "Tu suscripción Premium ya está vigente.");

            } catch (errSusc) {
                await clientDb.query('ROLLBACK');
                console.error("❌ Error DB Suscripción:", errSusc);
            } finally {
                clientDb.release();
            }
        } 

        // ====================================================
        // CASO B: VENTA MARKETPLACE (E-COMMERCE + SOCIOS + AGENDA + CUPONES) 🛒
        // ====================================================
        else if (externalRef && externalRef.startsWith('CM-')) {
            
            const checkDuplicado = await pool.query('SELECT 1 FROM transacciones_p2p WHERE mp_payment_id = $1', [paymentId.toString()]);
            if (checkDuplicado.rows.length > 0) return res.status(200).send("OK");

            // Datos
            const meta = paymentData.metadata;
            const compradorId = meta.comprador_id;
            const vendedorId = meta.vendedor_id;
            let itemsComprados = typeof meta.items_json === 'string' ? JSON.parse(meta.items_json) : meta.items_json;
            const tipoEntrega = meta.tipo_entrega;
            const totalPagado = paymentData.transaction_amount;
            const compraUuid = crypto.randomUUID();
            
            // 🔥 DATOS DE CUPÓN (NUEVO)
            const cuponId = meta.cupon_id || null;
            const montoDescuento = meta.monto_descuento || 0;

            // Generar OTP Seguro
            const generarOTP = () => Math.random().toString(36).substring(2, 6).toUpperCase();
            const codigoRetiro = generarOTP(); 

            const clientDb = await pool.connect(); 
            
            try {
              await clientDb.query('BEGIN');

              // 1. BUSCAR DATOS DEL SOCIO
              const socioRes = await clientDb.query(`
                  SELECT L.local_id, L.referido_por_socio_id, S.porcentaje_ganancia
                  FROM locales L
                  LEFT JOIN socios S ON L.referido_por_socio_id = S.socio_id
                  WHERE L.usuario_id = $1
              `, [vendedorId]);
              
              const localInfo = socioRes.rows[0];
              const socioId = localInfo?.referido_por_socio_id;
              const porcentajeSocio = socioId ? parseFloat(localInfo.porcentaje_ganancia || 5.00) : 0;
              const localId = localInfo?.local_id;

              let comisionTotalOrden = 0;
              let ultimoTransaccionId = null;
              let resumenAgenda = ""; 

              // 2. PROCESAR CADA PRODUCTO
              for (const item of itemsComprados) {
                 // A. Validar Stock y Datos Reales
                 const queryProducto = `
                    SELECT 
                        I.stock, I.global_id, I.tipo_item, I.duracion_minutos,
                        COALESCE(I.nombre, C.nombre_oficial, 'Producto') as nombre,
                        COALESCE(I.foto_url, C.foto_url) as foto_url
                    FROM inventario_local I
                    LEFT JOIN catalogo_global C ON I.global_id = C.global_id
                    WHERE I.inventario_id = $1 
                    FOR UPDATE
                 `;
                 const prodRes = await clientDb.query(queryProducto, [item.id]);
                 
                 const datosReales = prodRes.rows.length > 0 ? prodRes.rows[0] : { global_id: null, nombre: item.title, foto_url: null, tipo_item: 'PRODUCTO_STOCK', stock: 0, duracion_minutos: 30 };

                 if (datosReales.tipo_item === 'PRODUCTO_STOCK') {
                    await clientDb.query('UPDATE inventario_local SET stock = stock - $1 WHERE inventario_id = $2', [item.cant, item.id]);
                 }

                 // B. Agenda
                 let fechaInicio = null;
                 let fechaFin = null;
                 if (item.fecha_reserva) {
                     fechaInicio = new Date(item.fecha_reserva);
                     const duracion = (datosReales.duracion_minutos || 30) * 60000;
                     fechaFin = new Date(fechaInicio.getTime() + duracion);
                     const dia = fechaInicio.getDate().toString().padStart(2, '0');
                     const mes = (fechaInicio.getMonth() + 1).toString().padStart(2, '0');
                     const hora = fechaInicio.getHours().toString().padStart(2, '0');
                     const min = fechaInicio.getMinutes().toString().padStart(2, '0');
                     resumenAgenda += `\n📅 ${datosReales.nombre}: ${dia}/${mes} ${hora}:${min}hs`;
                 }

                 // C. Calcular Comisión (Base: Precio Real del producto)
                 // Nota: CercaMío cobra comisión sobre el precio de lista, aunque haya descuento.
                 const totalItem = item.precio * item.cant;
                 const comisionItem = Math.round((totalItem * 0.01) * 100) / 100;
                 comisionTotalOrden += comisionItem;

                 // D. Insertar Transacción (CON CUPÓN) 🔥
                 const insertTx = `
                    INSERT INTO transacciones_p2p 
                    (
                      comprador_id, vendedor_id, producto_global_id, cantidad, monto_total, 
                      estado, tipo_entrega, mp_payment_id, fecha_operacion,
                      compra_uuid, nombre_snapshot, foto_snapshot, codigo_retiro,
                      comision_plataforma, fecha_reserva_inicio, fecha_reserva_fin,
                      cupon_id, monto_descuento -- <--- NUEVOS
                    )
                    VALUES ($1, $2, $3, $4, $5, 'APROBADO', $6, $7, NOW(), $8, $9, $10, $11, $12, $13, $14, $15, $16)
                    RETURNING transaccion_id
                 `;
                 
                 const txRes = await clientDb.query(insertTx, [
                    compradorId, vendedorId, datosReales.global_id, item.cant, totalItem, 
                    tipoEntrega, paymentId.toString(), compraUuid, datosReales.nombre, datosReales.foto_url,
                    codigoRetiro, comisionItem,
                    fechaInicio, fechaFin,
                    cuponId, 0 // Guardamos ID de cupón en todas las filas, pero monto 0 individual (descuento global)
                 ]);
                 
                 ultimoTransaccionId = txRes.rows[0].transaccion_id;
              }

              // 3. PAGAR AL SOCIO
              if (socioId && comisionTotalOrden > 0) {
                 const gananciaSocio = Math.round((comisionTotalOrden * (porcentajeSocio / 100)) * 100) / 100;
                 if (gananciaSocio > 0) {
                    await clientDb.query('UPDATE socios SET saldo_acumulado = saldo_acumulado + $1 WHERE socio_id = $2', [gananciaSocio, socioId]);
                    
                    await clientDb.query(`
                        INSERT INTO historial_comisiones (socio_id, transaccion_origen_id, local_origen_id, monto_comision, porcentaje_aplicado, base_calculo_plataforma)
                        VALUES ($1, $2, $3, $4, $5, $6)
                    `, [socioId, ultimoTransaccionId, localId, gananciaSocio, porcentajeSocio, comisionTotalOrden]);
                 }
              }

              // 5. QUEMAR CUPÓN (UNA VEZ) 🔥
              if (cuponId) {
                  await clientDb.query('UPDATE cupones SET stock_usado = stock_usado + 1 WHERE cupon_id = $1', [cuponId]);
                  await clientDb.query(`UPDATE cupones_wallet SET estado = 'USADO', fecha_uso = NOW() WHERE cupon_id = $1 AND usuario_id = $2`, [cuponId, compradorId]);
              }

              await clientDb.query('COMMIT');
              
              // 4. NOTIFICACIONES
              let msgVendedor = `Recibiste $${totalPagado}. Entrega: ${tipoEntrega}`;
              if (resumenAgenda) msgVendedor += `\n\nTURNOS:${resumenAgenda}`;
              if (cuponId) msgVendedor += `\n\n🎟️ Cupón aplicado.`; // Aviso al vendedor
              
              enviarNotificacion(vendedorId, "¡Nueva Venta Online! 💳", msgVendedor, { tipo: 'VENTA', uuid: compraUuid });
              
              let msgComprador = `Tu pedido fue confirmado.`;
              if (resumenAgenda) msgComprador += `\n\nGUARDÁ TU TURNO:${resumenAgenda}`;
              msgComprador += `\n\n🔐 CÓDIGO: ${codigoRetiro}`;

              enviarNotificacion(compradorId, "¡Compra Exitosa! 🛍️", msgComprador, { tipo: 'COMPRA', uuid: compraUuid });

            } catch (dbError) {
              await clientDb.query('ROLLBACK');
              console.error("❌ Error Webhook DB:", dbError);
              return res.status(500).send("DB Error");
            } finally {
              clientDb.release();
            }
        }

        // ====================================================
        // CASO C: VENTA FLEX (POS VIRTUAL) ⚡
        // ====================================================
        else if (externalRef && externalRef.startsWith('FLEX-')) {
            const checkDuplicado = await pool.query('SELECT 1 FROM historial_comisiones WHERE transaccion_origen_id = $1 AND estado = \'FLEX_PAGADO\'', [paymentId.toString()]);
            // Usamos paymentId como ID unico temporal ya que no guardamos transacción completa
            
            if (checkDuplicado.rows.length > 0) return res.status(200).send("OK");

            const meta = paymentData.metadata;
            const vendedorId = meta.vendedor_id;
            const monto = Number(meta.monto_original);
            const comisionPlataforma = Math.round((monto * 0.01) * 100) / 100;

            const clientDb = await pool.connect();
            try {
                await clientDb.query('BEGIN');

                // 1. REPARTO A SOCIO (Si corresponde)
                const socioRes = await clientDb.query(`
                    SELECT L.local_id, L.referido_por_socio_id, S.porcentaje_ganancia
                    FROM locales L
                    LEFT JOIN socios S ON L.referido_por_socio_id = S.socio_id
                    WHERE L.usuario_id = $1
                `, [vendedorId]);

                const localInfo = socioRes.rows[0];
                const socioId = localInfo?.referido_por_socio_id;
                const porcentajeSocio = socioId ? parseFloat(localInfo.porcentaje_ganancia || 5.00) : 0;

                if (socioId && comisionPlataforma > 0) {
                    const gananciaSocio = Math.round((comisionPlataforma * (porcentajeSocio / 100)) * 100) / 100;
                    
                    if (gananciaSocio > 0) {
                        await clientDb.query('UPDATE socios SET saldo_acumulado = saldo_acumulado + $1 WHERE socio_id = $2', [gananciaSocio, socioId]);
                        
                        // Guardamos rastro en historial (Usamos paymentId negativo o string para diferenciar si tu columna es INT, 
                        // pero mejor insertar con transaccion_id NULL si tu schema lo permite. 
                        // ASUMO QUE transaccion_origen_id ES INT. TRUCO: Insertamos 0 o NULL)
                        
                        /* NOTA: Si tu tabla 'historial_comisiones' requiere FK válida a transacciones_p2p, 
                           este insert fallará. Si es nullable, pasamos NULL. 
                           Si es estricto, debemos crear una transacción dummy en p2p.
                           VAMOS A CREAR UNA TRANSACCIÓN DUMMY PARA MANTENER INTEGRIDAD */
                           
                        const txDummy = await clientDb.query(`
                            INSERT INTO transacciones_p2p 
                            (comprador_id, vendedor_id, monto_total, estado, tipo_entrega, mp_payment_id, compra_uuid, nombre_snapshot, fecha_operacion, comision_plataforma)
                            VALUES ($1, $2, $3, 'APROBADO', 'FLEX', $4, $5, 'COBRO RÁPIDO POS', NOW(), $6)
                            RETURNING transaccion_id
                        `, [meta.comprador_id, vendedorId, monto, paymentId.toString(), externalRef, comisionPlataforma]);

                        const txId = txDummy.rows[0].transaccion_id;

                        await clientDb.query(`
                            INSERT INTO historial_comisiones (socio_id, transaccion_origen_id, local_origen_id, monto_comision, porcentaje_aplicado, base_calculo_plataforma, estado)
                            VALUES ($1, $2, $3, $4, $5, $6, 'FLEX_PAGADO')
                        `, [socioId, txId, localInfo.local_id, gananciaSocio, porcentajeSocio, comisionPlataforma]);
                    }
                } else {
                    // Si no hay socio, igual registramos la venta para estadísticas (opcional, pero recomendado)
                     await clientDb.query(`
                        INSERT INTO transacciones_p2p 
                        (comprador_id, vendedor_id, monto_total, estado, tipo_entrega, mp_payment_id, compra_uuid, nombre_snapshot, fecha_operacion, comision_plataforma)
                        VALUES ($1, $2, $3, 'APROBADO', 'FLEX', $4, $5, 'COBRO RÁPIDO POS', NOW(), $6)
                    `, [meta.comprador_id, vendedorId, monto, paymentId.toString(), externalRef, comisionPlataforma]);
                }

                await clientDb.query('COMMIT');
                
                // 2. NOTIFICACIÓN
                enviarNotificacion(vendedorId, "Pago Recibido ⚡", `Cobraste $${monto} con éxito.`, { tipo: 'VENTA_FLEX', monto: monto });

            } catch (errFlex) {
                await clientDb.query('ROLLBACK');
                console.error("❌ Error Webhook Flex:", errFlex);
            } finally {
                clientDb.release();
            }
        }
      }
    } catch (error) {
      console.error("❌ Error Webhook:", error);
      return res.status(500).send("Error interno");
    }
  }

  res.status(200).send("OK");
});

// ==========================================
// RUTA 5.B: PREFERENCIA FLEX (COBRO RÁPIDO POS) ⚡
// ==========================================
app.post('/api/pagos/crear-preferencia-flex', verificarToken, async (req, res) => {
  const { monto, concepto, local_id } = req.body;

  if (!local_id || !monto || monto <= 0) return res.status(400).json({ error: 'Datos inválidos' });

  try {
    // 1. OBTENER CREDENCIALES DEL VENDEDOR
    const queryLocal = 'SELECT mp_access_token, nombre, usuario_id FROM locales WHERE local_id = $1';
    const localRes = await pool.query(queryLocal, [local_id]);

    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const sellerData = localRes.rows[0];
    
    if (!sellerData.mp_access_token) return res.status(400).json({ error: 'Debes vincular Mercado Pago primero.' });

    const vendedorId = sellerData.usuario_id;
    const externalRef = `FLEX-${Date.now()}-${req.usuario.id}`; // Prefijo FLEX clave para el webhook

    // 2. CALCULAR COMISIÓN (1%)
    const comisionCercaMio = Math.round((monto * 0.01) * 100) / 100;

    // 3. CREAR PREFERENCIA
    const sellerClient = new MercadoPagoConfig({ accessToken: sellerData.mp_access_token });
    const preference = new Preference(sellerClient);

    const body = {
      items: [
        {
          id: 'FLEX', // ID Genérico
          title: concepto || "Compra en Local",
          description: "Pago presencial rápido",
          quantity: 1,
          unit_price: Number(monto),
          currency_id: 'ARS',
        }
      ],
      marketplace_fee: comisionCercaMio,
      external_reference: externalRef,
      metadata: {
        tipo: 'FLEX', // Bandera para el Webhook
        comprador_id: req.usuario.id, // Puede ser el mismo vendedor si usa su cel para cobrar a un NN
        vendedor_id: vendedorId,
        local_id: local_id,
        monto_original: monto
      },
      back_urls: {
        success: "cercamio://payment-result",
        failure: "cercamio://payment-result",
      },
      auto_return: "approved",
      notification_url: "https://api.cercamio.app/api/pagos/webhook", // TU URL REAL
      statement_descriptor: "CERCAMIO POS"
    };

    const result = await preference.create({ body });

    // Devolvemos init_point (Link) y qr (Imagen genérica o string QR si MP lo devuelve, por ahora usamos el link)
    res.json({ 
      id: result.id, 
      link_pago: result.init_point,
      qr_code: result.init_point // En web móvil, el link abre la app directo
    });

  } catch (error) {
    console.error("Error Flex:", error);
    res.status(500).json({ error: 'Error al generar cobro' });
  }
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
// RUTA 42: SOLICITAR VERIFICACIÓN DE EMAIL (CON HTML PREMIUM 🎨)
// ==========================================
app.post('/api/auth/send-verification', async (req, res) => {
  const { email } = req.body;
  const codigo = generarCodigo(); // Usa tu función helper existente

  try {
    // 1. Guardamos el código y recuperamos el nombre para personalizar el mail
    const result = await pool.query(
      'UPDATE usuarios SET verification_code = $1 WHERE email = $2 RETURNING nombre_completo',
      [codigo, email]
    );

    if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const nombreUsuario = capitalizarNombre(result.rows[0].nombre_completo);

    // 2. Diseño del Email (Responsive & Branding)
    // Usamos tablas HTML antiguas porque es lo único que soportan todos los clientes de correo
    const htmlEmail = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f8;">
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; margin-top: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
          
          <!-- HEADER AZUL (CONFIANZA) -->
          <tr>
            <td style="background-color: #2196F3; padding: 30px; text-align: center;">
              <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: bold; letter-spacing: 1px;">CercaMío</h1>
              <p style="color: #e3f2fd; margin: 5px 0 0 0; font-size: 14px;">Tu barrio, conectado.</p>
            </td>
          </tr>

          <!-- CUERPO DEL MENSAJE -->
          <tr>
            <td style="padding: 40px 30px;">
              <h2 style="color: #333333; margin-top: 0;">¡Hola, ${nombreUsuario}! 👋</h2>
              <p style="color: #666666; font-size: 16px; line-height: 1.5;">
                Estás a un paso de activar tu cuenta. Usa el siguiente código para verificar tu identidad y asegurar tus compras.
              </p>
              
              <!-- CAJA DEL CÓDIGO (NARANJA - ACCIÓN) -->
              <div style="background-color: #fff3e0; border-left: 4px solid #FF9800; padding: 20px; margin: 30px 0; text-align: center; border-radius: 4px;">
                <span style="display: block; color: #ef6c00; font-size: 12px; font-weight: bold; text-transform: uppercase; margin-bottom: 5px;">Tu código de seguridad</span>
                <span style="font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #333;">${codigo}</span>
              </div>

              <p style="color: #999999; font-size: 14px; text-align: center;">
                Este código expira en 15 minutos.<br>Si no lo solicitaste, simplemente ignora este correo.
              </p>
            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td style="background-color: #f9f9f9; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
              <p style="color: #aaaaaa; font-size: 12px; margin: 0;">
                © 2025 CercaMío App. Comodoro Rivadavia.<br>
                ¿Necesitas ayuda? Responde a este correo.
              </p>
            </td>
          </tr>
        </table>
        <div style="height: 40px;"></div>
      </body>
      </html>
    `;

    // 3. Enviar usando tu función auxiliar (ahora soporta HTML)
    // Parametros: destinatario, asunto, texto_plano (fallback), html
    await enviarEmail(
      email, 
      '🔐 Tu código de verificación CercaMío', 
      `Hola ${nombreUsuario}, tu código es: ${codigo}`, 
      htmlEmail
    );

    res.json({ mensaje: 'Código enviado correctamente' });

  } catch (error) {
    console.error("❌ Error enviando email:", error);
    res.status(500).json({ error: 'Error al enviar el código. Intenta de nuevo.' });
  }
});

// ==========================================
// RUTA 43: CONFIRMAR CÓDIGO DE EMAIL
// ==========================================
app.post('/api/auth/verify-email', async (req, res) => {
  const { email, codigo } = req.body;

  // Validación básica
  if (!email || !codigo) return res.status(400).json({ error: 'Faltan datos' });

  try {
    // 1. Buscamos el código
    const user = await pool.query('SELECT verification_code FROM usuarios WHERE email = $1', [email]);
    
    if (user.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    // 2. Comparamos (Trim para evitar errores de espacios vacíos)
    // Convertimos a string por seguridad
    const codigoReal = user.rows[0].verification_code ? user.rows[0].verification_code.toString() : '';
    const codigoInput = codigo.toString().trim();

    if (codigoReal !== codigoInput) {
      return res.status(400).json({ error: 'Código incorrecto' });
    }

    // 3. Código correcto: Verificamos y limpiamos
    await pool.query(
      'UPDATE usuarios SET email_verified = TRUE, verification_code = NULL WHERE email = $1',
      [email]
    );

    res.json({ mensaje: '¡Cuenta verificada exitosamente! Bienvenido al barrio.' });

  } catch (error) {
    console.error("❌ Error verificando:", error);
    res.status(500).json({ error: 'Error interno al verificar' });
  }
});

// ==========================================
// RUTA 44: OLVIDÉ MI CONTRASEÑA (DISEÑO SECURITY 🔑)
// ==========================================
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const codigo = generarCodigo();

  try {
    // 1. Guardamos el código y recuperamos el nombre
    const result = await pool.query(
      'UPDATE usuarios SET recovery_code = $1 WHERE email = $2 RETURNING nombre_completo',
      [codigo, email]
    );

    if (result.rowCount === 0) return res.status(404).json({ error: 'Email no registrado' });

    const nombreUsuario = capitalizarNombre(result.rows[0].nombre_completo);

    // 2. Diseño HTML (Enfoque: Seguridad y Claridad)
    const htmlEmail = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f8;">
        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; margin-top: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
          
          <!-- HEADER AZUL (MARCA) -->
          <tr>
            <td style="background-color: #1976D2; padding: 30px; text-align: center;">
              <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: bold;">CercaMío</h1>
              <p style="color: #bbdefb; margin: 5px 0 0 0; font-size: 14px;">Recuperación de cuenta</p>
            </td>
          </tr>

          <!-- CUERPO -->
          <tr>
            <td style="padding: 40px 30px;">
              <h2 style="color: #333; margin-top: 0;">Hola, ${nombreUsuario} 🔒</h2>
              <p style="color: #666; font-size: 16px; line-height: 1.5;">
                Recibimos una solicitud para restablecer tu contraseña. Si fuiste tú, usa el siguiente código para crear una nueva clave.
              </p>
              
              <!-- CAJA DEL CÓDIGO (GRIS OSCURO - SERIEDAD) -->
              <div style="background-color: #263238; color: #ffffff; padding: 20px; margin: 30px 0; text-align: center; border-radius: 8px;">
                <span style="display: block; color: #90a4ae; font-size: 11px; text-transform: uppercase; margin-bottom: 5px; letter-spacing: 2px;">CÓDIGO DE RECUPERACIÓN</span>
                <span style="font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #fff;">${codigo}</span>
              </div>

              <p style="color: #d32f2f; font-size: 13px; text-align: center; background-color: #ffebee; padding: 10px; border-radius: 4px;">
                ⚠️ <strong>Importante:</strong> Si no solicitaste este cambio, ignora este correo. Tu cuenta sigue segura.
              </p>
            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td style="background-color: #fafafa; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
              <p style="color: #999; font-size: 12px; margin: 0;">
                Este enlace expira en 15 minutos.<br>
                © 2025 CercaMío Seguridad.
              </p>
            </td>
          </tr>
        </table>
        <div style="height: 40px;"></div>
      </body>
      </html>
    `;

    // 3. Enviar email
    await enviarEmail(
      email, 
      '🔑 Restablecer contraseña - CercaMío', 
      `Tu código de recuperación es: ${codigo}`, 
      htmlEmail
    );

    res.json({ mensaje: 'Código enviado a tu correo.' });

  } catch (error) {
    console.error("❌ Error forgot-password:", error);
    res.status(500).json({ error: 'Error del servidor al procesar la solicitud.' });
  }
});

// ==========================================
// RUTA 45: RESTABLECER CONTRASEÑA (SECURITY CHECK ✅)
// ==========================================
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, codigo, nuevaPassword } = req.body;

  // Validación básica
  if (!email || !codigo || !nuevaPassword) {
    return res.status(400).json({ error: 'Faltan datos requeridos.' });
  }

  try {
    // 1. Validar código en DB
    const user = await pool.query('SELECT recovery_code FROM usuarios WHERE email = $1', [email]);
    
    if (user.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    // Comparación estricta
    const codigoReal = user.rows[0].recovery_code ? user.rows[0].recovery_code.toString() : '';
    const codigoInput = codigo.toString().trim();

    if (codigoReal !== codigoInput) {
      return res.status(400).json({ error: 'El código es incorrecto o ha expirado.' });
    }

    // 2. Hashear la nueva contraseña (Seguridad)
    // Usamos bcryptjs (asegúrate de que esté importado arriba: const bcrypt = require('bcryptjs');)
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(nuevaPassword, salt);

    // 3. Actualizar contraseña y destruir el código usado (One-Time Use)
    await pool.query(
      'UPDATE usuarios SET password_hash = $1, recovery_code = NULL WHERE email = $2',
      [hash, email]
    );

    // Opcional: Podrías enviar un email de "Tu contraseña ha sido cambiada" aquí.
    
    res.json({ mensaje: '¡Contraseña actualizada con éxito! Ya puedes iniciar sesión.' });

  } catch (error) {
    console.error("❌ Error reset-password:", error);
    res.status(500).json({ error: 'Error interno al cambiar la contraseña.' });
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

// ==========================================
// RUTA 47: ACTUALIZAR PERFIL DE USUARIO (OPTIMIZADA v10.1) 👤
// ==========================================
app.put('/api/users/update', upload.single('foto'), async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { nombre, telefono, fecha_nacimiento, direccion, barrio, ciudad, provincia, pais } = req.body;
  
  // Si Cloudinary procesó la foto, req.file.path tiene la URL nueva
  const nuevaFotoUrl = req.file ? req.file.path : null;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // Capitalización (Lógica de negocio en Backend = Bien)
    const capitalizar = (txt) => txt ? txt.toLowerCase().split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') : "";
    const nombreFormateado = capitalizar(nombre);
    const fechaFinal = fecha_nacimiento || null;

    let result;

    if (nuevaFotoUrl) {
      // CASO A: CON FOTO NUEVA
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
        RETURNING nombre_completo, foto_url, telefono, direccion, barrio -- 👈 RETORNAMOS TODO LO VISIBLE
      `;
      
      result = await pool.query(queryConFoto, [
        nombreFormateado, telefono, fechaFinal, direccion, barrio, ciudad, provincia, pais, 
        nuevaFotoUrl, // $9
        usuario.id    // $10
      ]);

    } else {
      // CASO B: SIN FOTO (Mantenemos foto_url existente)
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
        RETURNING nombre_completo, foto_url, telefono, direccion, barrio -- 👈 RETORNAMOS TAMBIÉN
      `;

      result = await pool.query(querySinFoto, [
        nombreFormateado, telefono, fechaFinal, direccion, barrio, ciudad, provincia, pais, 
        usuario.id    // $9
      ]);
    }

    // RESPUESTA AL FRONTEND (DATA FRESCA) 🍎
    res.json({ 
      mensaje: 'Perfil actualizado', 
      usuario: result.rows[0] // Ahora el frontend tiene la URL nueva y el nombre formateado
    });

  } catch (error) {
    console.error("Error ruta 47:", error);
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

// ==========================================
// RUTA 10: SOLICITAR ALTA SOCIO (VERSIÓN FINAL Y LIMPIA)
// ==========================================
app.post('/api/socios/solicitar', uploadPrivado.fields([
  { name: 'dni_frente', maxCount: 1 },
  { name: 'dni_dorso', maxCount: 1 }
]), async (req, res) => {
  
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { cbu_alias, nombre_real } = req.body;
  
  // Validaciones
  const files = req.files;
  if (!files || !files['dni_frente'] || !files['dni_dorso']) {
    return res.status(400).json({ error: 'Faltan las fotos del DNI' });
  }

  const dniFrenteUrl = files['dni_frente'][0].path;
  const dniDorsoUrl = files['dni_dorso'][0].path;

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    await client.query('BEGIN'); // Inicio transacción

    // 1. Generar Código
    const nombreBase = (nombre_real || "SOCIO").substring(0, 3).toUpperCase().replace(/[^A-Z]/g, "X");
    const rand = Math.floor(100 + Math.random() * 900);
    const codigoGenerado = `${nombreBase}-${rand}`;

    // 2. Insertar Socio
    const insertQuery = `
      INSERT INTO socios (usuario_id, codigo_referido, cbu_alias, dni_frente_url, dni_dorso_url, estado)
      VALUES ($1, $2, $3, $4, $5, 'PENDIENTE')
      RETURNING socio_id
    `;

    await client.query(insertQuery, [
      usuario.id, codigoGenerado, cbu_alias, dniFrenteUrl, dniDorsoUrl
    ]);

    await client.query('COMMIT'); // 🔒 GUARDADO CONFIRMADO

    // 3. Responder
    res.json({ mensaje: 'Solicitud enviada correctamente', codigo: codigoGenerado });
    
    console.log(`✅ Nueva solicitud de socio guardada para usuario ID: ${usuario.id}`);

  } catch (error) {
    await client.query('ROLLBACK'); // Solo deshacemos si falla el INSERT
    
    if (error.code === '23505') {
        return res.status(400).json({ error: 'Ya tienes una solicitud en curso.' });
    }
    
    console.error("❌ Error alta socio:", error);
    if (!res.headersSent) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
  } finally {
    client.release();
  }
});

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

// =========================================================
// 💎 GESTIÓN DE SUSCRIPCIONES (PREMIUM)
// =========================================================

// 1. GET: Obtener planes activos para mostrarlos en la App
app.get('/api/suscripciones/planes', async (req, res) => {
  try {
    // Traemos solo los activos y ordenados por "orden_visual"
    const query = 'SELECT * FROM planes_suscripcion WHERE es_activo = TRUE ORDER BY orden_visual ASC';
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error obteniendo planes:", error);
    res.status(500).json({ error: 'Error interno al cargar planes' });
  }
});

// =========================================================
// 💎 CREAR PAGO (VERSIÓN A PRUEBA DE ERRORES)
// =========================================================
app.post('/api/suscripciones/crear-pago', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  // Recibimos local_id (que a veces viene mal) y plan_codigo
  let { local_id, plan_codigo } = req.body; 

  try {
    const token = authHeader.split(' ')[1];
    const usuario = jwt.verify(token, JWT_SECRET);

    // 1. AUTO-CORRECCIÓN DE ID
    // Si local_id viene como el token (texto largo) o está vacío, 
    // lo buscamos nosotros en la base de datos usando el ID del usuario.
    if (!local_id || isNaN(local_id)) {
        console.log("⚠️ local_id inválido recibido. Buscando local del usuario...");
        
        const localSearch = await pool.query(
            'SELECT local_id FROM locales WHERE usuario_id = $1 LIMIT 1', 
            [usuario.id]
        );
        
        if (localSearch.rows.length === 0) {
            return res.status(404).json({ error: 'No tienes un local registrado.' });
        }
        
        // Asignamos el ID correcto
        local_id = localSearch.rows[0].local_id;
        console.log(`✅ Local encontrado automáticamente: ID ${local_id}`);
    }

    // 2. VERIFICACIÓN DE PROPIEDAD
    const localCheck = await pool.query(
        'SELECT nombre FROM locales WHERE local_id = $1 AND usuario_id = $2', 
        [local_id, usuario.id]
    );
    
    if (localCheck.rows.length === 0) {
        return res.status(403).json({ error: 'No eres dueño de este local' });
    }

    // 3. OBTENER PRECIO
    const planRes = await pool.query(
        'SELECT * FROM planes_suscripcion WHERE codigo_interno = $1 AND es_activo = TRUE', 
        [plan_codigo]
    );
    
    if (planRes.rows.length === 0) return res.status(404).json({ error: 'Plan no existe' });
    const plan = planRes.rows[0];

    // 4. MERCADO PAGO
    const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN_PROD });
    const preference = new Preference(client);

    const externalRef = `SUB-${local_id}-${plan.codigo_interno}-${Date.now()}`;

    const body = {
      items: [{
        id: `PLAN-${plan.codigo_interno}`,
        title: `CercaMío PRO: ${plan.titulo}`,
        description: `Suscripción ${plan.dias_duracion} días - ${localCheck.rows[0].nombre}`,
        quantity: 1,
        unit_price: Number(plan.precio),
        currency_id: 'ARS'
      }],
      external_reference: externalRef,
      metadata: { 
          local_id: local_id, 
          plan_codigo: plan.codigo_interno,
          dias_duracion: plan.dias_duracion
      },
      back_urls: {
        success: "cercamio://premium-success", 
        failure: "cercamio://premium-fail",
        pending: "cercamio://premium-pending"
      },
      auto_return: "approved",
      notification_url: "https://api.cercamio.app/api/pagos/webhook",
      statement_descriptor: "CERCAMIO PRO"
    };

    const result = await preference.create({ body });
    res.json({ init_point: result.init_point });

  } catch (error) {
    console.error("❌ Error creando pago:", error);
    // Devolvemos el error en JSON para que el frontend lo muestre en el SnackBar
    res.status(500).json({ error: error.message || 'Error interno' });
  }
});

// ==========================================
// RUTA: OBTENER PERFIL (CORREGIDA SEGÚN ESQUEMA REAL)
// ==========================================
app.get('/api/auth/me', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // CONSULTA SQL PRECISA:
    // u.nombre_completo -> Lo traemos como 'nombre_usuario'
    // l.nombre          -> Lo traemos como 'nombre_fantasia'
    const query = `
      SELECT 
        u.usuario_id, 
        u.nombre_completo, -- <--- CAMPO CORRECTO DE USUARIOS
        u.foto_url, 
        u.tipo, 
        
        l.local_id, 
        l.nombre as nombre_tienda, -- <--- CAMPO CORRECTO DE LOCALES
        l.tipo_actividad, 
        l.mp_access_token,
        l.foto_perfil, 
        l.foto_portada,
        
        s.socio_id, 
        s.estado as estado_socio
      FROM usuarios u
      LEFT JOIN locales l ON u.usuario_id = l.usuario_id
      LEFT JOIN socios s ON u.usuario_id = s.usuario_id
      WHERE u.usuario_id = $1
    `;
    
    const result = await pool.query(query, [decoded.id]);
    
    if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    
    const row = result.rows[0];
    
    // Mapeo para que el Frontend (Flutter) no se rompa
    const respuesta = {
      usuario: {
        id: row.usuario_id,
        // Al frontend le mandamos 'nombre' genérico usando el nombre_completo real
        nombre: row.nombre_completo, 
        foto_url: row.foto_url,
        tipo: row.tipo
      },
      perfil_profesional: row.local_id ? {
        local_id: row.local_id,
        nombre_fantasia: row.nombre_tienda, // El nombre del local
        tipo_actividad: row.tipo_actividad,
        mp_vinculado: !!row.mp_access_token,
        foto_perfil: row.foto_perfil, 
        foto_portada: row.foto_portada
      } : null,
      perfil_socio: row.socio_id ? {
        socio_id: row.socio_id,
        estado: row.estado_socio
      } : null
    };

    res.json(respuesta);

  } catch (error) {
    console.error("Error en /api/auth/me:", error);
    res.status(500).json({ error: 'Error al obtener perfil' });
  }
});

// ==========================================
// RUTA AUXILIAR: SUBIR IMAGEN SUELTA 📸
// ==========================================
app.post('/api/uploads/imagen', upload.single('imagen'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No se subió ningún archivo' });
    }
    // Cloudinary/Multer ya subieron el archivo, devolvemos la URL
    res.json({ url: req.file.path });
  } catch (error) {
    console.error("Error subiendo imagen:", error);
    res.status(500).json({ error: 'Error al subir imagen' });
  }
});

// ==========================================
// RUTA 50: ESCÁNER INTELIGENTE (OPTIMIZADO v10.1) 🚀
// ==========================================
app.get('/api/producto/scan/:codigo', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  // Limpiamos el código (a veces los lectores mandan espacios o saltos de línea)
  const codigo = req.params.codigo.trim();

  try {
    const token = authHeader.split(' ')[1];
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // 1. Obtener Local ID (Cacheable en el futuro, por ahora DB directa es rápida por PK)
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Sin local asociado' });
    const localId = localRes.rows[0].local_id;

    // console.log(`🔍 Escaneando: ${codigo} en Local ${localId}`);

    // --- CAPA 1: BÚSQUEDA LOCAL (PRIORIDAD MÁXIMA) ---
    // NOTA: Quitamos el CAST(). Asumimos que codigo_barras es VARCHAR o BIGINT. 
    // Postgres manejará la comparación usando el índice.
    const queryLocal = `
      SELECT 
        I.inventario_id, I.local_id, I.precio, I.stock, I.tipo_item, I.codigo_barras,
        COALESCE(I.nombre, C.nombre_oficial) as nombre, 
        COALESCE(I.descripcion, C.descripcion) as descripcion,
        COALESCE(I.foto_url, C.foto_url) as foto_url,
        I.categoria_interna
      FROM inventario_local I
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id
      WHERE I.local_id = $1 
      AND I.codigo_barras = $2 
    `;
    
    const localProduct = await pool.query(queryLocal, [localId, codigo]);

    if (localProduct.rows.length > 0) {
      // console.log("✅ ENCONTRADO EN LOCAL");
      return res.json({
        estado: 'EN_INVENTARIO', 
        producto: localProduct.rows[0]
      });
    }

    // --- CAPA 2: BÚSQUEDA GLOBAL (CercaMío DB) ---
    // Usamos el índice de catalogo_global
    const globalProduct = await pool.query(
        'SELECT * FROM catalogo_global WHERE codigo_barras = $1 LIMIT 1', 
        [codigo]
    );

    if (globalProduct.rows.length > 0) {
      // console.log("☁️ ENCONTRADO EN GLOBAL");
      return res.json({
        estado: 'EN_GLOBAL', 
        producto: globalProduct.rows[0]
      });
    }

    // --- CAPA 3: INTERNET (OpenFoodFacts) 🌐 ---
    // console.log("🌍 Buscando en OpenFoodFacts...");
    try {
        const offUrl = `https://world.openfoodfacts.org/api/v0/product/${codigo}.json`;
        
        const apiRes = await axios.get(offUrl, { 
            timeout: 2500, // 2.5s es el límite de paciencia del usuario
            headers: {
                // OFF pide User-Agent para no bloquear
                'User-Agent': 'CercaMioApp - Android - Version 1.0 - www.cercamio.app' 
            }
        });

        if (apiRes.data.status === 1) {
            const p = apiRes.data.product;
            // console.log("🎉 ENCONTRADO EN INTERNET: " + p.product_name);
            
            // Mapeo inteligente de datos (Prioriza Español, luego Inglés)
            const nombreOFF = p.product_name_es || p.product_name || p.generic_name || "";
            const imagenOFF = p.image_front_url || p.image_url || null;
            
            return res.json({
                estado: 'EN_GLOBAL', // Simulamos global para activar autocompletado en front
                producto: {
                    nombre_oficial: nombreOFF,
                    descripcion: p.brands ? `Marca: ${p.brands}` : "",
                    foto_url: imagenOFF,
                    codigo_barras: codigo,
                    origen: 'OFF' // Flag para debugging
                }
            });
        }
    } catch (apiError) {
        // Si falla OFF (timeout o error 500), no bloqueamos el flujo. 
        // Simplemente pasamos a "NUEVO".
        console.warn("⚠️ OFF API falló o tardó:", apiError.message);
    }

    // --- CAPA 4: NO EXISTE (CREAR NUEVO) ---
    // console.log("🆕 PRODUCTO NUEVO");
    res.json({
      estado: 'NUEVO', 
      codigo_barras: codigo
    });

  } catch (error) {
    console.error("❌ ERROR SCAN:", error);
    res.status(500).json({ error: 'Error interno en escáner' });
  }
});

// ==========================================
// RUTA 51: IMPORTAR PACK AUTOMÁTICO (SEGÚN RUBRO) 📦
// ==========================================
app.post('/api/mi-negocio/importar-pack', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  try {
    const token = authHeader.split(' ')[1];
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // 1. Obtener datos del local del usuario
    const localRes = await pool.query('SELECT local_id, rubro FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    
    const { local_id, rubro } = localRes.rows[0];

    // 2. Buscar qué pack corresponde a este rubro
    // Usamos ILIKE para coincidencia flexible (ej: "Kiosco" matchea con "Kiosco / Almacén")
    const packRes = await pool.query('SELECT * FROM packs_plantillas WHERE rubro_target ILIKE $1 LIMIT 1', [`%${rubro}%`]);

    if (packRes.rows.length === 0) {
      return res.status(404).json({ error: `No hay packs disponibles para el rubro ${rubro}` });
    }

    const pack = packRes.rows[0];

    // 3. CLONACIÓN MASIVA (Magia SQL)
    // Insertamos en inventario_local copiando de items_pack.
    // Solo si el nombre NO existe ya en ese local (para evitar duplicados).
    const insertQuery = `
      INSERT INTO inventario_local (local_id, nombre, descripcion, precio, stock, tipo_item, codigo_barras, foto_url)
      SELECT 
        $1, 
        IP.nombre, 
        'Producto importado automáticamente', 
        0,   -- Precio 0 para que el usuario lo edite
        0,   -- Stock 0
        'PRODUCTO_STOCK',
        IP.codigo_barras,
        IP.foto_url
      FROM items_pack IP
      WHERE IP.pack_id = $2
      AND NOT EXISTS (
          SELECT 1 FROM inventario_local IL 
          WHERE IL.local_id = $1 AND IL.nombre = IP.nombre
      )
    `;

    const result = await pool.query(insertQuery, [local_id, pack.pack_id]);

    res.json({ 
      mensaje: 'Importación exitosa', 
      items_agregados: result.rowCount,
      nombre_pack: pack.nombre_pack
    });

  } catch (error) {
    console.error("Error importando pack:", error);
    res.status(500).json({ error: 'Error al importar pack' });
  }
});

// RUTA AUXILIAR: VERIFICAR SI HAY PACK DISPONIBLE (Para mostrar el botón o no)
app.get('/api/mi-negocio/check-pack', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
    try {
        const token = authHeader.split(' ')[1];
        const usuario = jwt.verify(token, process.env.JWT_SECRET);
        
        // Buscamos local y pack compatible en una sola query
        const query = `
            SELECT P.nombre_pack, P.icono, P.descripcion, COUNT(I.item_id) as cantidad_items
            FROM locales L
            JOIN packs_plantillas P ON P.rubro_target ILIKE '%' || L.rubro || '%'
            LEFT JOIN items_pack I ON I.pack_id = P.pack_id
            WHERE L.usuario_id = $1
            GROUP BY P.pack_id
        `;
        const result = await pool.query(query, [usuario.id]);
        
        if (result.rows.length > 0) {
            res.json({ disponible: true, pack: result.rows[0] });
        } else {
            res.json({ disponible: false });
        }
    } catch(e) { res.status(500).json({error: 'Error check pack'}); }
});

// ==========================================
// RUTA 52: GESTIÓN DE OFERTAS Y PRECIOS (LOGICA INTELIGENTE v2) 🏷️
// ==========================================
app.put('/api/mi-negocio/producto/cambiar-categoria', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Sesión expirada. Inicia sesión nuevamente.' });
  const token = authHeader.split(' ')[1];

  // Recibimos: ID, la categoría nueva y el precio ofertado (opcional)
  const { inventario_id, nueva_categoria, precio_oferta } = req.body;

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    await client.query('BEGIN');

    // 1. OBTENER ESTADO ACTUAL DEL PRODUCTO
    const checkQuery = `
        SELECT I.nombre, I.precio, I.precio_regular, I.categoria_interna 
        FROM inventario_local I
        JOIN locales L ON I.local_id = L.local_id
        WHERE I.inventario_id = $1 AND L.usuario_id = $2
    `;
    const checkRes = await client.query(checkQuery, [inventario_id, usuario.id]);
    
    if (checkRes.rows.length === 0) {
        throw new Error("No encontramos el producto o no tienes permiso.");
    }
    
    const actual = checkRes.rows[0];
    
    // Variables para el update
    let precioFinal = Number(actual.precio);
    let precioRegularFinal = actual.precio_regular ? Number(actual.precio_regular) : null;
    let mensajeRespuesta = "Producto actualizado.";

    console.log(`🏷️ [OFERTAS] Modificando '${actual.nombre}' | De: ${actual.categoria_interna} -> A: ${nueva_categoria}`);

    // --- LÓGICA DE NEGOCIO ---

    // CASO A: ACTIVANDO UNA OFERTA (De GENERAL a OFERTA)
    // El usuario quiere poner un descuento.
    if (nueva_categoria !== 'GENERAL' && actual.categoria_interna === 'GENERAL') {
        
        if (!precio_oferta || Number(precio_oferta) >= Number(actual.precio)) {
            // Error amigable para el usuario
            throw new Error("⚠️ El precio de oferta debe ser menor al precio actual.");
        }

        // Guardamos el precio actual en el "backup" (precio_regular) para no perderlo
        precioRegularFinal = Number(actual.precio);
        
        // El precio activo pasa a ser el de oferta
        precioFinal = Number(precio_oferta);
        
        mensajeRespuesta = `¡Oferta Activada! 🔥 Ahora vale $${precioFinal}`;
        console.log(`   ↘️ [BAJA PRECIO] Antes: $${precioRegularFinal} -> Ahora: $${precioFinal}`);
    }

    // CASO B: QUITANDO UNA OFERTA (De OFERTA a GENERAL)
    // El usuario se arrepintió o se acabó la promo.
    else if (nueva_categoria === 'GENERAL' && actual.categoria_interna !== 'GENERAL') {
        
        // Restauramos el precio original si existe en el backup
        if (actual.precio_regular) {
            precioFinal = Number(actual.precio_regular);
        }
        // Limpiamos el backup (ya no es oferta)
        precioRegularFinal = null; 
        
        mensajeRespuesta = `Producto restaurado al precio original ($${precioFinal}).`;
        console.log(`   ↗️ [RESTAURAR] Precio volvió a normalidad.`);
    }

    // CASO C: MODIFICANDO DENTRO DE OFERTA (De FLASH a ESPECIAL o corregir precio)
    // El usuario cambia de tipo de oferta o ajusta el número.
    else if (nueva_categoria !== 'GENERAL') {
        if (precio_oferta) {
            // Validamos contra el precio regular (si existe) para no cometer errores
            if (precioRegularFinal && Number(precio_oferta) >= precioRegularFinal) {
                 throw new Error("⚠️ La oferta no puede ser mayor al precio original.");
            }
            precioFinal = Number(precio_oferta);
            mensajeRespuesta = `Precio de oferta actualizado a $${precioFinal}.`;
        }
    }

    // 2. EJECUTAR ACTUALIZACIÓN
    const updateQuery = `
        UPDATE inventario_local 
        SET 
            categoria_interna = $1,
            precio = $2,
            precio_regular = $3
        WHERE inventario_id = $4
    `;
    
    await client.query(updateQuery, [nueva_categoria, precioFinal, precioRegularFinal, inventario_id]);

    await client.query('COMMIT');
    
    // Respondemos con datos listos para mostrar en la UI
    res.json({ 
        mensaje: mensajeRespuesta, 
        precio_actual: precioFinal,
        precio_regular: precioRegularFinal,
        categoria: nueva_categoria
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Error en gestión de ofertas:", error.message);
    // Devolvemos el mensaje limpio (sin "Error: ...") para el SnackBar
    res.status(400).json({ error: error.message.replace('Error: ', '') }); 
  } finally {
    client.release();
  }
});

// ==========================================
// RUTA 51: GUARDAR CONFIGURACIÓN DE AGENDA 📅
// ==========================================
app.post('/api/mi-negocio/agenda', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  // Recibimos la configuración completa
  // dias_activos debe ser un array ej: [1, 2, 6, 7] (Lunes, Martes, Sabado, Domingo)
  const { dias_activos, hora_inicio, hora_fin, intervalo, descanso_inicio, descanso_fin } = req.body;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // 1. Obtener ID del local
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const localId = localRes.rows[0].local_id;

    // 2. UPSERT (Insertar o Actualizar si ya existe)
    // Usamos ON CONFLICT para manejar la unicidad
    const query = `
      INSERT INTO agenda_config (local_id, dias_activos, hora_inicio, hora_fin, duracion_turno_minutos, hora_descanso_inicio, hora_descanso_fin)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (local_id) 
      DO UPDATE SET 
        dias_activos = EXCLUDED.dias_activos,
        hora_inicio = EXCLUDED.hora_inicio,
        hora_fin = EXCLUDED.hora_fin,
        duracion_turno_minutos = EXCLUDED.duracion_turno_minutos,
        hora_descanso_inicio = EXCLUDED.hora_descanso_inicio,
        hora_descanso_fin = EXCLUDED.hora_descanso_fin
    `;

    await pool.query(query, [
        localId, 
        JSON.stringify(dias_activos), // Postgres pide JSON stringificado
        hora_inicio, 
        hora_fin, 
        intervalo, 
        descanso_inicio || null, 
        descanso_fin || null
    ]);

    res.json({ mensaje: 'Agenda actualizada correctamente' });

  } catch (error) {
    console.error("Error guardando agenda:", error);
    res.status(500).json({ error: 'Error al guardar agenda' });
  }
});

// ==========================================
// RUTA 52: CALCULAR TURNOS (CON BLOQUEOS MANUALES) ⏳🛡️
// ==========================================
app.get('/api/turnos/disponibles', async (req, res) => {
  const { local_id, fecha, duracion_minutos } = req.query; 

  if (!local_id || !fecha) return res.status(400).json({ error: 'Faltan datos' });

  try {
    // 1. Configuración del Local
    const configRes = await pool.query('SELECT * FROM agenda_config WHERE local_id = $1', [local_id]);
    if (configRes.rows.length === 0) return res.json([]); 
    const config = configRes.rows[0];
    
    // 2. Verificar día de la semana
    const fechaObj = new Date(fecha + 'T00:00:00'); 
    let diaSemana = fechaObj.getDay(); 
    if (diaSemana === 0) diaSemana = 7; 
    
    if (!config.dias_activos.includes(diaSemana)) return res.json([]);

    // 3. OBTENER OCUPACIÓN TOTAL (VENTAS + BLOQUEOS) 🔥
    // Usamos UNION ALL para juntar ambas tablas en una sola lista de "intervalos ocupados"
    const ocupacionRes = await pool.query(`
        SELECT fecha_reserva_inicio as inicio, fecha_reserva_fin as fin 
        FROM transacciones_p2p 
        WHERE vendedor_id = (SELECT usuario_id FROM locales WHERE local_id = $1)
        AND estado NOT IN ('CANCELADO', 'RECHAZADO')
        AND fecha_reserva_inicio::date = $2::date
        
        UNION ALL
        
        SELECT fecha_inicio as inicio, fecha_fin as fin
        FROM agenda_bloqueos
        WHERE local_id = $1
        AND fecha_inicio::date = $2::date
    `, [local_id, fecha]);

    const intervalosOcupados = ocupacionRes.rows.map(r => ({
        inicio: new Date(r.inicio).getTime(),
        fin: new Date(r.fin).getTime()
    }));

    // 4. GENERAR SLOTS (Igual que antes, pero comparando contra la lista unificada)
    const turnosDisponibles = [];
    const timeToMins = (t) => { const [h, m] = t.split(':').map(Number); return h * 60 + m; };

    let minutoActual = timeToMins(config.hora_inicio);
    const minutoFinDia = timeToMins(config.hora_fin);
    const duracionServicio = parseInt(duracion_minutos) || config.duracion_turno_minutos;

    // Descansos fijos (Configuración general)
    let descansoInicio = config.hora_descanso_inicio ? timeToMins(config.hora_descanso_inicio) : -1;
    let descansoFin = config.hora_descanso_fin ? timeToMins(config.hora_descanso_fin) : -1;

    while (minutoActual + duracionServicio <= minutoFinDia) {
        
        const slotInicio = new Date(fechaObj);
        slotInicio.setHours(Math.floor(minutoActual / 60), minutoActual % 60, 0, 0);
        const slotFin = new Date(slotInicio.getTime() + duracionServicio * 60000);

        // A. Chequeo Configuración General (Almuerzo fijo)
        let caeEnDescanso = false;
        if (descansoInicio !== -1) {
            if ((minutoActual >= descansoInicio && minutoActual < descansoFin) ||
                (minutoActual + duracionServicio > descansoInicio && minutoActual + duracionServicio <= descansoFin)) {
                caeEnDescanso = true;
            }
        }

        // B. Chequeo Ocupación Real (Ventas + Bloqueos Manuales)
        let estaOcupado = false;
        const slotStartMs = slotInicio.getTime();
        const slotEndMs = slotFin.getTime();

        // Filtro de tiempo pasado (Si es hoy, no mostrar horas viejas)
        const ahoraMs = Date.now();
        if (slotStartMs < ahoraMs) estaOcupado = true; // Ya pasó

        if (!estaOcupado) {
            for (const intervalo of intervalosOcupados) {
                // Si se solapan
                if (slotStartMs < intervalo.fin && slotEndMs > intervalo.inicio) {
                    estaOcupado = true;
                    break;
                }
            }
        }

        if (!caeEnDescanso && !estaOcupado) {
            const horaStr = `${slotInicio.getHours().toString().padStart(2, '0')}:${slotInicio.getMinutes().toString().padStart(2, '0')}`;
            turnosDisponibles.push(horaStr);
        }

        minutoActual += config.duracion_turno_minutos; 
    }

    res.json(turnosDisponibles);

  } catch (error) {
    console.error("Error calculando turnos:", error);
    res.status(500).json({ error: 'Error al calcular disponibilidad' });
  }
});

// ==========================================
// RUTA 53: OBTENER CONFIGURACIÓN DE AGENDA 📅
// ==========================================
app.get('/api/mi-negocio/agenda', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // Obtenemos local
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const localId = localRes.rows[0].local_id;

    // Buscamos la config
    const configRes = await pool.query('SELECT * FROM agenda_config WHERE local_id = $1', [localId]);

    if (configRes.rows.length > 0) {
      res.json(configRes.rows[0]); // Devolvemos la config guardada
    } else {
      res.json(null); // No configuró nada aún (el frontend usará defaults)
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener agenda' });
  }
});

// ==========================================
// RUTA: CANCELAR TURNO (CLIENTE) - CON REGLA 24HS ⏳
// ==========================================
app.post('/api/transaccion/cancelar-turno', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { transaccion_id } = req.body;
  const HORAS_LIMITE = 24; // Configuración de la regla de oro

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    await client.query('BEGIN');

    // 1. Obtener datos del turno
    // Necesitamos fecha de reserva, monto, pago_id y vendedor
    const query = `
      SELECT 
        t.*, 
        l.usuario_id as vendedor_id,
        l.nombre as nombre_local
      FROM transacciones_p2p t
      JOIN locales l ON t.vendedor_id = l.usuario_id
      WHERE t.transaccion_id = $1 AND t.comprador_id = $2
      FOR UPDATE
    `;
    const resTurno = await client.query(query, [transaccion_id, usuario.id]);

    if (resTurno.rows.length === 0) throw new Error('Turno no encontrado');
    const turno = resTurno.rows[0];

    // 2. VALIDAR ESTADO
    if (turno.estado === 'CANCELADO' || turno.estado === 'RECHAZADO') {
       throw new Error('Este turno ya estaba cancelado.');
    }
    if (turno.estado === 'ENTREGADO') {
       throw new Error('No puedes cancelar un servicio ya realizado.');
    }
    if (!turno.fecha_reserva_inicio) {
       throw new Error('Esta compra no es un turno agendado.');
    }

    // 3. 🛑 REGLA DE ORO: VERIFICAR TIEMPO (24 HS)
    const fechaTurno = new Date(turno.fecha_reserva_inicio);
    const ahora = new Date();
    
    // Calculamos diferencia en horas
    const diferenciaHoras = (fechaTurno - ahora) / 1000 / 60 / 60;

    if (diferenciaHoras < HORAS_LIMITE) {
       // SI FALTA POCO, BLOQUEAMOS LA AUTO-CANCELACIÓN
       // El frontend debe manejar este error sugiriendo WhatsApp
       throw new Error(`Faltan menos de ${HORAS_LIMITE}hs. Debes contactar al local directamente para cancelar.`);
    }

    // 4. SI PASA EL TIEMPO -> EJECUTAR REEMBOLSO
    console.log(`🔄 Cliente cancelando turno ${turno.compra_uuid} (A tiempo: ${diferenciaHoras.toFixed(1)}hs antes)`);

    if (turno.mp_payment_id) {
        try {
            const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN_PROD });
            const paymentClient = new Payment(mpClient);
            
            // Reembolso Parcial (Solo el monto de este turno)
            await paymentClient.refund(turno.mp_payment_id, { amount: parseFloat(turno.monto_total) });
            console.log("✅ Reembolso MP exitoso.");
        } catch (mpError) {
            console.error("⚠️ Error MP Refund:", mpError);
            // Si falla MP (ej: ya devuelto), seguimos para cancelar en DB, o lanzamos error.
            // En este caso, asumimos que si falla es mejor avisar para no dejar inconsistencia.
            throw new Error("Error procesando el reembolso. Contacta a soporte.");
        }
    }

    // 5. ACTUALIZAR DB
    await client.query(`
        UPDATE transacciones_p2p 
        SET estado = 'CANCELADO', motivo_rechazo = 'Cancelado por el usuario (A tiempo)'
        WHERE transaccion_id = $1
    `, [transaccion_id]);

    // 6. ANULAR COMISIÓN SOCIO (Si existía)
    await client.query(`
        UPDATE historial_comisiones 
        SET estado = 'ANULADA', monto_comision = 0 
        WHERE transaccion_origen_id = $1
    `, [transaccion_id]);

    await client.query('COMMIT');

    // 7. NOTIFICAR AL VENDEDOR
    // Formato fecha amigable
    const fechaStr = new Date(turno.fecha_reserva_inicio).toLocaleString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires' });
    
    enviarNotificacion(
       turno.vendedor_id, 
       "Turno Cancelado 📅", 
       `${usuario.nombre || 'Un cliente'} canceló su turno del ${fechaStr}. El cupo ha sido liberado.`,
       { tipo: 'VENTA' }
    );

    res.json({ mensaje: 'Turno cancelado y dinero reembolsado.' });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("Error cancelar turno:", error.message);
    
    // Devolvemos 400 para que el frontend sepa que fue un error de lógica (ej: tiempo)
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});

// ==========================================
// CRON JOB: AGENDA DIARIA (05:00 AM ARG / 08:00 UTC) ⏰
// ==========================================
cron.schedule('0 8 * * *', async () => {
  console.log('⏰ Generando resumen de agenda del día...');
  
  try {
    const query = `
      SELECT 
        t.fecha_reserva_inicio,
        -- 🔥 CAMBIO A FORMATO 24HS (Ej: 17:30)
        TO_CHAR(
            t.fecha_reserva_inicio AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires', 
            'HH24:MI'
        ) as hora_argentina,
        
        COALESCE(t.nombre_snapshot, 'Servicio Reservado') as servicio,
        l.nombre as local_nombre,
        u_comprador.usuario_id as comprador_id,
        u_vendedor.usuario_id as vendedor_id
      FROM transacciones_p2p t
      JOIN locales l ON t.vendedor_id = l.usuario_id
      JOIN usuarios u_comprador ON t.comprador_id = u_comprador.usuario_id
      JOIN usuarios u_vendedor ON l.usuario_id = u_vendedor.usuario_id
      WHERE 
        (t.fecha_reserva_inicio AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires')::date = 
        (NOW() AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires')::date
        AND t.estado NOT IN ('CANCELADO', 'RECHAZADO', 'ENTREGADO')
      ORDER BY t.fecha_reserva_inicio ASC
    `;
    
    const res = await pool.query(query);
    
    if (res.rows.length === 0) return;

    const agendaCompradores = {};
    const agendaVendedores = {};

    res.rows.forEach(turno => {
        const hora = turno.hora_argentina;
        
        // Agregamos "hs" para que quede "17:30hs"
        if (!agendaCompradores[turno.comprador_id]) agendaCompradores[turno.comprador_id] = [];
        agendaCompradores[turno.comprador_id].push(`▪ ${hora}hs - ${turno.servicio} en ${turno.local_nombre}`);

        if (!agendaVendedores[turno.vendedor_id]) agendaVendedores[turno.vendedor_id] = [];
        agendaVendedores[turno.vendedor_id].push(`▪ ${hora}hs - ${turno.servicio}`);
    });

    const promesasEnvio = [];

    // Compradores
    for (const [id, lista] of Object.entries(agendaCompradores)) {
        let titulo = "¡Tienes turno hoy! 📅";
        let cuerpo = lista.length === 1 
            ? lista[0].replace('▪ ', 'Recuerda tu cita: ')
            : `Tu itinerario:\n\n` + lista.join("\n");
        promesasEnvio.push(enviarNotificacion(id, titulo, cuerpo, { tipo: 'COMPRA' }));
    }

    // Vendedores
    for (const [id, lista] of Object.entries(agendaVendedores)) {
        let titulo = "Agenda del Día 📅";
        let cuerpo = lista.length === 1
            ? `Tienes 1 cliente agendado:\n${lista[0]}`
            : `Tu agenda:\n\n` + lista.join("\n");
        promesasEnvio.push(enviarNotificacion(id, titulo, cuerpo, { tipo: 'VENTA' }));
    }

    await Promise.all(promesasEnvio);
    console.log(`✅ Enviados ${promesasEnvio.length} recordatorios diarios.`);

  } catch (error) {
    console.error("❌ Error Cron Diario:", error);
  }
});

// ==========================================
// CRON JOB: RECORDATORIO "1 HORA ANTES" (CADA 15 MIN) ⏳
// ==========================================
cron.schedule('*/15 * * * *', async () => {
  try {
    const query = `
      SELECT 
        t.fecha_reserva_inicio,
        -- 🔥 CAMBIO A FORMATO 24HS
        TO_CHAR(
            t.fecha_reserva_inicio AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires', 
            'HH24:MI'
        ) as hora_argentina,
        
        COALESCE(t.nombre_snapshot, 'Servicio') as servicio,
        l.nombre as local_nombre,
        u.usuario_id as comprador_id
      FROM transacciones_p2p t
      JOIN locales l ON t.vendedor_id = l.usuario_id
      JOIN usuarios u ON t.comprador_id = u.usuario_id
      WHERE 
        t.estado NOT IN ('CANCELADO', 'RECHAZADO', 'ENTREGADO')
        AND t.fecha_reserva_inicio >= (NOW() + INTERVAL '55 minutes') 
        AND t.fecha_reserva_inicio < (NOW() + INTERVAL '70 minutes')
    `;

    const res = await pool.query(query);

    if (res.rows.length > 0) {
      console.log(`🔔 Enviando recordatorios inminentes a ${res.rows.length} usuarios.`);
      
      const promesas = res.rows.map(turno => {
          return enviarNotificacion(
              turno.comprador_id, 
              "⏰ ¡Tu turno es en 1 hora!", 
              `No olvides tu cita: ${turno.servicio} en ${turno.local_nombre} a las ${turno.hora_argentina}hs.`, // Agregamos 'hs'
              { tipo: 'COMPRA' }
          );
      });

      await Promise.all(promesas);
    }
  } catch (error) {
    console.error("❌ Error Cron 1h:", error);
  }
});

// ==========================================
// MÓDULO AGENDA VISUAL (V13.5) 📅
// ==========================================

// RUTA A: OBTENER AGENDA DEL DÍA (VENTAS + BLOQUEOS)
app.get('/api/agenda/dia', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { fecha } = req.query; // Formato 'YYYY-MM-DD'
  if (!fecha) return res.status(400).json({ error: 'Fecha requerida' });

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // 1. Obtener ID del local
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Local no encontrado' });
    const localId = localRes.rows[0].local_id;

    // 2. Traer VENTAS (Turnos reales)
    const ventasQuery = `
        SELECT 
            transaccion_id as id,
            fecha_reserva_inicio as inicio,
            fecha_reserva_fin as fin,
            nombre_snapshot as titulo,
            'VENTA' as tipo, -- Para diferenciar en el frontend (Color Verde/Violeta)
            comprador_id,
            (SELECT nombre_completo FROM usuarios WHERE usuario_id = transacciones_p2p.comprador_id) as cliente
        FROM transacciones_p2p 
        WHERE vendedor_id = $1
        AND estado NOT IN ('CANCELADO', 'RECHAZADO')
        AND fecha_reserva_inicio::date = $2::date
    `;
    const ventasRes = await pool.query(ventasQuery, [usuario.id, fecha]);

    // 3. Traer BLOQUEOS MANUALES
    const bloqueosQuery = `
        SELECT 
            bloqueo_id as id,
            fecha_inicio as inicio,
            fecha_fin as fin,
            motivo as titulo,
            'BLOQUEO' as tipo, -- Para diferenciar (Color Gris)
            NULL as comprador_id,
            'N/A' as cliente
        FROM agenda_bloqueos 
        WHERE local_id = $1
        AND fecha_inicio::date = $2::date
    `;
    const bloqueosRes = await pool.query(bloqueosQuery, [localId, fecha]);

    // 4. Unificar y Ordenar
    const agenda = [...ventasRes.rows, ...bloqueosRes.rows];
    
    // Ordenamos por hora de inicio
    agenda.sort((a, b) => new Date(a.inicio) - new Date(b.inicio));

    res.json(agenda);

  } catch (error) {
    console.error("Error obteniendo agenda:", error);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// RUTA B: CREAR BLOQUEO MANUAL
app.post('/api/agenda/bloquear', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { fecha_inicio, fecha_fin, motivo } = req.body;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    const localId = localRes.rows[0].local_id;

    await pool.query(
        'INSERT INTO agenda_bloqueos (local_id, fecha_inicio, fecha_fin, motivo) VALUES ($1, $2, $3, $4)',
        [localId, fecha_inicio, fecha_fin, motivo || 'Ocupado']
    );

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Error al bloquear turno' });
  }
});

// RUTA C: ELIMINAR BLOQUEO
app.delete('/api/agenda/bloquear/:id', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  const { id } = req.params;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    const localId = localRes.rows[0].local_id;

    await pool.query('DELETE FROM agenda_bloqueos WHERE bloqueo_id = $1 AND local_id = $2', [id, localId]);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar bloqueo' });
  }
});

// ==========================================
// RUTA 54: ANALIZAR EXCEL (PREVISUALIZACIÓN) 📊
// ==========================================
app.post('/api/mi-negocio/importar-excel/analizar', uploadMemoria.single('archivo'), async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  try {
    if (!req.file) return res.status(400).json({ error: 'No se subió ningún archivo' });

    // 1. LEER EL ARCHIVO DESDE LA MEMORIA RAM
    const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0]; // Leemos la primera hoja
    const sheet = workbook.Sheets[sheetName];
    
    // Convertimos a JSON crudo (Array de objetos)
    const rawData = xlsx.utils.sheet_to_json(sheet);

    if (rawData.length === 0) return res.status(400).json({ error: 'El archivo está vacío' });

    // 2. MAPEO INTELIGENTE (NORMALIZADOR) 🧠
    // Convertimos las columnas del usuario a nuestras columnas
    const productosProcesados = [];
    let errores = 0;

    for (let row of rawData) {
        // Normalizamos claves a minúsculas para buscar patrones
        let item = { nombre: '', precio: 0, stock: 0, codigo: '' };
        let esValido = true;

        Object.keys(row).forEach(key => {
            const k = key.toLowerCase().trim();
            const val = row[key];

            // Detección de Nombre
            if (k.includes('nombre') || k.includes('producto') || k.includes('item') || k.includes('titulo')) {
                item.nombre = String(val).trim();
            }
            // Detección de Precio
            else if (k.includes('precio') || k.includes('valor') || k.includes('costo') || k.includes('$')) {
                item.precio = parseFloat(String(val).replace(/[^0-9.]/g, '')) || 0;
            }
            // Detección de Stock
            else if (k.includes('stock') || k.includes('cant') || k.includes('unid')) {
                item.stock = parseInt(val) || 0;
            }
            // Detección de Código
            else if (k.includes('cod') || k.includes('ean') || k.includes('sku') || k.includes('barra')) {
                item.codigo = String(val).trim();
            }
        });

        // Validaciones mínimas
        if (!item.nombre || item.precio <= 0) {
            esValido = false;
            errores++;
        }

        if (esValido) {
            productosProcesados.push(item);
        }
    }

    // 3. RESPONDER CON EL RESUMEN
    res.json({
        total_encontrados: rawData.length,
        validos: productosProcesados.length,
        errores: errores,
        muestra: productosProcesados.slice(0, 5), // Mandamos los primeros 5 para que el usuario confirme
        datos_completos: productosProcesados // Mandamos todo para que el frontend lo tenga listo para confirmar
    });

  } catch (error) {
    console.error("Error leyendo Excel:", error);
    res.status(500).json({ error: 'El archivo no es válido o está dañado.' });
  }
});

// ==========================================
// RUTA 55: CONFIRMAR IMPORTACIÓN (BULK INSERT) 🚀
// ==========================================
app.post('/api/mi-negocio/importar-excel/confirmar', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  
  const { productos } = req.body; // Recibe el array 'datos_completos' del paso anterior

  if (!productos || !Array.isArray(productos) || productos.length === 0) {
      return res.status(400).json({ error: 'No hay datos para importar' });
  }

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // Obtener Local
    const localRes = await client.query('SELECT local_id, categoria, rubro FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) throw new Error('Local no encontrado');
    const { local_id, categoria, rubro } = localRes.rows[0];

    await client.query('BEGIN');

    // INSERT MASIVO (Optinizado)
    // Hacemos un loop simple dentro de la transacción. 
    // Para miles de productos es mejor pg-format, pero para <500 esto es seguro y rápido.
    
    for (const p of productos) {
        // 1. Insertar en Catálogo Global (Privado por defecto para no ensuciar)
        // Usamos una foto genérica si no tienen
        const fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/2652/2652218.png'; // Icono de caja
        
        const resGlobal = await client.query(`
            INSERT INTO catalogo_global (nombre_oficial, descripcion, foto_url, categoria, codigo_barras, creado_por_usuario_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING global_id
        `, [p.nombre, 'Importado desde Excel', fotoDefecto, categoria, p.codigo || null, usuario.id]);
        
        const globalId = resGlobal.rows[0].global_id;

        // 2. Insertar en Inventario Local
        await client.query(`
            INSERT INTO inventario_local (local_id, global_id, precio, stock, tipo_item, codigo_barras, foto_url)
            VALUES ($1, $2, $3, $4, 'PRODUCTO_STOCK', $5, $6)
        `, [local_id, globalId, p.precio, p.stock, p.codigo || null, fotoDefecto]);
    }

    await client.query('COMMIT');
    res.json({ mensaje: `¡Se importaron ${productos.length} productos correctamente!` });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("Error importando:", error);
    res.status(500).json({ error: 'Error al guardar los datos en la base de datos.' });
  } finally {
    client.release();
  }
});

// ==========================================
// RUTA 56: DESCARGAR PLANTILLA EXCEL (PLAN B) 📉
// ==========================================
app.get('/api/mi-negocio/importar-excel/plantilla', (req, res) => {
  try {
    // 1. Datos de Ejemplo
    const datosEjemplo = [
      { Nombre: "Coca Cola 1.5L", Precio: 1500, Stock: 50, Codigo: "779123456" },
      { Nombre: "Alfajor Chocolate", Precio: 800, Stock: 100, Codigo: "779987654" },
      { Nombre: "Galletitas", Precio: 1200, Stock: 20, Codigo: "" }
    ];

    // 2. Crear Libro de Excel
    const ws = xlsx.utils.json_to_sheet(datosEjemplo);
    const wb = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(wb, ws, "Plantilla CercaMio");

    // 3. Generar Buffer
    const buffer = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });

    // 4. Enviar como Descarga
    res.setHeader('Content-Disposition', 'attachment; filename="Plantilla_CercaMio.xlsx"');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);

  } catch (error) {
    console.error("Error generando plantilla:", error);
    res.status(500).send("Error al generar plantilla");
  }
});

// ==========================================
// MÓDULO CUPONES: GESTIÓN VENDEDOR (V15.0) 🎟️
// ==========================================

// RUTA 70: CREAR CUPÓN NUEVO
app.post('/api/mi-negocio/cupones', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { codigo, descripcion, tipo_descuento, valor_descuento, stock_inicial, fecha_vencimiento } = req.body;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // 1. Obtener local
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'No tienes local' });
    const localId = localRes.rows[0].local_id;

    // 2. Validaciones de Negocio
    if (!codigo || !valor_descuento) return res.status(400).json({ error: 'Faltan datos obligatorios' });
    
    // Normalizar código (Mayúsculas sin espacios)
    const codigoClean = codigo.trim().toUpperCase().replace(/\s/g, '');

    // Seguridad financiera
    if (tipo_descuento === 'PORCENTAJE' && valor_descuento > 100) {
        return res.status(400).json({ error: 'El descuento no puede ser mayor al 100%' });
    }

    // 3. Insertar
    const query = `
      INSERT INTO cupones 
      (local_id, codigo, descripcion, tipo_descuento, valor_descuento, stock_inicial, fecha_vencimiento)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `;
    
    await pool.query(query, [
        localId, 
        codigoClean, 
        descripcion, 
        tipo_descuento || 'PORCENTAJE', 
        valor_descuento, 
        stock_inicial || 999999,
        fecha_vencimiento || null
    ]);

    res.json({ mensaje: 'Cupón creado exitosamente' });

  } catch (error) {
    if (error.code === '23505') { // Error de unicidad SQL
        return res.status(400).json({ error: 'Ya existe un cupón con este código en tu local.' });
    }
    console.error("Error creando cupón:", error);
    res.status(500).json({ error: 'Error al crear cupón' });
  }
});

// RUTA 71: LISTAR MIS CUPONES
app.get('/api/mi-negocio/cupones', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // Traemos cupones con formato de fecha bonito
    const query = `
      SELECT 
        c.*,
        TO_CHAR(c.fecha_vencimiento, 'DD/MM/YYYY') as vencimiento_fmt
      FROM cupones c
      JOIN locales l ON c.local_id = l.local_id
      WHERE l.usuario_id = $1
      ORDER BY c.activo DESC, c.fecha_creacion DESC
    `;
    
    const result = await pool.query(query, [usuario.id]);
    res.json(result.rows);

  } catch (error) {
    res.status(500).json({ error: 'Error al cargar cupones' });
  }
});

// RUTA 72: PAUSAR/ACTIVAR CUPÓN
app.put('/api/mi-negocio/cupones/:id/toggle', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  const { id } = req.params;

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    // Verificamos propiedad y actualizamos en un solo paso
    const query = `
      UPDATE cupones 
      SET activo = NOT activo
      FROM locales l
      WHERE cupones.local_id = l.local_id
      AND cupones.cupon_id = $1
      AND l.usuario_id = $2
      RETURNING cupones.activo
    `;
    
    const result = await pool.query(query, [id, usuario.id]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'Cupón no encontrado' });

    res.json({ mensaje: 'Estado actualizado', activo: result.rows[0].activo });

  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar' });
  }
});

// ==========================================
// RUTA 73: ELIMINAR CUPÓN (DELETE) 🗑️
// ==========================================
app.delete('/api/mi-negocio/cupones/:id', verificarToken, async (req, res) => {
  const usuarioId = req.usuario.id;
  const cuponId = req.params.id;

  try {
    // Solo borramos si pertenece al usuario (seguridad mediante JOIN implícito o subquery)
    const query = `
        DELETE FROM cupones 
        WHERE cupon_id = $1 
        AND local_id = (SELECT local_id FROM locales WHERE usuario_id = $2)
    `;
    
    const result = await pool.query(query, [cuponId, usuarioId]);

    if (result.rowCount === 0) {
        // Puede ser que no exista o que tenga FK constraints (ya se usó)
        // Si ya se usó, no se puede borrar por integridad SQL.
        // En ese caso, mejor usamos la lógica de "Desactivar" (Ruta 72), 
        // pero para el panel web intentaremos borrar primero.
        return res.status(404).json({ error: 'No se pudo eliminar (quizás ya tiene uso o no es tuyo)' });
    }

    res.json({ mensaje: 'Cupón eliminado permanentemente' });

  } catch (error) {
    // Error 23503 = Violación de Foreign Key (El cupón ya se usó en una venta)
    if (error.code === '23503') {
       return res.status(400).json({ error: 'No se puede borrar un cupón que ya fue utilizado por clientes. Puedes pausarlo.' });
    }
    console.error("Error Delete Cupón:", error);
    res.status(500).json({ error: 'Error al eliminar' });
  }
});

// ==========================================
// RUTA 73: VALIDAR CUPÓN EN CARRITO 🛒
// ==========================================
app.post('/api/transaccion/validar-cupon', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  const { local_id, codigo } = req.body;

  try {
    const codigoNorm = codigo.trim().toUpperCase();

    // 1. Buscar el cupón Maestro
    const query = `
      SELECT * FROM cupones 
      WHERE local_id = $1 
      AND codigo = $2
      AND activo = TRUE
    `;
    const result = await pool.query(query, [local_id, codigoNorm]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Cupón no válido para este local' });
    }

    const cupon = result.rows[0];

    // 2. Validaciones de Reglas
    // A. Fecha
    if (cupon.fecha_vencimiento && new Date() > new Date(cupon.fecha_vencimiento)) {
        return res.status(400).json({ error: 'Este cupón ya venció' });
    }
    
    // B. Stock Global
    if (cupon.stock_usado >= cupon.stock_inicial) {
        return res.status(400).json({ error: 'Este cupón se agotó' });
    }

    // 3. Respuesta Exitosa (Frontend calcula el total)
    res.json({
        valido: true,
        cupon_id: cupon.cupon_id,
        codigo: cupon.codigo,
        tipo: cupon.tipo_descuento, // 'PORCENTAJE' o 'FIJO'
        valor: parseFloat(cupon.valor_descuento),
        mensaje: '¡Cupón aplicado!'
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al validar cupón' });
  }
});

// ==========================================
// 🎟️ RUTAS DE BILLETERA (CUPONES)
// ==========================================
app.get('/api/usuario/mis-cupones', verificarToken, async (req, res) => {
  try {
    const usuarioId = req.usuario.id;

    const query = `
      SELECT 
        cw.wallet_id,
        cw.estado,
        c.cupon_id,
        c.codigo,
        c.descripcion,
        c.tipo_descuento, -- 'PORCENTAJE' o 'FIJO'
        c.valor_descuento,
        c.fecha_vencimiento,
        l.local_id,
        l.nombre as nombre_local,
        l.foto_perfil,
        l.rubro
      FROM cupones_wallet cw
      JOIN cupones c ON cw.cupon_id = c.cupon_id
      JOIN locales l ON c.local_id = l.local_id
      WHERE cw.usuario_id = $1 
        AND cw.estado = 'ACTIVO'
        AND c.fecha_vencimiento > NOW()
      ORDER BY c.fecha_vencimiento ASC
    `;

    const result = await pool.query(query, [usuarioId]);
    
    // Formateo para frontend
    const cupones = result.rows.map(row => ({
      wallet_id: row.wallet_id,
      cupon_id: row.cupon_id,
      codigo: row.codigo,
      descripcion: row.descripcion,
      tipo: row.tipo_descuento,
      valor: row.valor_descuento,
      vencimiento: row.fecha_vencimiento,
      local: {
        id: row.local_id,
        nombre: row.nombre_local,
        foto: row.foto_perfil,
        rubro: row.rubro
      }
    }));

    res.json(cupones);

  } catch (err) {
    console.error('Error al obtener mis cupones:', err);
    res.status(500).json({ error: 'Error interno al cargar la billetera' });
  }
});

// ENCENDEMOS EL SERVIDOR
app.listen(port, () => {
  console.log(`🚀 SERVIDOR ACTUALIZADO - VERSIÓN CON SOCIOS ACTIVA - Puerto ${port}`);
});

