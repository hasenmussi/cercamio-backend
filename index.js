// 1. IMPORTAMOS LAS LIBRERÍAS
require('dotenv').config(); // <--- ESTO SIEMPRE PRIMERO
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const cron = require('node-cron');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const axios = require('axios');

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

// 3. MERCADO PAGO (Solo importamos clases, instanciamos en las rutas)
const { MercadoPagoConfig, Preference, Payment } = require('mercadopago');

// 4. CONFIGURACIÓN DE EMAIL (NODEMAILER)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587, 
  secure: false, 
  auth: {
    user: process.env.EMAIL_USER, 
    pass: process.env.EMAIL_PASS 
  },
  tls: {
    rejectUnauthorized: false 
  }
});

// Función auxiliar de Email
const enviarEmail = async (destinatario, asunto, texto) => {
  console.log(`📨 Enviando email a: ${destinatario}`);
  try {
    await transporter.sendMail({
      from: '"Soporte CercaMío" <soporte@cercamio.app>',
      to: destinatario,
      subject: asunto,
      text: texto,
    });
    console.log('✅ Email enviado.');
  } catch (error) {
    console.error("⚠️ Falló envío de email:", error.message);
  }
};

// 5. FUNCIONES AUXILIARES SIMPLES
const generarCodigo = () => Math.floor(100000 + Math.random() * 900000).toString();
const capitalizarNombre = (texto) => {
  if (!texto) return "";
  return texto.toLowerCase().split(' ').map(p => p.charAt(0).toUpperCase() + p.slice(1)).join(' ');
};

// ==========================================
// FUNCIÓN AUXILIAR: ENVIAR NOTIFICACIONES PUSH (FCM) 📲
// ==========================================
const enviarNotificacion = async (usuarioIdDestino, titulo, mensaje, dataPayload = {}) => {
  try {
    // 1. Buscamos el token del usuario en la BD
    const query = 'SELECT fcm_token FROM usuarios WHERE usuario_id = $1';
    const res = await pool.query(query, [usuarioIdDestino]);

    // Si no existe el usuario o no tiene token, salimos
    if (res.rows.length === 0 || !res.rows[0].fcm_token) {
      return; 
    }

    const fcmToken = res.rows[0].fcm_token;

    // 2. Preparamos el mensaje para Firebase
    const message = {
      notification: { title: titulo, body: mensaje },
      token: fcmToken,
      data: dataPayload // Datos extra (ej: ID de pedido)
    };

    // 3. Enviamos
    await admin.messaging().send(message);
    // console.log(`📲 Notificación enviada a usuario ${usuarioIdDestino}`);

  } catch (error) {
    // console.error('Error enviando notificación:', error.message);

    // --- AUTO-LIMPIEZA DE TOKENS MUERTOS ---
    // Si Firebase nos dice que el token ya no sirve (App desinstalada), lo borramos de la BD
    if (error.code === 'messaging/registration-token-not-registered' || 
        error.code === 'messaging/invalid-argument') {
       
       await pool.query('UPDATE usuarios SET fcm_token = NULL WHERE usuario_id = $1', [usuarioIdDestino]);
       console.log(`🗑️ Token inválido eliminado para usuario ${usuarioIdDestino}`);
    }
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

// 8. MIDDLEWARES
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] }));
app.use(express.json());

// 9. BASE DE DATOS (NEON)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Lee del .env
  ssl: { require: true, rejectUnauthorized: false },
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
// RUTA 1: OBTENER LOCALES (GPS REAL + BÚSQUEDA VISUAL) 📍
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
        
        -- 📏 CÁLCULO DE DISTANCIA REAL 📏
        -- Usamos los parámetros $4 y $5 (Ubicación del Usuario)
        ST_Distance(
          L.ubicacion::geometry, 
          ST_SetSRID(ST_MakePoint($4, $5), 4326)::geometry
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
        -- Usamos los parámetros $1 y $2 (Centro del Mapa)
        ST_DWithin(
          L.ubicacion::geometry,
          ST_SetSRID(ST_MakePoint($1, $2), 4326)::geometry,
          $3
        )
    `;
    
    // Parámetros SQL:
    // $1, $2, $3 -> Filtran (Centro del Mapa + Radio)
    // $4, $5     -> Miden (GPS del Usuario)
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
// RUTA 2: BUSCADOR AVANZADO (TRIGRAMAS + GEO + FILTROS) 🔍
// ==========================================
app.get('/api/buscar', async (req, res) => {
  const { q, lat, lng } = req.query; 
  
  if (!q) return res.status(400).json({ error: 'Falta el término de búsqueda' });
  
  // Validación de GPS
  if (!lat || !lng) {
      return res.status(400).json({ error: "Se requiere ubicación para buscar" });
  }

  try {
    // Preparamos el término para búsqueda parcial (%texto%)
    const terminoBusqueda = `%${q}%`;

    const consulta = `
      SELECT 
        L.local_id,
        I.inventario_id,
        
        -- DATOS INTELIGENTES (COALESCE)
        COALESCE(I.nombre, C.nombre_oficial) as nombre_oficial, 
        COALESCE(I.descripcion, C.descripcion) as descripcion,
        COALESCE(I.foto_url, C.foto_url) as foto_producto,
        
        I.precio, 
        L.nombre as tienda,
        L.categoria,
        L.rubro,
        L.tipo_actividad,
        L.reputacion,
        L.whatsapp,
        
        -- FOTO DEL LOCAL (Con lógica de perfil nueva)
        COALESCE(L.foto_perfil, L.foto_url) as foto_local,

        ST_X(L.ubicacion::geometry) as long, 
        ST_Y(L.ubicacion::geometry) as lat,
        
        -- Distancia Real
        ST_Distance(
          L.ubicacion::geometry, 
          ST_SetSRID(ST_MakePoint($2, $3), 4326)::geometry
        ) as distancia_metros

      FROM inventario_local I
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id
      JOIN locales L ON I.local_id = L.local_id
      
      WHERE 
        -- 1. FILTRO GEOESPACIAL (Radio 10km)
        ST_DWithin(
          L.ubicacion::geometry,
          ST_SetSRID(ST_MakePoint($2, $3), 4326)::geometry,
          10000 
        )
        AND
        -- 2. FILTRO DE SEGURIDAD (Solo productos vendibles)
        I.stock > 0 AND I.precio > 0
        AND
        -- 3. BÚSQUEDA INTELIGENTE (Usa los índices GIN creados)
        (
          -- Busca en nombre del producto (sin acentos)
          public.immutable_unaccent(COALESCE(I.nombre, C.nombre_oficial)) ILIKE public.immutable_unaccent($1)
          OR 
          -- Busca en descripción del producto
          public.immutable_unaccent(COALESCE(I.descripcion, C.descripcion)) ILIKE public.immutable_unaccent($1)
          OR
          -- Busca en nombre de la tienda
          public.immutable_unaccent(L.nombre) ILIKE public.immutable_unaccent($1)
          OR 
          -- Busca en el rubro (ej: "Ferretería")
          public.immutable_unaccent(L.rubro) ILIKE public.immutable_unaccent($1)
        )

      -- ORDENAMIENTO: Primero lo más cerca
      ORDER BY distancia_metros ASC
      LIMIT 50 -- Límite para no saturar la red
    `;
    
    // Parámetros: [Query con %, Longitud, Latitud]
    const respuesta = await pool.query(consulta, [terminoBusqueda, parseFloat(lng), parseFloat(lat)]);
    
    res.json(respuesta.rows);

  } catch (error) {
    console.error("Error en GET /api/buscar:", error);
    res.status(500).json({ error: 'Error al buscar productos' });
  }
});

// ==========================================
// RUTA 6: VER MIS PRODUCTOS (CON ORDENAMIENTO DE OFERTAS) 🏆
// ==========================================
app.get('/api/mi-negocio/productos', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // 1. Obtener datos del Local
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
        I.precio_regular

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
      items: productosRes.rows
    });

  } catch (error) {
    console.error("Error GET productos:", error);
    res.status(500).json({ error: 'Error al obtener inventario' });
  }
});

// ==========================================
// RUTA 7: ACTUALIZAR NEGOCIO (HÍBRIDO + OFERTAS) 🧠
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
    categoria_interna // <--- NUEVO CAMPO: 'GENERAL', 'OFERTA_FLASH', etc.
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
    // CASO B: ACTUALIZAR PRODUCTO (CON LÓGICA DE PRECIOS)
    // ---------------------------------------------------------
    if (inventario_id) {
      
      // 1. OBTENER ESTADO ACTUAL (Para la lógica de Ofertas)
      const currentRes = await pool.query('SELECT precio, precio_regular, categoria_interna FROM inventario_local WHERE inventario_id = $1', [inventario_id]);
      
      if (currentRes.rows.length === 0) return res.status(404).json({ error: 'Producto no encontrado' });
      const actual = currentRes.rows[0];

      // --- LÓGICA DE PRECIOS INTELIGENTE ---
      let precioFinal = nuevo_precio;
      let precioRegularFinal = actual.precio_regular; // Por defecto mantenemos el backup si existe
      let catFinal = categoria_interna || actual.categoria_interna; // Si no mandan categoría, queda la que estaba

      // A. Si estamos ACTIVANDO una oferta (y antes era GENERAL)
      if (catFinal !== 'GENERAL' && actual.categoria_interna === 'GENERAL') {
          // Guardamos el precio viejo como backup antes de aplicar el nuevo precio de oferta
          // (Asumimos que 'nuevo_precio' ya viene con el descuento aplicado desde el frontend)
          precioRegularFinal = actual.precio;
      }
      
      // B. Si estamos QUITANDO una oferta (volvemos a GENERAL)
      else if (catFinal === 'GENERAL' && actual.categoria_interna !== 'GENERAL') {
          // Si había un precio backup, lo restauramos automáticamente
          if (actual.precio_regular) {
              precioFinal = actual.precio_regular;
          }
          precioRegularFinal = null; // Borramos el backup porque ya no es oferta
      }

      // 2. ACTUALIZAMOS INVENTARIO LOCAL
      const updateInventario = `
        UPDATE inventario_local 
        SET 
          precio = $1, 
          stock = $2,
          codigo_barras = COALESCE($3, codigo_barras),
          categoria_interna = $4,
          precio_regular = $5
        WHERE inventario_id = $6
      `;
      
      await pool.query(updateInventario, [
        precioFinal,        // $1
        nuevo_stock,        // $2
        codigo_barras,      // $3
        catFinal,           // $4 (Nueva Categoría)
        precioRegularFinal, // $5 (Precio Tachado)
        inventario_id       // $6
      ]);

      // 3. ACTUALIZAMOS CATALOGO GLOBAL (Nombre, Descripción, Foto - Sin cambios)
      const getGlobal = await pool.query('SELECT global_id FROM inventario_local WHERE inventario_id = $1', [inventario_id]);
      
      if (getGlobal.rows.length > 0) {
        const globalId = getGlobal.rows[0].global_id;
        
        let queryCatalogo = `
          UPDATE catalogo_global 
          SET nombre_oficial = $1, descripcion = $2 
          WHERE global_id = $3
        `;
        
        await pool.query(queryCatalogo, [nuevo_nombre, nuevo_desc, globalId]);

        if (nuevo_foto) {
          await pool.query('UPDATE catalogo_global SET foto_url = $1 WHERE global_id = $2', [nuevo_foto, globalId]);
        }
      }

      return res.json({ mensaje: 'Producto actualizado correctamente' });
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

// ==========================================
// RUTA 9: CONVERTIRSE EN VENDEDOR (VERSIÓN LIMPIA 🛡️)
// ==========================================
app.post('/api/auth/convertir-vendedor', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  // Recibimos los datos del formulario
  const { nombre_tienda, categoria, whatsapp, direccion, tipo_actividad, rubro, lat, long, codigo_socio } = req.body;

  const client = await pool.connect();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    
    await client.query('BEGIN'); // Iniciamos la transacción

    let socioIdEncontrado = null;

    // 1. VALIDAR CÓDIGO DE SOCIO (Si existe)
    if (codigo_socio) {
      // Solo pedimos IDs, no nombres, para evitar errores de SQL
      const socioRes = await client.query('SELECT socio_id, usuario_id FROM socios WHERE codigo_referido = $1', [codigo_socio]);
      
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

    // 2. ACTUALIZAR EL TIPO DE USUARIO
    const nuevoTipoUsuario = (tipo_actividad === 'SERVICIO') ? 'Profesional' : categoria;
    await client.query(
      'UPDATE usuarios SET tipo = $1 WHERE usuario_id = $2',
      [nuevoTipoUsuario, usuario.id]
    );

    // 3. PREPARAR DATOS GEOGRÁFICOS Y FOTO
    const latitudFinal = lat || -45.86;
    const longitudFinal = long || -67.48;
    
    let fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/3081/3081559.png';
    if (tipo_actividad === 'SERVICIO') {
        fotoDefecto = 'https://cdn-icons-png.flaticon.com/512/1063/1063376.png';
    }

    // 4. INSERTAR EL LOCAL (LA TIENDA)
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

    await client.query('COMMIT'); // 🔒 GUARDAMOS CAMBIOS

    // 5. RESPONDER AL FRONTEND INMEDIATAMENTE
    console.log(`✅ Tienda creada para usuario ID: ${usuario.id}`);
    res.json({ mensaje: '¡Perfil profesional creado exitosamente!' });

    // 6. TAREAS SECUNDARIAS (Nivel Socio)
    // Lo hacemos fuera del flujo principal para que si falla, no rompa la tienda creada.
    if (socioIdEncontrado) {
       // Llamamos a la función auxiliar sin await bloqueante o con catch propio
       actualizarNivelSocio(socioIdEncontrado).catch(err => console.error("Error actualizando nivel (ignorable):", err.message));
    }

  } catch (error) {
    await client.query('ROLLBACK'); // Si algo falló antes del commit, deshacemos
    console.error("❌ Error creando tienda:", error);
    
    if (error.message && (error.message.includes("código") || error.message.includes("propio"))) {
       return res.status(400).json({ error: error.message });
    }
    
    // Solo respondemos si no se respondió antes
    if (!res.headersSent) {
        res.status(500).json({ error: 'Error al crear la tienda.' });
    }
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

// RUTA 13: CREAR PRODUCTO (BLINDADA 🛡️)
app.post('/api/mi-negocio/crear-item', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];

  const { 
    nombre, descripcion, precio, foto_url, tipo_item, stock_inicial,
    codigo_barras // <--- ESTE DATO ES CRÍTICO
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

    // 2. LOGICA GLOBAL (Solo si hay código)
    if (codigo_barras) {
        // Buscamos si existe en global
        const checkGlobal = await client.query('SELECT global_id FROM catalogo_global WHERE codigo_barras = $1', [codigo_barras]);
        
        if (checkGlobal.rows.length > 0) {
            globalId = checkGlobal.rows[0].global_id; // Vinculamos
        } else {
            // Creamos en global para ayudar a otros
            const insertGlobal = `
              INSERT INTO catalogo_global (nombre_oficial, descripcion, foto_url, categoria, codigo_barras, creado_por_usuario_id)
              VALUES ($1, $2, $3, $4, $5, $6) RETURNING global_id
            `;
            const resG = await client.query(insertGlobal, [nombre, descripcion, foto_url, categoria, codigo_barras, usuario.id]);
            globalId = resG.rows[0].global_id;
        }
    } else {
        // Producto sin código (Manual)
        const insertGlobal = `INSERT INTO catalogo_global (nombre_oficial, descripcion, foto_url, categoria) VALUES ($1, $2, $3, $4) RETURNING global_id`;
        const resG = await client.query(insertGlobal, [nombre, descripcion, foto_url, categoria]);
        globalId = resG.rows[0].global_id;
    }

    // 3. INSERTAR EN INVENTARIO LOCAL (AQUÍ ESTABA EL POSIBLE ERROR)
    let stock = tipo_item === 'PRODUCTO_STOCK' ? stock_inicial : 9999;

    const insertLocal = `
      INSERT INTO inventario_local 
      (local_id, global_id, precio, stock, tipo_item, codigo_barras)
      VALUES ($1, $2, $3, $4, $5, $6) -- <--- Aseguramos que $6 se guarde
    `;
    
    await client.query(insertLocal, [local_id, globalId, precio, stock, tipo_item, codigo_barras]);

    await client.query('COMMIT');
    res.json({ mensaje: 'Producto creado correctamente' });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error("Error creando item:", error);
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
        I.precio_regular

      FROM inventario_local I 
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id 
      WHERE I.local_id = $1
      AND I.stock > 0        -- FILTRO DE SEGURIDAD 1 (Hay mercadería)
      AND I.precio > 0       -- FILTRO DE SEGURIDAD 2 (Tiene precio real)
      
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
    `;
    
    // El orden del array debe coincidir EXACTAMENTE con los números $
    await pool.query(updateQuery, [
      nombre, direccion, whatsapp,                        // $1, $2, $3
      hora_apertura, hora_cierre, dias_atencion,          // $4, $5, $6
      rubro, permite_delivery, permite_retiro,            // $7, $8, $9
      pago_efectivo, pago_transferencia, pago_tarjeta,    // $10, $11, $12
      en_vacaciones, notif_nuevas_ventas, notif_preguntas,// $13, $14, $15
      
      usuario.id,   // $16 (Va en el WHERE)
      foto_perfil,  // $17
      foto_portada  // $18
    ]);

    res.json({ mensaje: 'Configuración y perfil guardados correctamente' });

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
// RUTA DE PAGOS: CHECKOUT MARKETPLACE (OPTIMIZADO v3 - MP 100%) 🌟
// ==========================================
app.post('/api/pagos/crear-preferencia', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  // Frontend nos manda items y el ID del local
  const { items, local_id, tipo_entrega } = req.body; 

  if (!local_id) return res.status(400).json({ error: 'Falta el ID del local' });

  try {
    // 0. Identificar al COMPRADOR
    const token = authHeader.split(' ')[1];
    const usuarioComprador = jwt.verify(token, JWT_SECRET);

    // 1. BUSCAR CREDENCIALES DEL VENDEDOR
    const queryLocal = 'SELECT mp_access_token, nombre, usuario_id FROM locales WHERE local_id = $1';
    const localRes = await pool.query(queryLocal, [local_id]);

    if (localRes.rows.length === 0) {
      return res.status(404).json({ error: 'Local no encontrado' });
    }

    const sellerData = localRes.rows[0];
    const sellerToken = sellerData.mp_access_token;

    if (!sellerToken) {
      return res.status(400).json({ 
        error: `El local "${sellerData.nombre}" no tiene pagos activos.` 
      });
    }

    // 2. GENERAR REFERENCIA EXTERNA ÚNICA (Acción Obligatoria MP)
    // Formato: CM (CercaMio) - Timestamp - ID Usuario
    const externalRef = `CM-${Date.now()}-${usuarioComprador.id}`;

    // 3. PREPARAR ITEMS
    let totalVenta = 0;
    
    // Metadata ligera
    const itemsParaMetadata = items.map(i => ({
      id: i.inventario_id,
      cant: Number(i.cantidad),
      precio: Number(i.precio),
      title: i.nombre
    }));

    const itemsMP = items.map(item => {
      const precio = Number(item.precio);
      const cantidad = Number(item.cantidad);
      totalVenta += precio * cantidad;
      
      // LÓGICA DE DESCRIPCIÓN Y CATEGORÍA (Acciones Recomendadas MP)
      // Si tiene descripción, la usamos (recortada a 200 chars por seguridad)
      // Si no tiene, repetimos el nombre.
      const descripcionItem = item.descripcion 
          ? item.descripcion.substring(0, 250) 
          : item.nombre;

      return {
        id: item.inventario_id.toString(),
        title: item.nombre,
        description: descripcionItem, // <--- RECOMENDADO AGREGADO
        category_id: 'others',        // <--- RECOMENDADO AGREGADO (Comodín)
        quantity: cantidad,
        unit_price: precio,
        currency_id: 'ARS',
      };
    });
    // COMISIÓN CERCAMÍO CONFIGURABLE - ACTUAL 1%
    const comisionCercaMio = Math.round((totalVenta * 0.01) * 100) / 100;

    // 4. CONFIGURAR CLIENTE
    const sellerClient = new MercadoPagoConfig({ accessToken: sellerToken });
    const preference = new Preference(sellerClient);

    // 5. CREAR PREFERENCIA
    const body = {
      items: itemsMP,
      marketplace_fee: comisionCercaMio,
      
      // --- OBLIGATORIO PARA CONCILIACIÓN ---
      external_reference: externalRef, 

      metadata: {
        comprador_id: usuarioComprador.id,
        vendedor_id: sellerData.usuario_id,
        local_id: local_id,
        tipo_entrega: tipo_entrega || 'RETIRO',
        items_json: JSON.stringify(itemsParaMetadata)
      },

      back_urls: {
        success: "cercamio://payment-result", 
        failure: "cercamio://payment-result",
        pending: "cercamio://payment-result"
      },
      auto_return: "approved",
      
      // La URL del Webhook
      notification_url: "https://cercamio-backend.onrender.com/api/pagos/webhook",
      
      statement_descriptor: "CERCAMIO APP"
    };

    const result = await preference.create({ body });

    res.json({ 
      id: result.id, 
      link_pago: result.init_point 
    });

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
        redirect_uri: 'https://cercamio-backend.onrender.com/api/pagos/callback'
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
// RUTA 37: WEBHOOK MAESTRO (VENTAS + SUSCRIPCIONES) 🤖 [CORREGIDO]
// ==========================================
app.post('/api/pagos/webhook', async (req, res) => {
  const { type, data } = req.body;

  // Solo procesamos pagos
  if (type === 'payment') {
    try {
      const paymentId = data.id;
      
      // 1. INICIALIZAR CLIENTE MP (LA LÍNEA QUE FALTABA) 🔑
      // Usamos el token de la plataforma para consultar el pago
      const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN_PROD });

      // 2. CONSULTAR ESTADO DEL PAGO
      const paymentClient = new Payment(client); 
      const paymentData = await paymentClient.get({ id: paymentId });

      if (paymentData.status === 'approved') {
        
        const externalRef = paymentData.external_reference; // Ej: "SUB-..." o "CM-..."
        console.log(`🔔 Webhook Aprobado. Ref: ${externalRef}`);

        // ====================================================
        // CASO A: SUSCRIPCIÓN PREMIUM (NUEVO) 💎
        // ====================================================
        if (externalRef && externalRef.startsWith('SUB-')) {
            
            // Extraemos datos de la metadata
            const { local_id, dias_duracion } = paymentData.metadata;
            const diasAgregar = Number(dias_duracion) || 30; 

            console.log(`💎 ACTIVANDO PLAN PREMIUM: Local ${local_id} (+${diasAgregar} días)`);

            // Lógica Inteligente de Vencimiento:
            const updateQuery = `
              UPDATE locales 
              SET 
                plan_tipo = 'PREMIUM',
                plan_vencimiento = CASE 
                   WHEN plan_vencimiento > NOW() THEN plan_vencimiento + make_interval(days => $2)
                   ELSE NOW() + make_interval(days => $2)
                END
              WHERE local_id = $1
            `;
            
            await pool.query(updateQuery, [local_id, diasAgregar]);
            console.log("✅ Suscripción activada exitosamente.");
        } 

        // ====================================================
        // CASO B: VENTA MARKETPLACE (TU CÓDIGO ORIGINAL) 🛒
        // ====================================================
        else if (externalRef && externalRef.startsWith('CM-')) {
            
            // 1. IDEMPOTENCIA
            const checkDuplicado = await pool.query('SELECT 1 FROM transacciones_p2p WHERE mp_payment_id = $1', [paymentId.toString()]);
            
            if (checkDuplicado.rows.length > 0) {
                console.log("⚠️ Venta ya registrada anteriormente. Ignorando.");
                return res.status(200).send("OK");
            }

            // 2. PROCESAMIENTO
            const meta = paymentData.metadata;
            const compradorId = meta.comprador_id;
            const vendedorId = meta.vendedor_id;
            const itemsComprados = typeof meta.items_json === 'string' ? JSON.parse(meta.items_json) : meta.items_json;
            const tipoEntrega = meta.tipo_entrega;
            const totalPagado = paymentData.transaction_amount;

            const compraUuid = crypto.randomUUID();

            console.log(`🛒 Procesando Venta para vendedor ${vendedorId}...`);

            const clientDb = await pool.connect(); 
            
            try {
              await clientDb.query('BEGIN');

              for (const item of itemsComprados) {
                 // A. BUSCAR DATOS REALES
                 const queryProducto = `
                    SELECT global_id, nombre, foto_url, tipo_item, stock 
                    FROM inventario_local 
                    WHERE inventario_id = $1 FOR UPDATE
                 `;
                 const prodRes = await clientDb.query(queryProducto, [item.id]);
                 
                 const datosReales = prodRes.rows.length > 0 ? prodRes.rows[0] : {
                    global_id: null,
                    nombre: item.title,
                    foto_url: null,
                    tipo_item: 'PRODUCTO_STOCK',
                    stock: 0
                 };

                 // B. DESCONTAR STOCK
                 if (datosReales.tipo_item === 'PRODUCTO_STOCK') {
                    await clientDb.query(
                      'UPDATE inventario_local SET stock = stock - $1 WHERE inventario_id = $2', 
                      [item.cant, item.id]
                    );
                 }

                 // C. INSERTAR TRANSACCIÓN
                 const insertTx = `
                    INSERT INTO transacciones_p2p 
                    (
                      comprador_id, vendedor_id, producto_global_id, cantidad, monto_total, 
                      estado, tipo_entrega, mp_payment_id, fecha_operacion,
                      compra_uuid, nombre_snapshot, foto_snapshot
                    )
                    VALUES ($1, $2, $3, $4, $5, 'APROBADO', $6, $7, NOW(), $8, $9, $10)
                 `;
                 
                 await clientDb.query(insertTx, [
                    compradorId, 
                    vendedorId, 
                    datosReales.global_id, 
                    item.cant, 
                    item.precio * item.cant, 
                    tipoEntrega,
                    paymentId.toString(),
                    compraUuid,            
                    datosReales.nombre,    
                    datosReales.foto_url   
                 ]);
              }

              await clientDb.query('COMMIT');
              
              // 5. NOTIFICAR
              const mensaje = `¡Pago de MP acreditado! Total: $${totalPagado}. Entrega: ${tipoEntrega}`;
              if (typeof enviarNotificacion === 'function') {
                  enviarNotificacion(vendedorId, "¡Nueva Venta Online! 💳", mensaje);
              }

            } catch (dbError) {
              await clientDb.query('ROLLBACK');
              console.error("❌ Error guardando Venta en BD:", dbError);
            } finally {
              clientDb.release();
            }
        }
      }
    } catch (error) {
      console.error("❌ Error general en Webhook:", error);
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
      notification_url: "https://cercamio-backend.onrender.com/api/pagos/webhook",
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
// RUTA 50: ESCÁNER INTELIGENTE (LOCAL -> GLOBAL -> INTERNET) 🧠🌐
// ==========================================
app.get('/api/producto/scan/:codigo', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });
  
  const codigo = req.params.codigo.trim();

  try {
    const token = authHeader.split(' ')[1];
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    // 1. Obtener Local ID
    const localRes = await pool.query('SELECT local_id FROM locales WHERE usuario_id = $1', [usuario.id]);
    if (localRes.rows.length === 0) return res.status(404).json({ error: 'Sin local' });
    const localId = localRes.rows[0].local_id;

    console.error(`🔥 [SCAN V3] Buscando '${codigo}' en Local ${localId}`);

    // --- CAPA 1: BÚSQUEDA LOCAL (CON HERENCIA) ---
    const queryLocal = `
      SELECT 
        I.inventario_id, I.local_id, I.precio, I.stock, I.tipo_item, I.codigo_barras,
        COALESCE(I.nombre, C.nombre_oficial) as nombre, 
        COALESCE(I.descripcion, C.descripcion) as descripcion,
        COALESCE(I.foto_url, C.foto_url) as foto_url
      FROM inventario_local I
      LEFT JOIN catalogo_global C ON I.global_id = C.global_id
      WHERE I.local_id = $1 
      AND CAST(I.codigo_barras AS TEXT) = $2
    `;
    
    const localProduct = await pool.query(queryLocal, [localId, codigo]);

    if (localProduct.rows.length > 0) {
      console.error("✅ ENCONTRADO EN LOCAL");
      return res.json({
        estado: 'EN_INVENTARIO', 
        producto: localProduct.rows[0]
      });
    }

    // --- CAPA 2: BÚSQUEDA GLOBAL (CercaMío) ---
    const globalProduct = await pool.query('SELECT * FROM catalogo_global WHERE CAST(codigo_barras AS TEXT) = $1', [codigo]);

    if (globalProduct.rows.length > 0) {
      console.error("☁️ ENCONTRADO EN GLOBAL");
      return res.json({
        estado: 'EN_GLOBAL', 
        producto: globalProduct.rows[0]
      });
    }

    // --- CAPA 3: INTERNET (OpenFoodFacts) 🌐 ---
    console.error("🌍 Buscando en OpenFoodFacts...");
    try {
        const offUrl = `https://world.openfoodfacts.org/api/v0/product/${codigo}.json`;
        const apiRes = await axios.get(offUrl, { timeout: 3000 });

        if (apiRes.data.status === 1) {
            const p = apiRes.data.product;
            console.error("🎉 ENCONTRADO EN INTERNET: " + p.product_name);
            
            // Retornamos mapeado para que la App lo use
            return res.json({
                estado: 'EN_GLOBAL', // Reutilizamos este estado para disparar el autocompletado
                producto: {
                    nombre_oficial: p.product_name_es || p.product_name || "",
                    descripcion: `Agregar descripción`,
                    //descripcion: `Marca: ${p.brands || 'S/D'}. Categoría: ${p.categories || 'General'}`,
                    foto_url: p.image_front_url || p.image_url || null,
                    codigo_barras: codigo
                }
            });
        }
    } catch (apiError) {
        console.error("⚠️ Error API Externa (No bloqueante):", apiError.message);
    }

    // --- CAPA 4: NUEVO (Si todo lo anterior falló) ---
    console.error("🆕 NO EXISTE. ES NUEVO.");
    res.json({
      estado: 'NUEVO', 
      codigo_barras: codigo
    });

  } catch (error) {
    console.error("❌ ERROR SCAN:", error);
    res.status(500).json({ error: 'Error interno' });
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


// ENCENDEMOS EL SERVIDOR
app.listen(port, () => {
  console.log(`🚀 SERVIDOR ACTUALIZADO - VERSIÓN CON SOCIOS ACTIVA - Puerto ${port}`);
});

