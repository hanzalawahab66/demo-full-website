import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

// ESM-compatible __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// App and config
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const PUBLIC_URL = process.env.PUBLIC_URL || process.env.APP_BASE_URL || `http://localhost:${process.env.FRONTEND_PORT || 8015}`;

// File-based fallback stores
const USERS_FILE = path.join(__dirname, 'users.json');
const CATEGORIES_FILE = path.join(__dirname, 'categories.json');
const LISTINGS_FILE = path.join(__dirname, 'listings.json');
const TAGS_FILE = path.join(__dirname, 'tags.json');
const ORDERS_FILE = path.join(__dirname, 'orders.json');
const MODELS_FILE = path.join(__dirname, 'models.json');
const BLOGS_FILE = path.join(__dirname, 'blogs.json');
const REVIEWS_FILE = path.join(__dirname, 'reviews.json');
// New: Secondary slider configuration (array of slides)
const SECONDARY_SLIDER_FILE = path.join(__dirname, 'secondary-slider.json');

// Helpers for file-based fallback
function readJson(filePath, defaultValue = []) {
  try {
    if (!fs.existsSync(filePath)) return defaultValue;
    const raw = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(raw || '[]');
    return Array.isArray(parsed) ? parsed : defaultValue;
  } catch (err) {
    console.warn(`Failed reading ${filePath}:`, err.message);
    return defaultValue;
  }
}

function writeJson(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.warn(`Failed writing ${filePath}:`, err.message);
  }
}

function nextId(items) {
  if (!Array.isArray(items) || items.length === 0) return 1;
  const max = items.reduce((acc, item) => Math.max(acc, Number(item.id || item.ID || 0)), 0);
  return max + 1;
}

// -------------------------
// Email sending for invoice notification
// -------------------------
function buildInvoiceUrl(orderId) {
  try { return `${PUBLIC_URL}/buyer-invoice.html?orderId=${encodeURIComponent(String(orderId))}`; } catch(_) { return `${PUBLIC_URL}/buyer-invoice.html?orderId=${orderId}`; }
}

function resolveBuyerEmail(order) {
  const email = order?.buyer_email || null;
  if (email) return email;
  try {
    const users = readJson(USERS_FILE, []);
    const u = (Array.isArray(users) ? users : []).find(x => String(x.id) === String(order?.buyer_id));
    return u?.email || null;
  } catch(_) { return null; }
}

async function sendInvoiceEmail(order) {
  try {
    const to = resolveBuyerEmail(order);
    if (!to) { console.warn('Invoice email skipped: no buyer email for order', order?.id); return { skipped: true, reason: 'no_email' }; }

    const host = process.env.SMTP_HOST;
    const port = Number(process.env.SMTP_PORT || 587);
    const secure = String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    const from = process.env.EMAIL_FROM || 'no-reply@nsm-koreacars.com';

    if (!host || !user || !pass) {
      console.warn('SMTP not configured; skipping email send. Set SMTP_HOST/SMTP_USER/SMTP_PASS');
      return { skipped: true, reason: 'smtp_not_configured' };
    }

    // Lazy-load nodemailer so server doesn't crash if not installed
    const nm = await import('nodemailer');
    const transporter = nm.createTransport({ host, port, secure, auth: { user, pass } });
    const url = order?.invoice_url || buildInvoiceUrl(order?.id);
    const subject = `Your Invoice for Order #${order?.id}`;
    const html = `
      <div style="font-family:Arial, sans-serif; color:#222">
        <h2>Invoice Completed</h2>
        <p>Dear Customer,</p>
        <p>Your order <strong>#${order?.id}</strong> has been marked as <strong>Completed</strong>.</p>
        <p>You can view and download your professional invoice at the link below:</p>
        <p><a href="${url}" target="_blank" rel="noopener">View Invoice</a></p>
        <p>If you have any questions, please reply to this email.</p>
        <hr />
        <p style="font-size:12px; color:#555">NAWISAJAD MUMAND CO., LTD</p>
      </div>`;
    const text = `Invoice Completed\nOrder #${order?.id}\nView your invoice: ${url}`;

    await transporter.sendMail({ from, to, subject, text, html });
    return { sent: true };
  } catch (err) {
    console.error('Failed to send invoice email:', err.message);
    return { error: err.message };
  }
}

// CORS setup
const allowedOrigins = [
  'http://localhost:8000',
  'http://127.0.0.1:8000',
  'http://localhost:8003',
  'http://127.0.0.1:8003',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:5501',
  'http://127.0.0.1:5501',
  'http://localhost:5502',
  'http://127.0.0.1:5502',
  'http://localhost:5510',
  'http://127.0.0.1:5510',
  'http://localhost:5511',
  'http://127.0.0.1:5511',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // allow same-origin
    const ok = allowedOrigins.includes(origin)
      || /^http:\/\/localhost:\d{4,5}$/.test(origin)
      || /^http:\/\/127\.0\.0\.1:\d{4,5}$/.test(origin);
    if (ok) return callback(null, true);
    // Dev-friendly: allow any origin but log it
    console.warn('CORS: allowing non-whitelisted origin', origin);
    return callback(null, true);
  },
  credentials: true,
}));

// Ensure CORS preflight succeeds for all routes
app.options('*', cors());

// Request logging middleware for debugging
app.use((req, res, next) => {
  const contentLength = req.get('Content-Length');
  if (contentLength) {
    console.log(`${req.method} ${req.path} - Content-Length: ${contentLength} bytes (${(contentLength / 1024 / 1024).toFixed(2)} MB)`);
  }
  next();
});

// Increase body size to handle images embedded as data URLs
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
// Serve static files (frontend HTML/CSS/JS) from project root
app.use(express.static(path.resolve(__dirname, '..')));
// Serve uploaded files from /uploads
const UPLOADS_DIR = path.resolve(__dirname, '..', 'uploads');
try { if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true }); } catch(_) {}
app.use('/uploads', express.static(UPLOADS_DIR));

// MySQL setup (optional; falls back to JSON files if unreachable)
const DB_HOST = process.env.DB_HOST || '127.0.0.1';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';
const DB_NAME = process.env.DB_NAME || 'nsm_autos';

let pool = null;

async function createPool() {
  try {
    pool = mysql.createPool({
      host: DB_HOST,
      user: DB_USER,
      password: DB_PASSWORD,
      database: DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });
    await pool.query('SELECT 1');
    console.log('DB connected');
    return true;
  } catch (err) {
    console.warn('DB setup skipped (not reachable):', err.message);
    pool = null;
    return false;
  }
}

async function setupDatabase() {
  const ok = await createPool();
  if (!ok) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('buyer','seller','admin','superadmin','listing_editor','user_manager') NOT NULL,
        status ENUM('pending','approved','rejected','suspended') NOT NULL DEFAULT 'pending',
        phone_number VARCHAR(30) NULL,
        country VARCHAR(100) NULL,
        company_name_korean VARCHAR(255) NULL,
        company_name_english VARCHAR(255) NULL,
        export_items VARCHAR(100) NULL,
        available_languages TEXT NULL,
        representative_name VARCHAR(255) NULL,
        company_tel VARCHAR(50) NULL,
        company_logo_url VARCHAR(255) NULL,
        company_address VARCHAR(255) NULL,
        detailed_address VARCHAR(255) NULL,
        establishment_date DATE NULL,
        business_registration_url VARCHAR(255) NULL,
        business_registration_document VARCHAR(255) NULL,
        company_introduction TEXT NULL,
        bank_name VARCHAR(255) NULL,
        account_number VARCHAR(255) NULL,
        account_holder_name VARCHAR(255) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        parent_id INT NULL,
        image_url VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    // Backward-compatible upgrades for existing deployments
    try { await pool.query('ALTER TABLE categories ADD COLUMN parent_id INT NULL'); } catch(_) {}
    try { await pool.query('ALTER TABLE categories ADD COLUMN image_url VARCHAR(255) NULL'); } catch(_) {}
    try { await pool.query("ALTER TABLE categories ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"); } catch(_) {}

    await pool.query(`
      CREATE TABLE IF NOT EXISTS listings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        price DECIMAL(12,2) NOT NULL,
        category_id INT,
        description TEXT,
        status ENUM('pending','approved','rejected') DEFAULT 'approved',
        seller_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories(id)
      ) ENGINE=InnoDB;
    `);

    // Tags (no color column) and listing-tags association for strict tagging
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tags (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        slug VARCHAR(255) UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS listing_tags (
        listing_id INT NOT NULL,
        tag_id INT NOT NULL,
        PRIMARY KEY (listing_id, tag_id),
        FOREIGN KEY (listing_id) REFERENCES listings(id) ON DELETE CASCADE,
        FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
      ) ENGINE=InnoDB;
    `);
    console.log('DB schema ensured');
  } catch (err) {
    console.warn('DB schema setup failed:', err.message);
  }
}

setupDatabase().catch(err => console.error('setupDatabase error:', err));

// Health endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Auth helpers
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function authorizeRoles(allowed) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    if (!allowed.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

// New: Listing Editor gate — allows listing_editor, user_manager, superadmin, admin
const authListingEditor = [authenticateToken, authorizeRoles(['listing_editor', 'user_manager', 'superadmin', 'admin'])];
// Super Admin only gate
const authSuperAdmin = [authenticateToken, authorizeRoles(['superadmin'])];

// Login route with DB + file fallback
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    let user = null;

    // Try DB first
    if (pool) {
      try {
        const [rows] = await pool.query(
          'SELECT id, name, email, password, password_hash, role, status FROM users WHERE email = ?',
          [email]
        );
        if (rows && rows.length > 0) {
          const r = rows[0];
          user = { id: r.id, name: r.name, email: r.email, password: r.password, password_hash: r.password_hash, role: r.role, status: r.status };
        }
      } catch (err) {
        console.warn('DB query failed for login:', err.message);
      }
    }

    // Fallback to file store
    if (!user) {
      const users = readJson(USERS_FILE);
      user = users.find(u => u.email === email) || null;
    }

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const passwordHash = user.password_hash || user.password;
    const rawPassword = user.password; // for legacy dev entries

    let ok = false;
    if (passwordHash) {
      ok = await bcrypt.compare(password, passwordHash);
    } else if (rawPassword) {
      ok = await bcrypt.compare(password, await bcrypt.hash(rawPassword, 10));
    }

    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const status = String(user.status || '').toLowerCase();
    const roleLower = String(user.role || '').toLowerCase();
    if (roleLower === 'seller' && (status === 'pending' || status === 'rejected')) {
      return res.status(403).json({ error: 'Seller account not approved' });
    }
    if (status === 'suspended') {
      return res.status(403).json({ error: 'Account suspended' });
    }

    // Allow staff roles and common roles to sign in
    const allowedRolesLogin = ['superadmin', 'user_manager', 'listing_editor', 'seller', 'buyer'];
  if (!allowedRolesLogin.includes(String(user.role))) {
      return res.status(403).json({ error: 'Role not permitted' });
    }

    const token = generateToken({ id: user.id || email, email, role: user.role });
    // Provide a redirect hint for the client based on role
    const redirectMap = {
      superadmin: 'admin.html',
      user_manager: 'user-management.html',
      listing_editor: 'manage-all-listings.html',
      seller: 'seller-dashboard.html',
      buyer: 'buyer-dashboard.html'
    };
    return res.json({
      message: 'Login successful',
      token,
      role: user.role,
      user: { id: user.id || email, name: user.name || null, email, role: user.role },
      redirect: redirectMap[user.role] || 'admin.html'
    });
  } catch (err) {
    return res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// -------------------------
// Public Tags (Strict Tagging source)
// -------------------------
app.get('/public/tags', async (req, res) => {
  try {
    if (pool) {
      const [rows] = await pool.query(
        'SELECT id, name, slug, created_at FROM tags ORDER BY created_at DESC'
      );
      return res.json(rows);
    }
    const tags = readJson(TAGS_FILE, []);
    return res.json(Array.isArray(tags) ? tags.map(t => ({ id: t.id, name: t.name, slug: t.slug, created_at: t.created_at })) : []);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch tags', details: err.message });
  }
});

// -------------------------
// Public: Secondary Home Slider
// -------------------------
app.get('/public/sliders/home-secondary', async (req, res) => {
  try {
    // File-based store: array of { src, alt }
    const slides = readJson(SECONDARY_SLIDER_FILE, []);
    return res.json(Array.isArray(slides) ? slides : []);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch secondary slider', details: err.message });
  }
});

// -------------------------
// Public Models (Car Models)
// -------------------------
app.get('/public/models', async (req, res) => {
  try {
    if (pool) {
      try {
        const [rows] = await pool.query(
          'SELECT id, name, slug, created_at FROM models ORDER BY name'
        );
        return res.json(rows);
      } catch (dbErr) {
        console.warn('DB error on /public/models, falling back to JSON:', dbErr.message);
      }
    }
    const models = readJson(MODELS_FILE, []);
    return res.json(Array.isArray(models) ? models : []);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch models', details: err.message });
  }
});

// -------------------------
// Public Blogs
// -------------------------
app.get('/public/blogs', async (req, res) => {
  try {
    const blogs = readJson(BLOGS_FILE, []);
    const list = Array.isArray(blogs) ? blogs.slice().sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)) : [];
    return res.json({ blogs: list });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch blogs', details: err.message });
  }
});

// Public: Individual Blog by ID (no auth)
app.get('/public/blogs/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const blogs = readJson(BLOGS_FILE, []);
    const blog = (Array.isArray(blogs) ? blogs : []).find(b => Number(b.id) === id);
    if (!blog) return res.status(404).json({ error: 'Blog not found' });
    return res.json(blog);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch blog', details: err.message });
  }
});

// -------------------------
// Public: Approved Listings (no auth)
// -------------------------
app.get('/public/listings', async (req, res) => {
  try {
    // Prefer DB if available
    if (pool) {
      try {
        const [rows] = await pool.query(
          'SELECT id, title, price, product_id_number, category_id, description, status, seller_id, created_at FROM listings WHERE status = ? ORDER BY created_at DESC',
          ['approved']
        );
        return res.json({ listings: rows });
      } catch (dbErr) {
        console.warn('DB error on /public/listings, falling back to JSON:', dbErr.message);
      }
    }

    // JSON fallback
    const listings = readJson(LISTINGS_FILE, []);
    const approved = (Array.isArray(listings) ? listings : [])
      .filter(l => String(l.status || '').toLowerCase() === 'approved')
      .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    return res.json({ listings: approved });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch public listings', details: err.message });
  }
});

// -------------------------
// Public: Individual Listing by ID (no auth)
// -------------------------
app.get('/public/listings/:id', async (req, res) => {
  try {
    const listingId = req.params.id;
    
    // Prefer DB if available
    if (pool) {
      try {
        const [rows] = await pool.query(
          'SELECT * FROM listings WHERE id = ? AND status = ?',
          [listingId, 'approved']
        );
        if (rows.length === 0) {
          return res.status(404).json({ error: 'Vehicle not found' });
        }
        return res.json(rows[0]);
      } catch (dbErr) {
        console.warn('DB error on /public/listings/:id, falling back to JSON:', dbErr.message);
      }
    }

    // JSON fallback
    const listings = readJson(LISTINGS_FILE, []);
    const listing = (Array.isArray(listings) ? listings : [])
      .find(l => String(l.id) === String(listingId) && String(l.status || '').toLowerCase() === 'approved');
    
    if (!listing) {
      return res.status(404).json({ error: 'Vehicle not found' });
    }
    
    return res.json(listing);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch listing', details: err.message });
  }
});

// -------------------------
// Admin: Create Tag (no color field)
// -------------------------
app.post('/admin/tags', ...authListingEditor, async (req, res) => {
  try {
    let { name, slug } = req.body || {};
    name = String(name || '').trim();
    slug = String(slug || '').trim();
    const toSlug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').replace(/-{2,}/g, '-');
    if (!name) return res.status(400).json({ error: 'Tag name required' });
    if (!slug) slug = toSlug(name);

    if (pool) {
      try {
        const [result] = await pool.query('INSERT INTO tags (name, slug) VALUES (?, ?)', [name, slug]);
        const id = result.insertId;
        return res.status(201).json({ id, name, slug });
      } catch (dbErr) {
        return res.status(500).json({ error: 'DB insert failed', details: dbErr.message });
      }
    }

    const tags = readJson(TAGS_FILE, []);
    if (tags.some(t => String(t.name).toLowerCase() === name.toLowerCase())) {
      return res.status(409).json({ error: 'Tag with same name exists' });
    }
    const id = nextId(tags);
    const created_at = new Date().toISOString();
    const tag = { id, name, slug, created_at };
    tags.push(tag);
    writeJson(TAGS_FILE, tags);
    return res.status(201).json(tag);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to create tag', details: err.message });
  }
});

// -------------------------
// Admin: Update Tag name
// -------------------------
app.put('/admin/tags/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    let { name } = req.body || {};
    name = String(name || '').trim();
    if (!name) return res.status(400).json({ error: 'Tag name required' });

    if (pool) {
      try {
        const [result] = await pool.query('UPDATE tags SET name = ? WHERE id = ?', [name, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Tag not found' });
        const [rows] = await pool.query('SELECT id, name, slug, created_at FROM tags WHERE id = ?', [id]);
        if (!rows || rows.length === 0) return res.status(404).json({ error: 'Tag not found' });
        return res.json(rows[0]);
      } catch (dbErr) {
        return res.status(500).json({ error: 'DB update failed', details: dbErr.message });
      }
    }

    const tags = readJson(TAGS_FILE, []);
    const idx = tags.findIndex(t => Number(t.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'Tag not found' });
    tags[idx].name = name;
    writeJson(TAGS_FILE, tags);
    const { slug, created_at } = tags[idx];
    return res.json({ id: Number(id), name, slug, created_at });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update tag', details: err.message });
  }
});

// -------------------------
// Admin: Delete Tag
// -------------------------
app.delete('/admin/tags/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;

    if (pool) {
      try {
        // Remove tag associations first to avoid FK issues
        await pool.query('DELETE FROM listing_tags WHERE tag_id = ?', [id]);
        const [result] = await pool.query('DELETE FROM tags WHERE id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Tag not found' });
        return res.json({ id: Number(id), removed: true });
      } catch (dbErr) {
        return res.status(500).json({ error: 'DB delete failed', details: dbErr.message });
      }
    }

    const tags = readJson(TAGS_FILE, []);
    const idx = tags.findIndex(t => Number(t.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'Tag not found' });
    tags.splice(idx, 1);
    writeJson(TAGS_FILE, tags);
    return res.json({ id: Number(id), removed: true });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete tag', details: err.message });
  }
});

// Signup route (buyer/seller) with DB + file fallback
app.post('/signup', async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      role,
      country,
      phone_number,
      // seller extras (ignored if not provided)
      company_name_korean,
      company_name_english,
      representative_name,
      company_tel,
      company_address,
      detailed_address,
      establishment_date,
      business_registration_url,
      business_registration_document,
      company_introduction,
      bank_name,
      account_number,
      account_holder_name,
      company_logo_url,
      export_items,
      available_languages,
  } = req.body || {};

  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: 'Name, email, password, and role are required' });
  }
  const allowedSignupRoles = ['buyer', 'seller'];
  if (!allowedSignupRoles.includes(String(role))) {
    return res.status(400).json({ error: 'Invalid role for signup' });
  }

  // Enforce required fields per role
  const roleLower = String(role).toLowerCase();
  const missing = [];
  const hasVal = (v) => String(v || '').trim().length > 0;
  if (roleLower === 'buyer') {
    if (!hasVal(country)) missing.push('country');
    if (!hasVal(phone_number)) missing.push('phone_number');
  } else if (roleLower === 'seller') {
    const requiredSeller = [
      'country', 'phone_number', 'company_name_korean', 'company_name_english',
      'representative_name', 'company_tel', 'company_address', 'detailed_address',
      'establishment_date', 'company_introduction', 'bank_name', 'account_number',
      'account_holder_name', 'export_items'
    ];
    const fieldMap = {
      country,
      phone_number,
      company_name_korean,
      company_name_english,
      representative_name,
      company_tel,
      company_address,
      detailed_address,
      establishment_date,
      company_introduction,
      bank_name,
      account_number,
      account_holder_name,
      export_items,
    };
    requiredSeller.forEach((field) => { if (!hasVal(fieldMap[field])) missing.push(field); });
    const langsOk = Array.isArray(available_languages) ? available_languages.length > 0 : hasVal(available_languages);
    if (!langsOk) missing.push('available_languages');
    const hasBusinessReg = hasVal(business_registration_url) || hasVal(business_registration_document);
    if (!hasBusinessReg) missing.push('business_registration_url_or_document');
    if (!hasVal(company_logo_url)) missing.push('company_logo_url');
  }
  if (missing.length) {
    return res.status(400).json({ error: 'Missing required fields', missing });
  }

  const password_hash = await bcrypt.hash(String(password), 10);
  const status = String(role) === 'seller' ? 'pending' : 'approved';

    // Try DB first
    if (pool) {
      try {
        const [dup] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (dup && dup.length > 0) {
          return res.status(409).json({ error: 'Email already in use' });
        }
        // Prefer inserting into modern schema with `password`
        try {
          await pool.query(
            `INSERT INTO users (
              name, email, password, role, status, phone_number, country,
              company_name_korean, company_name_english, export_items, available_languages,
              representative_name, company_tel, company_logo_url, company_address, detailed_address,
              establishment_date, business_registration_url, business_registration_document,
              company_introduction, bank_name, account_number, account_holder_name
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [
              name, email, password_hash, role, status, phone_number || null, country || null,
              company_name_korean || null, company_name_english || null, export_items || null, available_languages || null,
              representative_name || null, company_tel || null, company_logo_url || null, company_address || null, detailed_address || null,
              establishment_date || null, business_registration_url || null, business_registration_document || null,
              company_introduction || null, bank_name || null, account_number || null, account_holder_name || null
            ]
          );
        } catch (schemaErr) {
          // Fallback for older schema that uses password_hash and minimal columns
          console.warn('Primary users insert failed, trying legacy schema:', schemaErr.message);
          await pool.query(
            'INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, ?, ?)',
            [email, password_hash, role, status]
          );
        }
        return res.status(201).json({ message: 'Signup successful', email, role, status });
      } catch (err) {
        console.warn('DB signup failed, falling back:', err.message);
      }
    }

    // File-based fallback
    const users = readJson(USERS_FILE, []);
    if (users.some(u => u.email === email)) {
      return res.status(409).json({ error: 'Email already in use' });
    }
    const id = nextId(users);
    // Store flat user object for file fallback to match admin UI expectations
    users.push({
      id,
      name,
      email,
      password_hash,
      role,
      status,
      phone_number: phone_number || null,
      country: country || null,
      company_name_korean: company_name_korean || null,
      company_name_english: company_name_english || null,
      export_items: export_items || null,
      available_languages: available_languages || null,
      representative_name: representative_name || null,
      company_tel: company_tel || null,
      company_logo_url: company_logo_url || null,
      company_address: company_address || null,
      detailed_address: detailed_address || null,
      establishment_date: establishment_date || null,
      business_registration_url: business_registration_url || null,
      business_registration_document: business_registration_document || null,
      company_introduction: company_introduction || null,
      bank_name: bank_name || null,
      account_number: account_number || null,
      account_holder_name: account_holder_name || null,
      created_at: new Date().toISOString()
    });
    writeJson(USERS_FILE, users);
    return res.status(201).json({ message: 'Signup successful', id, email, role, status });
  } catch (err) {
    return res.status(500).json({ error: 'Signup failed', details: err.message });
  }
});

// -------------------------
// Simple base64 upload endpoint
// -------------------------
function sanitizeFilename(name) {
  const base = String(name || '').trim().replace(/\s+/g, '-');
  return base.replace(/[^a-zA-Z0-9._-]/g, '');
}

function pickExtensionFromMime(mime) {
  const map = {
    'image/png': '.png',
    'image/jpeg': '.jpg',
    'image/jpg': '.jpg',
    'image/gif': '.gif',
    'image/svg+xml': '.svg',
    'application/pdf': '.pdf',
    'application/msword': '.doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx'
  };
  return map[mime] || '';
}

app.post('/upload', async (req, res) => {
  try {
    const { filename, dataUrl } = req.body || {};
    if (!filename || !dataUrl) {
      return res.status(400).json({ error: 'filename and dataUrl are required' });
    }
    const match = /^data:([^;]+);base64,(.+)$/.exec(String(dataUrl));
    if (!match) {
      return res.status(400).json({ error: 'Invalid dataUrl format' });
    }
    const mime = match[1];
    const b64 = match[2];
    const buf = Buffer.from(b64, 'base64');
    if (!buf || !buf.length) {
      return res.status(400).json({ error: 'Empty upload data' });
    }
    // Max ~25MB to be safe
    const MAX_BYTES = 25 * 1024 * 1024;
    if (buf.length > MAX_BYTES) {
      return res.status(413).json({ error: 'File too large' });
    }
    const originalExt = path.extname(filename || '');
    const safeBase = sanitizeFilename(path.basename(filename, originalExt) || 'file');
    const ext = originalExt || pickExtensionFromMime(mime) || '';
    const unique = `${Date.now()}-${Math.random().toString(36).slice(2,8)}`;
    const finalName = `${safeBase}-${unique}${ext}`;
    const dest = path.join(UPLOADS_DIR, finalName);
    fs.writeFileSync(dest, buf);
    const url = `/uploads/${finalName}`;
    return res.status(201).json({ url });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: 'Upload failed', details: err.message });
  }
});

// -------------------------
// Admin: Users — full data for management
// -------------------------
app.get('/admin/users', authenticateToken, authorizeRoles(['user_manager', 'superadmin']), async (req, res) => {
  try {
    if (pool) {
      const [rows] = await pool.query(
        `SELECT id, name, email, role, status, phone_number, country,
                company_name_korean, company_name_english, export_items, available_languages,
                representative_name, company_tel, company_logo_url, company_address, detailed_address,
                establishment_date, business_registration_url, business_registration_document,
                company_introduction, bank_name, account_number, account_holder_name, created_at
         FROM users
         ORDER BY created_at DESC`
      );
      return res.json({ users: rows });
    }
    const users = readJson(USERS_FILE, []);
    const flattened = (Array.isArray(users) ? users : []).map((u, idx) => ({
      id: u.id != null ? u.id : (u.userId != null ? u.userId : idx + 1),
      name: u.name || u.profile?.name || null,
      email: u.email || null,
      role: (u.role || '').toLowerCase(),
      status: (u.status || 'pending').toLowerCase(),
      phone_number: u.phone_number != null ? u.phone_number : (u.profile?.phone_number || null),
      country: u.country != null ? u.country : (u.profile?.country || null),
      company_name_korean: u.company_name_korean != null ? u.company_name_korean : (u.profile?.company_name_korean || null),
      company_name_english: u.company_name_english != null ? u.company_name_english : (u.profile?.company_name_english || null),
      export_items: u.export_items != null ? u.export_items : (u.profile?.export_items || null),
      available_languages: u.available_languages != null ? u.available_languages : (u.profile?.available_languages || null),
      representative_name: u.representative_name != null ? u.representative_name : (u.profile?.representative_name || null),
      company_tel: u.company_tel != null ? u.company_tel : (u.profile?.company_tel || null),
      company_logo_url: u.company_logo_url != null ? u.company_logo_url : (u.profile?.company_logo_url || null),
      company_address: u.company_address != null ? u.company_address : (u.profile?.company_address || null),
      detailed_address: u.detailed_address != null ? u.detailed_address : (u.profile?.detailed_address || null),
      establishment_date: u.establishment_date != null ? u.establishment_date : (u.profile?.establishment_date || null),
      business_registration_url: u.business_registration_url != null ? u.business_registration_url : (u.profile?.business_registration_url || null),
      business_registration_document: u.business_registration_document != null ? u.business_registration_document : null,
      company_introduction: u.company_introduction != null ? u.company_introduction : (u.profile?.company_introduction || null),
      bank_name: u.bank_name != null ? u.bank_name : (u.profile?.bank_name || null),
      account_number: u.account_number != null ? u.account_number : (u.profile?.account_number || null),
      account_holder_name: u.account_holder_name != null ? u.account_holder_name : (u.profile?.account_holder_name || null),
      created_at: u.created_at || new Date().toISOString()
    }));
    return res.json({ users: flattened });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch users', details: err.message });
  }
});

// -------------------------
// Admin: Approve/Reject/Suspend Users
// -------------------------
app.put('/admin/approve/:id', authenticateToken, authorizeRoles(['user_manager', 'superadmin']), async (req, res) => {
  try {
    const { id } = req.params;
    if (pool) {
      const [result] = await pool.query('UPDATE users SET status = ? WHERE id = ?', ['approved', id]);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
      return res.json({ id: Number(id), status: 'approved' });
    }
    const users = readJson(USERS_FILE, []);
    const idx = users.findIndex(u => Number(u.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    users[idx].status = 'approved';
    writeJson(USERS_FILE, users);
    return res.json({ id: Number(id), status: 'approved' });
  } catch (err) {
    return res.status(500).json({ error: 'Approve failed', details: err.message });
  }
});

app.put('/admin/reject/:id', authenticateToken, authorizeRoles(['user_manager', 'superadmin']), async (req, res) => {
  try {
    const { id } = req.params;
    if (pool) {
      const [result] = await pool.query('UPDATE users SET status = ? WHERE id = ?', ['rejected', id]);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
      return res.json({ id: Number(id), status: 'rejected' });
    }
    const users = readJson(USERS_FILE, []);
    const idx = users.findIndex(u => Number(u.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    users[idx].status = 'rejected';
    writeJson(USERS_FILE, users);
    return res.json({ id: Number(id), status: 'rejected' });
  } catch (err) {
    return res.status(500).json({ error: 'Reject failed', details: err.message });
  }
});

app.put('/admin/suspend/:id', authenticateToken, authorizeRoles(['user_manager', 'superadmin']), async (req, res) => {
  try {
    const { id } = req.params;
    if (pool) {
      const [result] = await pool.query('UPDATE users SET status = ? WHERE id = ?', ['suspended', id]);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
      return res.json({ id: Number(id), status: 'suspended' });
    }
    const users = readJson(USERS_FILE, []);
    const idx = users.findIndex(u => Number(u.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    users[idx].status = 'suspended';
    writeJson(USERS_FILE, users);
    return res.json({ id: Number(id), status: 'suspended' });
  } catch (err) {
    return res.status(500).json({ error: 'Suspend failed', details: err.message });
  }
});

// -------------------------
// Category Management (CRUD)
// -------------------------
// All routes secured with authListingEditor (fixes old authAdmin protections)

// Get categories
app.get('/admin/categories', ...authListingEditor, async (req, res) => {
  try {
    if (pool) {
      const [rows] = await pool.query('SELECT id, name, parent_id, image_url, created_at FROM categories ORDER BY name');
      return res.json(rows);
    }
    const categories = readJson(CATEGORIES_FILE, []);
    return res.json(categories);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch categories', details: err.message });
  }
});

// Public categories (no auth) — used by inventory filters
app.get('/public/categories', async (req, res) => {
  try {
    if (pool) {
      const [rows] = await pool.query('SELECT id, name, parent_id, image_url, created_at FROM categories ORDER BY name');
      return res.json(rows);
    }
    const categories = readJson(CATEGORIES_FILE, []);
    return res.json(categories);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch categories', details: err.message });
  }
});

// -------------------------
// Model Management (CRUD)
// -------------------------
// All routes secured with authListingEditor

// Get models
app.get('/admin/models', ...authListingEditor, async (req, res) => {
  try {
    if (pool) {
      try {
        const [rows] = await pool.query('SELECT id, name, slug, created_at FROM models ORDER BY name');
        return res.json(rows);
      } catch (dbErr) {
        console.warn('DB error on /admin/models, falling back to JSON:', dbErr.message);
      }
    }
    const models = readJson(MODELS_FILE, []);
    return res.json(models);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch models', details: err.message });
  }
});

// Create model
app.post('/admin/models', ...authListingEditor, async (req, res) => {
  try {
    let { name, slug } = req.body || {};
    if (!name || String(name).trim() === '') {
      return res.status(400).json({ error: 'Model name is required' });
    }
    const toSlug = (str) => String(str || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .replace(/-{2,}/g, '-');
    slug = (slug && String(slug).trim()) ? String(slug).trim() : toSlug(name);

    if (pool) {
      try {
        const [result] = await pool.query('INSERT INTO models (name, slug) VALUES (?, ?)', [name.trim(), slug]);
        const id = result.insertId;
        return res.status(201).json({ id, name: name.trim(), slug });
      } catch (dbErr) {
        console.warn('DB error on POST /admin/models, falling back to JSON:', dbErr.message);
      }
    }

    const models = readJson(MODELS_FILE, []);
    if ((Array.isArray(models) ? models : []).some(m => String(m.name || '').toLowerCase() === String(name).trim().toLowerCase())) {
      return res.status(409).json({ error: 'Model already exists' });
    }
    const id = nextId(models);
    const newModel = { id, name: String(name).trim(), slug, created_at: new Date().toISOString() };
    models.push(newModel);
    writeJson(MODELS_FILE, models);
    return res.status(201).json(newModel);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to create model', details: err.message });
  }
});

// Update model
app.put('/admin/models/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    let { name, slug } = req.body || {};
    if (!name || String(name).trim() === '') {
      return res.status(400).json({ error: 'Model name is required' });
    }
    const toSlug = (str) => String(str || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .replace(/-{2,}/g, '-');
    slug = (slug && String(slug).trim()) ? String(slug).trim() : toSlug(name);

    if (pool) {
      try {
        const [result] = await pool.query('UPDATE models SET name = ?, slug = ? WHERE id = ?', [name.trim(), slug, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Model not found' });
        return res.json({ id: Number(id), name: name.trim(), slug });
      } catch (dbErr) {
        console.warn('DB error on PUT /admin/models/:id, falling back to JSON:', dbErr.message);
      }
    }

    const models = readJson(MODELS_FILE, []);
    const idx = models.findIndex(m => Number(m.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'Model not found' });
    models[idx].name = String(name).trim();
    models[idx].slug = slug;
    writeJson(MODELS_FILE, models);
    return res.json(models[idx]);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update model', details: err.message });
  }
});

// Delete model
app.delete('/admin/models/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    if (pool) {
      try {
        const [result] = await pool.query('DELETE FROM models WHERE id = ?', [id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Model not found' });
        return res.json({ id: Number(id), deleted: true });
      } catch (dbErr) {
        console.warn('DB error on DELETE /admin/models/:id, falling back to JSON:', dbErr.message);
      }
    }

    const models = readJson(MODELS_FILE, []);
    const idx = models.findIndex(m => Number(m.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'Model not found' });
    const removed = models.splice(idx, 1)[0];
    writeJson(MODELS_FILE, models);
    return res.json({ id: Number(id), deleted: true, name: removed?.name });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete model', details: err.message });
  }
});

// -------------------------
// Admin: Update Secondary Home Slider
// -------------------------
app.put('/admin/sliders/home-secondary', ...authListingEditor, async (req, res) => {
  try {
    // Accept either { slides: [...] } or a raw array
    let slides = (req.body && Array.isArray(req.body.slides)) ? req.body.slides : (Array.isArray(req.body) ? req.body : null);
    if (!Array.isArray(slides)) {
      return res.status(400).json({ error: 'slides array required' });
    }
    // Normalize payload
    const normalized = slides.map(s => ({
      src: String(s.src || s.url || '').trim(),
      alt: String(s.alt || '')
    })).filter(s => s.src);
    writeJson(SECONDARY_SLIDER_FILE, normalized);
    return res.json(normalized);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update secondary slider', details: err.message });
  }
});

// -------------------------
// Admin Blogs (create/list)
// -------------------------
app.get('/admin/blogs', ...authListingEditor, async (req, res) => {
  try {
    const blogs = readJson(BLOGS_FILE, []);
    return res.json(Array.isArray(blogs) ? blogs : []);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch blogs', details: err.message });
  }
});

app.post('/admin/blogs', ...authListingEditor, async (req, res) => {
  try {
    const { title, description_html, featured_image_url } = req.body || {};
    const safeTitle = String(title || '').trim();
    const safeDesc = String(description_html || '').trim();
    const safeFeat = String(featured_image_url || '').trim();

    if (!safeTitle || !safeDesc) {
      return res.status(400).json({ error: 'title and description_html are required' });
    }

    const blogs = readJson(BLOGS_FILE, []);
    const id = nextId(Array.isArray(blogs) ? blogs : []);
    const blog = {
      id,
      title: safeTitle,
      description_html: safeDesc,
      featured_image_url: safeFeat,
      created_at: new Date().toISOString(),
      author_id: (req.user && req.user.id) ? req.user.id : null
    };
    const next = Array.isArray(blogs) ? blogs : [];
    next.push(blog);
    writeJson(BLOGS_FILE, next);
    return res.status(201).json(blog);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to create blog', details: err.message });
  }
});

// Admin: Update Blog
app.put('/admin/blogs/:id', ...authListingEditor, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { title, description_html, featured_image_url } = req.body || {};

    const blogs = readJson(BLOGS_FILE, []);
    const idx = (Array.isArray(blogs) ? blogs : []).findIndex(b => Number(b.id) === id);
    if (idx === -1) return res.status(404).json({ error: 'Blog not found' });

    const prev = blogs[idx] || {};
    const updated = {
      ...prev,
      title: String(title ?? prev.title).trim(),
      description_html: String(description_html ?? prev.description_html).trim(),
      featured_image_url: String(featured_image_url ?? prev.featured_image_url).trim(),
      updated_at: new Date().toISOString(),
    };
    blogs[idx] = updated;
    writeJson(BLOGS_FILE, blogs);
    return res.json(updated);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update blog', details: err.message });
  }
});

// Create category
app.post('/admin/categories', ...authListingEditor, async (req, res) => {
  try {
    const { name, parent_id, image_url } = req.body || {};
    if (!name || String(name).trim() === '') {
      return res.status(400).json({ error: 'Category name is required' });
    }

    if (pool) {
      const parentIdOrNull = parent_id != null && parent_id !== '' ? Number(parent_id) : null;
      const [result] = await pool.query('INSERT INTO categories (name, parent_id, image_url) VALUES (?, ?, ?)', [name.trim(), parentIdOrNull, (image_url && String(image_url).trim()) ? String(image_url).trim() : null]);
      const id = result.insertId;
      return res.status(201).json({ id, name: name.trim(), parent_id: parentIdOrNull, image_url: (image_url && String(image_url).trim()) ? String(image_url).trim() : null });
    }

    const categories = readJson(CATEGORIES_FILE, []);
    if (categories.some(c => c.name.toLowerCase() === name.trim().toLowerCase())) {
      return res.status(409).json({ error: 'Category already exists' });
    }
    const id = nextId(categories);
    const parentIdOrNull = parent_id != null && parent_id !== '' ? Number(parent_id) : null;
    const newCategory = { id, name: name.trim(), parent_id: parentIdOrNull, image_url: (image_url && String(image_url).trim()) ? String(image_url).trim() : null, created_at: new Date().toISOString() };
    categories.push(newCategory);
    writeJson(CATEGORIES_FILE, categories);
    return res.status(201).json(newCategory);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to create category', details: err.message });
  }
});

// Update category
app.put('/admin/categories/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, image_url, remove_image } = req.body || {};

    if (pool) {
      // Build dynamic UPDATE to support explicit image removal
      const updates = [];
      const params = [];
      if (name != null && String(name).trim() !== '') { updates.push('name = ?'); params.push(String(name).trim()); }
      if (remove_image === true) { updates.push('image_url = NULL'); }
      else if (image_url != null) { updates.push('image_url = ?'); params.push(String(image_url).trim()); }
      if (updates.length === 0) return res.status(400).json({ error: 'No fields provided to update' });
      params.push(id);
      const [result] = await pool.query(`UPDATE categories SET ${updates.join(', ')} WHERE id = ?`, params);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Category not found' });
      return res.json({ id: Number(id), name: (name != null ? String(name).trim() : undefined), image_url: (remove_image === true ? null : (image_url != null ? String(image_url).trim() : undefined)) });
    }

    const categories = readJson(CATEGORIES_FILE, []);
    const idx = categories.findIndex(c => Number(c.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'Category not found' });
    if (name != null && String(name).trim() !== '') categories[idx].name = String(name).trim();
    if (remove_image === true) categories[idx].image_url = null;
    else if (image_url != null) categories[idx].image_url = String(image_url).trim();
    writeJson(CATEGORIES_FILE, categories);
    return res.json(categories[idx]);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update category', details: err.message });
  }
});

// Delete category
app.delete('/admin/categories/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    if (pool) {
      const [result] = await pool.query('DELETE FROM categories WHERE id = ?', [id]);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Category not found' });
      return res.json({ id: Number(id), deleted: true });
    }

    const categories = readJson(CATEGORIES_FILE, []);
    const idx = categories.findIndex(c => Number(c.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'Category not found' });
    const removed = categories.splice(idx, 1)[0];
    writeJson(CATEGORIES_FILE, categories);
    return res.json({ id: Number(id), deleted: true, name: removed?.name });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete category', details: err.message });
  }
});

// -------------------------
// Create New Listing
// -------------------------
// Secured with authListingEditor (fixes old authAdmin protection)

app.post('/admin/create-listing', ...authListingEditor, async (req, res) => {
  try {
    const {
      title,
      price,
      categoryId,
      description,
      product_id_number,
      tagIds,
      vehicle,
      relevant,
      options,
      interior,
      safety,
      convenience,
      insuranceHistory,
      photos,
      photoCount,
      language,
      image_url,
      status: statusInBody
    } = req.body || {};
    if (!title || !price) {
      return res.status(400).json({ error: 'Title and price are required' });
    }

    const status = statusInBody ? String(statusInBody).toLowerCase() : 'approved';

    if (pool) {
      const [result] = await pool.query(
        'INSERT INTO listings (title, price, product_id_number, category_id, description, status, seller_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [String(title).trim(), Number(price), product_id_number || null, categoryId || null, description || null, status, null]
      );
      const id = result.insertId;
      // Save tag associations if provided
      if (Array.isArray(tagIds) && tagIds.length) {
        const values = tagIds.map(tid => [id, Number(tid)]).filter(([lid, tid]) => Number.isFinite(tid));
        if (values.length) {
          await pool.query('INSERT IGNORE INTO listing_tags (listing_id, tag_id) VALUES ' + values.map(() => '(?, ?)').join(','), values.flat());
        }
      }
      // DB path only stores core fields; extended metadata is not persisted when DB is active
      return res.status(201).json({ id, title, price: Number(price), product_id_number: product_id_number || null, category_id: categoryId || null, description: description || null, status, tagIds: Array.isArray(tagIds) ? tagIds.map(Number) : [], image_url: image_url || null });
    }

    const listings = readJson(LISTINGS_FILE, []);
    const id = nextId(listings);
    const newListing = {
      id,
      title: String(title).trim(),
      price: Number(price),
      product_id_number: product_id_number || null,
      category_id: categoryId || null,
      description: description || null,
      status,
      created_at: new Date().toISOString(),
      seller_id: null,
      tag_ids: Array.isArray(tagIds) ? tagIds.map(Number) : [],
      vehicle: vehicle && typeof vehicle === 'object' ? vehicle : undefined,
      relevant: Array.isArray(relevant) ? relevant : undefined,
      options: Array.isArray(options) ? options : undefined,
      interior: Array.isArray(interior) ? interior : undefined,
      safety: Array.isArray(safety) ? safety : undefined,
      convenience: Array.isArray(convenience) ? convenience : undefined,
      insuranceHistory: insuranceHistory && typeof insuranceHistory === 'object' ? insuranceHistory : undefined,
      photos: Array.isArray(photos) ? photos : undefined,
      photoCount: Number.isFinite(photoCount) ? photoCount : (Array.isArray(photos) ? photos.length : undefined),
      language: language || undefined,
      image_url: image_url || (Array.isArray(photos) && photos[0] && (photos[0].url || photos[0].dataUrl)) || null
    };
    listings.push(newListing);
    writeJson(LISTINGS_FILE, listings);
    return res.status(201).json(newListing);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to create listing', details: err.message });
  }
});

// -------------------------
// Seller: Submit Listing (pending approval)
// -------------------------
app.post('/submit-listing', authenticateToken, authorizeRoles(['seller']), async (req, res) => {
  try {
    const {
      title,
      price,
      categoryId,
      description,
      product_id_number,
      tagIds,
      vehicle,
      relevant,
      options,
      interior,
      safety,
      convenience,
      insuranceHistory,
      photos,
      photoCount,
      language
    } = req.body || {};
    if (!title || !price) {
      return res.status(400).json({ error: 'Title and price are required' });
    }

    const status = 'pending_approval';

    if (pool) {
      const [result] = await pool.query(
        'INSERT INTO listings (title, price, product_id_number, category_id, description, status, seller_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [String(title).trim(), Number(price), product_id_number || null, categoryId || null, description || null, status, req.user?.id || null]
      );
      const id = result.insertId;
      if (Array.isArray(tagIds) && tagIds.length) {
        const values = tagIds.map(tid => [id, Number(tid)]).filter(([lid, tid]) => Number.isFinite(tid));
        if (values.length) {
          await pool.query('INSERT IGNORE INTO listing_tags (listing_id, tag_id) VALUES ' + values.map(() => '(?, ?)').join(','), values.flat());
        }
      }
      return res.status(201).json({ id, title: String(title).trim(), price: Number(price), product_id_number: product_id_number || null, category_id: categoryId || null, description: description || null, status, tagIds: Array.isArray(tagIds) ? tagIds.map(Number) : [] });
    }

    const listings = readJson(LISTINGS_FILE, []);
    const id = nextId(listings);
    const newListing = {
      id,
      title: String(title).trim(),
      price: Number(price),
      product_id_number: product_id_number || null,
      category_id: categoryId || null,
      description: description || null,
      status,
      created_at: new Date().toISOString(),
      seller_id: req.user?.id || null,
      tag_ids: Array.isArray(tagIds) ? tagIds.map(Number) : [],
      vehicle: vehicle && typeof vehicle === 'object' ? vehicle : undefined,
      relevant: Array.isArray(relevant) ? relevant : undefined,
      options: Array.isArray(options) ? options : undefined,
      interior: Array.isArray(interior) ? interior : undefined,
      safety: Array.isArray(safety) ? safety : undefined,
      convenience: Array.isArray(convenience) ? convenience : undefined,
      insuranceHistory: insuranceHistory && typeof insuranceHistory === 'object' ? insuranceHistory : undefined,
      photos: Array.isArray(photos) ? photos : undefined,
      photoCount: Number.isFinite(photoCount) ? photoCount : (Array.isArray(photos) ? photos.length : undefined),
      language: language || undefined
    };
    listings.push(newListing);
    writeJson(LISTINGS_FILE, listings);
    return res.status(201).json(newListing);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to submit listing', details: err.message });
  }
});

// -------------------------
// Seller: Get My Listings
// -------------------------
app.get('/my-listings', authenticateToken, authorizeRoles(['seller']), async (req, res) => {
  try {
    const sellerId = req.user?.id;
    if (!sellerId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (pool) {
      const [rows] = await pool.query(
        'SELECT id, title, price, product_id_number, category_id, description, status, seller_id, created_at AS createdAt FROM listings WHERE seller_id = ? ORDER BY created_at DESC',
        [sellerId]
      );
      const listings = (Array.isArray(rows) ? rows : []).map(r => ({
        ...r,
        carLabel: r.title || null,
      }));
      return res.json({ listings });
    }

    const all = readJson(LISTINGS_FILE, []);
    const filtered = (Array.isArray(all) ? all : [])
      .filter(l => Number(l.seller_id) === Number(sellerId))
      .map(l => ({
        id: l.id,
        carLabel: l.title || null,
        createdAt: l.created_at,
        status: l.status || 'pending_approval',
        // include common fields for potential future edits
        price: l.price,
        product_id_number: l.product_id_number,
        category_id: l.category_id,
        description: l.description,
        seller_id: l.seller_id,
        tag_ids: Array.isArray(l.tag_ids) ? l.tag_ids : []
      }));
    return res.json({ listings: filtered });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch my listings', details: err.message });
  }
});
// -------------------------
// Seller: Get My Listing Details
// -------------------------
app.get('/my-listings/:id', authenticateToken, authorizeRoles(['seller']), async (req, res) => {
  try {
    const sellerId = req.user?.id;
    const { id } = req.params;
    if (!sellerId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (pool) {
      const [rows] = await pool.query(
        'SELECT id, title, price, product_id_number, category_id, description, status, seller_id, created_at AS createdAt FROM listings WHERE id = ? AND seller_id = ?',
        [id, sellerId]
      );
      if (!rows || rows.length === 0) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const listing = rows[0];
      let tagIds = [];
      try {
        const [tagRows] = await pool.query('SELECT tag_id FROM listing_tags WHERE listing_id = ?', [id]);
        tagIds = (tagRows || []).map(r => Number(r.tag_id)).filter(n => Number.isFinite(n));
      } catch (_) {}
      return res.json({ ...listing, tagIds });
    }

    const all = readJson(LISTINGS_FILE, []);
    const item = (Array.isArray(all) ? all : []).find(l => Number(l.id) === Number(id) && Number(l.seller_id) === Number(sellerId));
    if (!item) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const tagIds = Array.isArray(item.tag_ids) ? item.tag_ids.map(Number) : [];
    return res.json({
      id: item.id,
      title: item.title || null,
      price: Number(item.price ?? 0),
      product_id_number: item.product_id_number || null,
      category_id: item.category_id || null,
      description: item.description || null,
      status: item.status || 'pending_approval',
      seller_id: item.seller_id || null,
      createdAt: item.created_at || null,
      tagIds
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch listing details', details: err.message });
  }
});

// -------------------------
// Admin: Get ALL Listings (for manage-all-listings page)
// -------------------------
app.get('/admin/all-listings', ...authListingEditor, async (req, res) => {
  try {
    // Try DB first; on DB error, fall back to JSON file
    if (pool) {
      try {
        const [rows] = await pool.query(
          `SELECT 
             l.id, l.title, l.price, l.product_id_number, l.category_id, l.description, l.status, l.seller_id, l.created_at,
             u.email AS seller_name
           FROM listings l
           LEFT JOIN users u ON l.seller_id = u.id
           ORDER BY l.created_at DESC`
        );
        return res.json(rows);
      } catch (dbErr) {
        console.warn('DB error on /admin/all-listings, falling back to JSON:', dbErr.message);
      }
    }

    // Fallback: read from listings.json and enrich with seller_name
    const listings = readJson(LISTINGS_FILE, []);
    const users = readJson(USERS_FILE, []);
    const byId = new Map((Array.isArray(users) ? users : []).map(u => [Number(u.id || u.ID || 0), u]));
    const enriched = (Array.isArray(listings) ? listings : []).map(l => {
      const seller = l.seller_id != null ? byId.get(Number(l.seller_id)) : null;
      const seller_name = seller ? (seller.profile?.name || seller.email || null) : null;
      return { ...l, seller_name };
    });
    return res.json(enriched);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch all listings', details: err.message });
  }
});

// New: Admin Manage All Listings with seller join
app.get('/admin/manage-all-listings', ...authListingEditor, async (req, res) => {
  try {
    if (pool) {
      const [rows] = await pool.query(
        `SELECT 
           l.id, l.title, l.price, l.product_id_number, l.category_id, l.description, l.status, l.seller_id, l.created_at,
           u.email AS seller_name
         FROM listings l
         LEFT JOIN users u ON l.seller_id = u.id
         ORDER BY l.created_at DESC`
      );
      return res.json(rows);
    }
    // JSON fallback with seller name enrichment
    const listings = readJson(LISTINGS_FILE, []);
    const users = readJson(USERS_FILE, []);
    const byId = new Map((Array.isArray(users) ? users : []).map(u => [Number(u.id || u.ID || 0), u]));
    const enriched = (Array.isArray(listings) ? listings : []).map(l => {
      const seller = l.seller_id != null ? byId.get(Number(l.seller_id)) : null;
      const seller_name = seller ? (seller.profile?.name || seller.email || null) : null;
      return { ...l, seller_name };
    });
    return res.json(enriched);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch manage-all listings', details: err.message });
  }
});

// -------------------------
// Admin: Listing details & update
// -------------------------
app.get('/admin/listing-details/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    if (pool) {
      const [rows] = await pool.query(
        'SELECT id, title, price, product_id_number, category_id, description, status, seller_id, created_at FROM listings WHERE id = ?',
        [id]
      );
      if (!rows || rows.length === 0) return res.status(404).json({ error: 'Listing not found' });
      const listing = rows[0];
      // get tagIds
      const [tagRows] = await pool.query('SELECT tag_id FROM listing_tags WHERE listing_id = ?', [id]);
      const tagIds = (tagRows || []).map(r => Number(r.tag_id)).filter(n => Number.isFinite(n));
      return res.json({ ...listing, tagIds });
    }
    const listings = readJson(LISTINGS_FILE, []);
    const item = (Array.isArray(listings) ? listings : []).find(l => Number(l.id) === Number(id));
    if (!item) return res.status(404).json({ error: 'Listing not found' });
    const tagIds = Array.isArray(item.tag_ids) ? item.tag_ids.map(Number) : [];
    return res.json({ ...item, tagIds });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch listing details', details: err.message });
  }
});

app.put('/admin/update-listing/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, price, product_id_number, categoryId, description, status, tagIds } = req.body || {};
    if (!title || !price) {
      return res.status(400).json({ error: 'Title and price are required' });
    }

    if (pool) {
      const [result] = await pool.query(
        'UPDATE listings SET title = ?, price = ?, product_id_number = ?, category_id = ?, description = ?, status = ? WHERE id = ?',
        [String(title).trim(), Number(price), product_id_number || null, categoryId || null, description || null, status || 'approved', id]
      );
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Listing not found' });
      // replace tag associations
      await pool.query('DELETE FROM listing_tags WHERE listing_id = ?', [id]);
      if (Array.isArray(tagIds) && tagIds.length) {
        const values = tagIds.map(tid => [Number(id), Number(tid)]).filter(([lid, tid]) => Number.isFinite(tid));
        if (values.length) {
          await pool.query('INSERT IGNORE INTO listing_tags (listing_id, tag_id) VALUES ' + values.map(() => '(?, ?)').join(','), values.flat());
        }
      }
      return res.json({ id: Number(id), title: String(title).trim(), price: Number(price), product_id_number: product_id_number || null, category_id: categoryId || null, description: description || null, status: status || 'approved', tagIds: Array.isArray(tagIds) ? tagIds.map(Number) : [] });
    }

    const listings = readJson(LISTINGS_FILE, []);
    const idx = (Array.isArray(listings) ? listings : []).findIndex(l => Number(l.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'Listing not found' });
    const updated = {
      ...listings[idx],
      title: String(title).trim(),
      price: Number(price),
      product_id_number: product_id_number || null,
      category_id: categoryId || null,
      description: description || null,
      status: status || listings[idx].status || 'approved',
      tag_ids: Array.isArray(tagIds) ? tagIds.map(Number) : (listings[idx].tag_ids || [])
    };
    listings[idx] = updated;
    writeJson(LISTINGS_FILE, listings);
    return res.json(updated);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update listing', details: err.message });
  }
});

// -------------------------
// Staff Management (minimal, for compatibility)
// -------------------------

// Add staff
app.post('/admin/add-staff', ...authListingEditor, async (req, res) => {
  try {
    const { email, password, role } = req.body || {};
    const allowedRoles = ['listing_editor', 'user_manager', 'superadmin', 'seller', 'buyer'];
    if (!email || !password || !role || !allowedRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid input or role' });
    }

    const password_hash = await bcrypt.hash(password, 10);

    if (pool) {
      await pool.query('INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, ?, ?)', [email, password_hash, role, 'approved']);
      return res.status(201).json({ email, role, status: 'approved' });
    }

    const users = readJson(USERS_FILE, []);
    if (users.some(u => u.email === email)) {
      return res.status(409).json({ error: 'User already exists' });
    }
    const id = nextId(users);
    users.push({ id, email, password_hash, role, status: 'approved', created_at: new Date().toISOString() });
    writeJson(USERS_FILE, users);
    return res.status(201).json({ id, email, role, status: 'approved' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to add staff', details: err.message });
  }
});

// Get staff
app.get('/admin/get-staff', ...authListingEditor, async (req, res) => {
  try {
    if (pool) {
      const [rows] = await pool.query('SELECT id, email, role, status, created_at FROM users ORDER BY created_at DESC');
      return res.json(rows);
    }
    const users = readJson(USERS_FILE, []);
    return res.json(users.map(({ password_hash, password, ...u }) => u));
  } catch (err) {
    return res.status(500).json({ error: 'Failed to get staff', details: err.message });
  }
});

// Update staff role
app.put('/admin/update-role/:id', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body || {};
    const allowedRoles = ['listing_editor', 'user_manager', 'superadmin', 'seller', 'buyer'];
    if (!role || !allowedRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    if (pool) {
      const [result] = await pool.query('UPDATE users SET role = ? WHERE id = ?', [role, id]);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
      return res.json({ id: Number(id), role });
    }

    const users = readJson(USERS_FILE, []);
    const idx = users.findIndex(u => Number(u.id) === Number(id));
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    users[idx].role = role;
    writeJson(USERS_FILE, users);
    return res.json({ id: Number(id), role });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update role', details: err.message });
  }
});

// Remove staff (Super Admin only)
app.delete('/admin/remove-staff/:id', ...authSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const targetId = Number(id);
    if (!targetId || Number.isNaN(targetId)) {
      return res.status(400).json({ error: 'Invalid staff id' });
    }

    if (pool) {
      const [result] = await pool.query('DELETE FROM users WHERE id = ?', [targetId]);
      if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
      return res.json({ id: targetId, removed: true });
    }

    const users = readJson(USERS_FILE, []);
    const idx = users.findIndex(u => Number(u.id) === targetId);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    users.splice(idx, 1);
    writeJson(USERS_FILE, users);
    return res.json({ id: targetId, removed: true });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to remove staff', details: err.message });
  }
});

// DELETE /listings/:id - Delete a listing (for sellers to delete their own listings)
app.delete('/listings/:id', authenticateToken, authorizeRoles(['seller']), async (req, res) => {
  try {
    const listingId = req.params.id;
    const userId = req.user.id;

    if (pool) {
      // Database version
      const [rows] = await pool.execute(
        'SELECT * FROM listings WHERE id = ? AND seller_id = ?',
        [listingId, userId]
      );
      
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Listing not found or not owned by user' });
      }

      await pool.execute('DELETE FROM listings WHERE id = ? AND seller_id = ?', [listingId, userId]);
      return res.json({ id: listingId, deleted: true });
    }

    // File-based fallback
    const listings = readJson(LISTINGS_FILE, []);
    const listingIndex = listings.findIndex(l => 
      String(l.id) === String(listingId) && String(l.seller_id) === String(userId)
    );
    
    if (listingIndex === -1) {
      return res.status(404).json({ error: 'Listing not found or not owned by user' });
    }

    listings.splice(listingIndex, 1);
    writeJson(LISTINGS_FILE, listings);
    
    return res.json({ id: listingId, deleted: true });
  } catch (err) {
    console.error('Error deleting listing:', err);
    return res.status(500).json({ error: 'Failed to delete listing', details: err.message });
  }
});

// ---------------------------------
// Orders: Public create (file fallback)
// ---------------------------------
app.post('/orders', async (req, res) => {
  try {
    const {
      listingId,
      country,
      type, // 'personal' or 'business'
      selection = {}
    } = req.body || {};

    if (!listingId || !country || !type) {
      return res.status(400).json({ error: 'listingId, country, and type are required' });
    }

    // Try to attach buyer info from Authorization header if present (optional)
    let buyer = null;
    const authHeader = req.headers['authorization'];
    if (authHeader && typeof authHeader === 'string') {
      const token = authHeader.split(' ')[1];
      if (token) {
        try {
          const payload = jwt.verify(token, JWT_SECRET);
          buyer = { id: payload.id, email: payload.email, role: payload.role };
        } catch (_) { /* ignore token errors for public order creation */ }
      }
    }

    // Persist to file store (fallback-style)
    const orders = readJson(ORDERS_FILE, []);
    const id = nextId(orders);
    const order = {
      id,
      listingId: Number(listingId) || listingId,
      country: String(country),
      type: String(type),
      selection: selection && typeof selection === 'object' ? selection : {},
      buyer_id: buyer?.id ?? null,
      buyer_email: buyer?.email ?? null,
      status: 'pending',
      created_at: new Date().toISOString()
    };
    orders.push(order);
    writeJson(ORDERS_FILE, orders);
    return res.status(201).json(order);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to create order', details: err.message });
  }
});

// ---------------------------------
// Orders: Admin and Buyer fetch
// ---------------------------------
app.get('/admin/orders', ...authListingEditor, async (req, res) => {
  try {
    // Prefer DB if available (not implemented yet); fall back to JSON
    const orders = readJson(ORDERS_FILE, []);
    return res.json(Array.isArray(orders) ? orders : []);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch orders', details: err.message });
  }
});

app.get('/buyer/orders', authenticateToken, authorizeRoles(['buyer']), async (req, res) => {
  try {
    const me = req.user || {};
    const orders = readJson(ORDERS_FILE, []);
    const listings = readJson(LISTINGS_FILE, []);

    const myEmail = me.email ? String(me.email).toLowerCase() : null;
    const mine = (Array.isArray(orders) ? orders : []).filter(o => {
      const byId = me.id != null && String(o.buyer_id) === String(me.id);
      const byEmail = myEmail && o.buyer_email && String(o.buyer_email).toLowerCase() === myEmail;
      const bySelectionEmail = myEmail && (
        (o.selection && o.selection.payer && o.selection.payer.email && String(o.selection.payer.email).toLowerCase() === myEmail) ||
        (o.selection && o.selection.consignee && o.selection.consignee.email && String(o.selection.consignee.email).toLowerCase() === myEmail)
      );
      return byId || byEmail || bySelectionEmail;
    });

    // Join listing details for invoice display convenience
    const listingMap = new Map((Array.isArray(listings) ? listings : []).map(l => [String(l.id), l]));
    const enriched = mine.map(o => {
      const l = listingMap.get(String(o.listingId));
      const listing = l ? {
        id: l.id,
        title: l.title || null,
        price: (typeof l.price !== 'undefined' ? l.price : null),
        product_id_number: l.product_id_number || null,
        status: l.status || null,
      } : null;
      return { ...o, listing };
    });

    return res.json(enriched);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch my orders', details: err.message });
  }
});

// ---------------------------------
// Orders: Admin update status
// ---------------------------------
app.patch('/admin/orders/:id/status', ...authListingEditor, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body || {};
    if (!status) return res.status(400).json({ error: 'status is required' });

    // Normalize requested status to our storage values
    const s = String(status).toLowerCase().trim();
    const normalized = (s === 'requested') ? 'pending' : (s === 'progress' ? 'in_progress' : s);

    // DB path could go here; for now use JSON fallback
    const orders = readJson(ORDERS_FILE, []);
    const idStr = String(id).trim();
    const idx = (Array.isArray(orders) ? orders : []).findIndex(o => {
      const oid = String(o.id);
      const lid = o.listingId != null ? String(o.listingId) : '';
      return oid === idStr || lid === idStr;
    });
    if (idx === -1) return res.status(404).json({ error: 'Order not found' });
    orders[idx].status = normalized;
    orders[idx].updated_at = new Date().toISOString();
    // On completion, attach invoice URL and trigger email
    if (normalized === 'completed') {
      const invoiceUrl = buildInvoiceUrl(orders[idx].id);
      orders[idx].invoice_url = invoiceUrl;
      orders[idx].invoice_at = new Date().toISOString();
      // fire-and-forget email
      sendInvoiceEmail(orders[idx]).then((r) => {
        if (r?.error) console.warn('Invoice email error for order', orders[idx].id, r.error);
      }).catch((e) => console.warn('Invoice email send exception:', e.message));
    }
    writeJson(ORDERS_FILE, orders);
    return res.json(orders[idx]);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update order status', details: err.message });
  }
});

// ---------------------------------
// Reviews: Buyer submit, Admin moderate, Public fetch approved
// ---------------------------------

// Buyer: Submit a product review
app.post('/buyer/reviews', authenticateToken, authorizeRoles(['buyer']), async (req, res) => {
  try {
    const { listingId, orderId, rating, title, description, country, image_url } = req.body || {};
    const r = Number(rating);
    const hasListing = listingId != null && String(listingId).trim() !== '';
    if (!hasListing || !r || r < 1 || r > 5 || !title || !description || !country) {
      return res.status(400).json({ error: 'listingId, rating(1-5), title, description, country are required' });
    }
    const reviews = readJson(REVIEWS_FILE, []);
    const id = nextId(Array.isArray(reviews) ? reviews : []);
    const buyer = req.user || {};
    const review = {
      id,
      listingId: Number(listingId) || listingId,
      orderId: orderId ?? null,
      rating: r,
      title: String(title).trim(),
      description: String(description).trim(),
      country: String(country).trim(),
      image_url: image_url || null,
      status: 'pending',
      buyer_id: buyer.id ?? null,
      buyer_email: buyer.email ?? null,
      created_at: new Date().toISOString()
    };
    const next = Array.isArray(reviews) ? reviews : [];
    next.push(review);
    writeJson(REVIEWS_FILE, next);
    return res.status(201).json(review);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to submit review', details: err.message });
  }
});

// Admin: Fetch reviews (optional ?status=pending|approved|rejected)
app.get('/admin/reviews', ...authListingEditor, async (req, res) => {
  try {
    const status = String(req.query.status || '').trim().toLowerCase();
    const reviews = readJson(REVIEWS_FILE, []);
    let list = Array.isArray(reviews) ? reviews.slice().sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)) : [];
    if (status) list = list.filter(r => String(r.status || '').toLowerCase() === status);
    return res.json(list);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch reviews', details: err.message });
  }
});

// Admin: Update review status
app.patch('/admin/reviews/:id/status', ...authListingEditor, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body || {};
    const s = String(status || '').trim().toLowerCase();
    if (!['approved', 'rejected', 'pending'].includes(s)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    const reviews = readJson(REVIEWS_FILE, []);
    const idx = (Array.isArray(reviews) ? reviews : []).findIndex(r => Number(r.id) === id);
    if (idx === -1) return res.status(404).json({ error: 'Review not found' });
    reviews[idx].status = s;
    reviews[idx].moderated_at = new Date().toISOString();
    reviews[idx].moderated_by = (req.user && req.user.id) ? req.user.id : null;
    writeJson(REVIEWS_FILE, reviews);
    return res.json(reviews[idx]);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update review status', details: err.message });
  }
});

// Public: Approved reviews for a listing
app.get('/public/listings/:id/reviews', async (req, res) => {
  try {
    const listingId = req.params.id;
    const reviews = readJson(REVIEWS_FILE, []);
    const approved = (Array.isArray(reviews) ? reviews : [])
      .filter(r => String(r.listingId) === String(listingId) && String(r.status || '').toLowerCase() === 'approved')
      .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
    return res.json({ reviews: approved });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch listing reviews', details: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Signup backend listening on http://localhost:${PORT}`);
});