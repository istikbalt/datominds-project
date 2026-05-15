require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "frontend")));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: { rejectUnauthorized: false }
});

function generateToken() { return crypto.randomBytes(48).toString("hex"); }

async function getSession(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return null;
  const token = auth.slice(7);
  try {
    const [rows] = await pool.execute(
      "SELECT * FROM sessions WHERE token = ? AND expires_at > NOW() LIMIT 1", [token]
    );
    return rows[0] || null;
  } catch { return null; }
}

async function requireAuth(req, res) {
  const session = await getSession(req);
  if (!session) { res.status(401).json({ success: false, error: "Login required." }); return null; }
  return session;
}

// HEALTH
app.get("/api/health", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 AS ok");
    res.json({ success: true, db: rows[0].ok === 1 });
  } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// CATEGORIES
app.get("/api/categories", async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, name, slug FROM categories WHERE status = 'active' ORDER BY sort_order ASC, name ASC"
    );
    res.json({ success: true, categories: rows });
  } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  const { first_name, last_name, email, password, phone } = req.body;
  if (!first_name || !last_name || !email || !password) {
    return res.status(400).json({ success: false, error: "Required fields missing." });
  }
  try {
    const [existing] = await pool.execute("SELECT id FROM users WHERE email = ? LIMIT 1", [email]);
    if (existing.length > 0) return res.status(400).json({ success: false, error: "Email already registered." });
    const [result] = await pool.execute(
      "INSERT INTO users (first_name, last_name, email, password_hash, phone, role, status) VALUES (?, ?, ?, ?, ?, 'individual', 'active')",
      [first_name, last_name, email, password, phone || null]
    );
    const token = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await pool.execute("INSERT INTO sessions (token, user_type, user_id, expires_at) VALUES (?, 'individual', ?, ?)", [token, result.insertId, expires]);
    return res.json({ success: true, token, user: { id: result.insertId, first_name, last_name, email, role: "individual" } });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, error: "Email and password required." });
  try {
    const [users] = await pool.execute("SELECT * FROM users WHERE email = ? AND password_hash = ? LIMIT 1", [email, password]);
    if (users.length === 0) return res.status(401).json({ success: false, error: "Invalid email or password." });
    const user = users[0];
    let business = null;
    if (user.role === "business_owner") {
      const [businesses] = await pool.execute("SELECT id, business_name, slug FROM businesses WHERE owner_user_id = ? LIMIT 1", [user.id]);
      business = businesses[0] || null;
    }
    const token = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await pool.execute(
      "INSERT INTO sessions (token, user_type, user_id, business_id, expires_at) VALUES (?, ?, ?, ?, ?)",
      [token, user.role === "business_owner" ? "business" : "individual", user.id, business ? business.id : null, expires]
    );
    return res.json({ success: true, token, user: { id: user.id, first_name: user.first_name, last_name: user.last_name, email: user.email, role: user.role, avatar_url: user.avatar_url || null }, business });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// LOGOUT
app.post("/api/auth/logout", async (req, res) => {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith("Bearer ")) {
    try { await pool.execute("DELETE FROM sessions WHERE token = ?", [auth.slice(7)]); } catch {}
  }
  res.json({ success: true });
});

// ME
app.get("/api/auth/me", async (req, res) => {
  const session = await getSession(req);
  if (!session) return res.status(401).json({ success: false, error: "Not logged in." });
  try {
    const [users] = await pool.execute("SELECT id, first_name, last_name, email, role, avatar_url, bio FROM users WHERE id = ?", [session.user_id]);
    if (!users.length) return res.status(404).json({ success: false, error: "User not found." });
    let business = null;
    if (session.business_id) {
      const [businesses] = await pool.execute("SELECT id, business_name, slug FROM businesses WHERE id = ?", [session.business_id]);
      business = businesses[0] || null;
    }
    return res.json({ success: true, user: users[0], business });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// BUSINESS REGISTER
app.post("/api/business/register", async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { owner_first_name, owner_last_name, owner_email, owner_password, owner_phone, business_name, slug, business_type, category_id, short_description, country, city, business_email, business_phone } = req.body;
    if (!owner_first_name || !owner_last_name || !owner_email || !owner_password || !business_name || !slug || !business_type || !category_id || !short_description || !country || !city) {
      return res.status(400).json({ success: false, error: "Required fields are missing." });
    }
    await connection.beginTransaction();
    const [existingUser] = await connection.execute("SELECT id FROM users WHERE email = ? LIMIT 1", [owner_email]);
    if (existingUser.length > 0) { await connection.rollback(); return res.status(400).json({ success: false, error: "This email is already registered." }); }
    const [existingSlug] = await connection.execute("SELECT id FROM businesses WHERE slug = ? LIMIT 1", [slug]);
    if (existingSlug.length > 0) { await connection.rollback(); return res.status(400).json({ success: false, error: "This business slug already exists." }); }
    const [userResult] = await connection.execute(
      "INSERT INTO users (first_name, last_name, email, password_hash, phone, role, status) VALUES (?, ?, ?, ?, ?, 'business_owner', 'active')",
      [owner_first_name, owner_last_name, owner_email, owner_password, owner_phone || null]
    );
    const ownerUserId = userResult.insertId;
    const [businessResult] = await connection.execute(
      "INSERT INTO businesses (owner_user_id, business_name, slug, business_type, category_id, short_description, business_email, business_phone, country, city, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published')",
      [ownerUserId, business_name, slug, business_type, Number(category_id), short_description, business_email || null, business_phone || null, country, city]
    );
    const token = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await connection.execute("INSERT INTO sessions (token, user_type, user_id, business_id, expires_at) VALUES (?, 'business', ?, ?, ?)", [token, ownerUserId, businessResult.insertId, expires]);
    await connection.commit();
    return res.json({ success: true, message: "Business page created successfully.", token, user_id: ownerUserId, business_id: businessResult.insertId, slug });
  } catch (error) { await connection.rollback(); return res.status(500).json({ success: false, error: error.message }); }
  finally { connection.release(); }
});

// BUSINESS GET
app.get("/api/business/:slug", async (req, res) => {
  try {
    const { slug } = req.params;
    const session = await getSession(req);
    const [rows] = await pool.execute(
      `SELECT b.id, b.business_name, b.slug, b.business_type, b.short_description, b.business_email, b.business_phone, b.country, b.city, b.logo_url, b.cover_url, b.website, b.created_at, c.name AS category_name,
       (SELECT COUNT(*) FROM follows WHERE following_business_id = b.id) AS follower_count
       FROM businesses b LEFT JOIN categories c ON b.category_id = c.id WHERE b.slug = ? LIMIT 1`, [slug]
    );
    if (!rows.length) return res.status(404).json({ success: false, error: "Business not found." });
    const business = rows[0];
    let is_following = false;
    if (session) {
      if (session.user_type === "individual") {
        const [f] = await pool.execute("SELECT id FROM follows WHERE follower_user_id = ? AND following_business_id = ? LIMIT 1", [session.user_id, business.id]);
        is_following = f.length > 0;
      } else if (session.user_type === "business" && session.business_id) {
        const [f] = await pool.execute("SELECT id FROM follows WHERE follower_business_id = ? AND following_business_id = ? LIMIT 1", [session.business_id, business.id]);
        is_following = f.length > 0;
      }
    }
    return res.json({ success: true, business: { ...business, is_following } });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// FOLLOW
app.post("/api/business/:slug/follow", async (req, res) => {
  const session = await requireAuth(req, res);
  if (!session) return;
  try {
    const [businesses] = await pool.execute("SELECT id FROM businesses WHERE slug = ? LIMIT 1", [req.params.slug]);
    if (!businesses.length) return res.status(404).json({ success: false, error: "Business not found." });
    const businessId = businesses[0].id;
    if (session.user_type === "individual") {
      const [existing] = await pool.execute("SELECT id FROM follows WHERE follower_user_id = ? AND following_business_id = ? LIMIT 1", [session.user_id, businessId]);
      if (existing.length > 0) { await pool.execute("DELETE FROM follows WHERE id = ?", [existing[0].id]); return res.json({ success: true, following: false }); }
      await pool.execute("INSERT INTO follows (follower_type, follower_user_id, following_business_id) VALUES ('individual', ?, ?)", [session.user_id, businessId]);
      return res.json({ success: true, following: true });
    } else {
      if (session.business_id === businessId) return res.status(400).json({ success: false, error: "Cannot follow yourself." });
      const [existing] = await pool.execute("SELECT id FROM follows WHERE follower_business_id = ? AND following_business_id = ? LIMIT 1", [session.business_id, businessId]);
      if (existing.length > 0) { await pool.execute("DELETE FROM follows WHERE id = ?", [existing[0].id]); return res.json({ success: true, following: false }); }
      await pool.execute("INSERT INTO follows (follower_type, follower_business_id, following_business_id) VALUES ('business', ?, ?)", [session.business_id, businessId]);
      return res.json({ success: true, following: true });
    }
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// CREATE POST
app.post("/api/posts", async (req, res) => {
  const session = await requireAuth(req, res);
  if (!session) return;
  if (session.user_type !== "business") return res.status(403).json({ success: false, error: "Only businesses can create posts." });
  const { content, image_url, tagged_businesses } = req.body;
  if (!content || content.trim().length === 0) return res.status(400).json({ success: false, error: "Content is required." });
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [result] = await connection.execute(
      "INSERT INTO posts (author_type, author_business_id, post_type, content, image_url) VALUES ('business', ?, 'post', ?, ?)",
      [session.business_id, content.trim(), image_url || null]
    );
    const postId = result.insertId;
    if (tagged_businesses && Array.isArray(tagged_businesses)) {
      for (const bSlug of tagged_businesses) {
        const [bRows] = await connection.execute("SELECT id FROM businesses WHERE slug = ? LIMIT 1", [bSlug]);
        if (bRows.length > 0) {
          await connection.execute("INSERT IGNORE INTO post_tags (post_id, business_id) VALUES (?, ?)", [postId, bRows[0].id]);
        }
      }
    }
    await connection.commit();
    const [posts] = await pool.execute("SELECT p.*, b.business_name, b.slug AS business_slug FROM posts p JOIN businesses b ON p.author_business_id = b.id WHERE p.id = ?", [postId]);
    return res.json({ success: true, post: posts[0] });
  } catch (error) { await connection.rollback(); return res.status(500).json({ success: false, error: error.message }); }
  finally { connection.release(); }
});

// SHARE POST
app.post("/api/posts/:id/share", async (req, res) => {
  const session = await requireAuth(req, res);
  if (!session) return;
  const { content } = req.body;
  const postId = Number(req.params.id);
  try {
    const [original] = await pool.execute("SELECT id, author_business_id FROM posts WHERE id = ? AND status = 'published' LIMIT 1", [postId]);
    if (!original.length) return res.status(404).json({ success: false, error: "Post not found." });
    const authorType = session.user_type === "individual" ? "individual" : "business";
    const bizId = session.user_type === "business" ? session.business_id : null;
    const userId = session.user_type === "individual" ? session.user_id : null;
    const [result] = await pool.execute(
      "INSERT INTO posts (author_type, author_business_id, author_user_id, post_type, shared_post_id, content) VALUES (?, ?, ?, 'share', ?, ?)",
      [authorType, bizId, userId, postId, content || ""]
    );
    return res.json({ success: true, share_id: result.insertId });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// FEED - basit versiyon, LIMIT değerleri integer olarak gömülü
app.get("/api/feed", async (req, res) => {
  try {
    const session = await getSession(req);
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 20;
    const offset = (page - 1) * limit;

    let posts;

    if (session && session.user_type === "individual") {
      const uid = session.user_id;
      [posts] = await pool.query(
        `SELECT p.id, p.author_type, p.post_type, p.content, p.image_url, p.shared_post_id, p.created_at,
         b.id AS business_id, b.business_name, b.slug AS business_slug,
         u.id AS user_id, u.first_name, u.last_name, u.avatar_url,
         (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS like_count,
         (SELECT COUNT(*) FROM comments WHERE post_id = p.id AND status = 'visible') AS comment_count,
         (SELECT COUNT(*) FROM posts p2 WHERE p2.shared_post_id = p.id AND p2.post_type = 'share') AS share_count,
         (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND liker_user_id = ${uid}) AS is_liked
         FROM posts p
         LEFT JOIN businesses b ON p.author_business_id = b.id
         LEFT JOIN users u ON p.author_user_id = u.id
         WHERE p.status = 'published'
         ORDER BY p.created_at DESC
         LIMIT ${limit} OFFSET ${offset}`
      );
    } else if (session && session.user_type === "business" && session.business_id) {
      const bid = session.business_id;
      [posts] = await pool.query(
        `SELECT p.id, p.author_type, p.post_type, p.content, p.image_url, p.shared_post_id, p.created_at,
         b.id AS business_id, b.business_name, b.slug AS business_slug,
         u.id AS user_id, u.first_name, u.last_name, u.avatar_url,
         (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS like_count,
         (SELECT COUNT(*) FROM comments WHERE post_id = p.id AND status = 'visible') AS comment_count,
         (SELECT COUNT(*) FROM posts p2 WHERE p2.shared_post_id = p.id AND p2.post_type = 'share') AS share_count,
         (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND liker_business_id = ${bid}) AS is_liked
         FROM posts p
         LEFT JOIN businesses b ON p.author_business_id = b.id
         LEFT JOIN users u ON p.author_user_id = u.id
         WHERE p.status = 'published'
         ORDER BY p.created_at DESC
         LIMIT ${limit} OFFSET ${offset}`
      );
    } else {
      [posts] = await pool.query(
        `SELECT p.id, p.author_type, p.post_type, p.content, p.image_url, p.shared_post_id, p.created_at,
         b.id AS business_id, b.business_name, b.slug AS business_slug,
         u.id AS user_id, u.first_name, u.last_name, u.avatar_url,
         (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS like_count,
         (SELECT COUNT(*) FROM comments WHERE post_id = p.id AND status = 'visible') AS comment_count,
         (SELECT COUNT(*) FROM posts p2 WHERE p2.shared_post_id = p.id AND p2.post_type = 'share') AS share_count,
         0 AS is_liked
         FROM posts p
         LEFT JOIN businesses b ON p.author_business_id = b.id
         LEFT JOIN users u ON p.author_user_id = u.id
         WHERE p.status = 'published'
         ORDER BY p.created_at DESC
         LIMIT ${limit} OFFSET ${offset}`
      );
    }

    // Shared post'ların orijinallerini getir
    const sharedIds = posts.filter(p => p.shared_post_id).map(p => p.shared_post_id);
    let sharedPosts = {};
    if (sharedIds.length > 0) {
      const placeholders = sharedIds.map(() => "?").join(",");
      const [originals] = await pool.execute(
        `SELECT p.id, p.content, p.image_url, p.created_at, b.business_name, b.slug AS business_slug FROM posts p LEFT JOIN businesses b ON p.author_business_id = b.id WHERE p.id IN (${placeholders})`,
        sharedIds
      );
      originals.forEach(o => { sharedPosts[o.id] = o; });
    }

    const enriched = posts.map(p => ({
      ...p,
      is_liked: Number(p.is_liked) > 0,
      original_post: p.shared_post_id ? sharedPosts[p.shared_post_id] || null : null
    }));

    return res.json({ success: true, posts: enriched, page, has_more: posts.length === limit });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// BUSINESS POSTS
app.get("/api/business/:slug/posts", async (req, res) => {
  try {
    const { slug } = req.params;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 20;
    const offset = (page - 1) * limit;
    const [businesses] = await pool.execute("SELECT id FROM businesses WHERE slug = ? LIMIT 1", [slug]);
    if (!businesses.length) return res.status(404).json({ success: false, error: "Business not found." });
    const businessId = businesses[0].id;
    const session = await getSession(req);

    let isLikedExpr = "0";
    if (session && session.user_type === "individual") isLikedExpr = `(SELECT COUNT(*) FROM likes WHERE post_id = p.id AND liker_user_id = ${session.user_id})`;
    else if (session && session.user_type === "business" && session.business_id) isLikedExpr = `(SELECT COUNT(*) FROM likes WHERE post_id = p.id AND liker_business_id = ${session.business_id})`;

    const [posts] = await pool.query(
      `SELECT p.id, p.author_type, p.post_type, p.content, p.image_url, p.shared_post_id, p.created_at,
       b.business_name, b.slug AS business_slug,
       (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS like_count,
       (SELECT COUNT(*) FROM comments WHERE post_id = p.id AND status = 'visible') AS comment_count,
       (SELECT COUNT(*) FROM posts p2 WHERE p2.shared_post_id = p.id) AS share_count,
       ${isLikedExpr} AS is_liked
       FROM posts p LEFT JOIN businesses b ON p.author_business_id = b.id
       WHERE p.author_business_id = ${businessId} AND p.post_type = 'post' AND p.status = 'published'
       ORDER BY p.created_at DESC LIMIT ${limit} OFFSET ${offset}`
    );

    const [taggedPosts] = await pool.execute(
      `SELECT p.id, p.content, p.created_at, b.business_name, b.slug AS business_slug FROM post_tags pt JOIN posts p ON pt.post_id = p.id JOIN businesses b ON p.author_business_id = b.id WHERE pt.business_id = ? AND p.status = 'published' ORDER BY p.created_at DESC LIMIT 10`,
      [businessId]
    );

    return res.json({ success: true, posts: posts.map(p => ({ ...p, is_liked: Number(p.is_liked) > 0 })), tagged_posts: taggedPosts, page, has_more: posts.length === limit });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// LIKE
app.post("/api/posts/:id/like", async (req, res) => {
  const session = await requireAuth(req, res);
  if (!session) return;
  const postId = Number(req.params.id);
  try {
    const [posts] = await pool.execute("SELECT id FROM posts WHERE id = ? LIMIT 1", [postId]);
    if (!posts.length) return res.status(404).json({ success: false, error: "Post not found." });
    let existing;
    if (session.user_type === "individual") {
      [existing] = await pool.execute("SELECT id FROM likes WHERE post_id = ? AND liker_user_id = ? LIMIT 1", [postId, session.user_id]);
    } else {
      [existing] = await pool.execute("SELECT id FROM likes WHERE post_id = ? AND liker_business_id = ? LIMIT 1", [postId, session.business_id]);
    }
    if (existing.length > 0) {
      await pool.execute("DELETE FROM likes WHERE id = ?", [existing[0].id]);
      const [[{ cnt }]] = await pool.execute("SELECT COUNT(*) AS cnt FROM likes WHERE post_id = ?", [postId]);
      return res.json({ success: true, liked: false, like_count: Number(cnt) });
    } else {
      if (session.user_type === "individual") {
        await pool.execute("INSERT INTO likes (post_id, liker_type, liker_user_id) VALUES (?, 'individual', ?)", [postId, session.user_id]);
      } else {
        await pool.execute("INSERT INTO likes (post_id, liker_type, liker_business_id) VALUES (?, 'business', ?)", [postId, session.business_id]);
      }
      const [[{ cnt }]] = await pool.execute("SELECT COUNT(*) AS cnt FROM likes WHERE post_id = ?", [postId]);
      return res.json({ success: true, liked: true, like_count: Number(cnt) });
    }
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// COMMENTS LIST
app.get("/api/posts/:id/comments", async (req, res) => {
  try {
    const postId = Number(req.params.id);
    const [comments] = await pool.execute(
      `SELECT c.id, c.commenter_type, c.content, c.created_at, b.business_name, b.slug AS business_slug, u.first_name, u.last_name, u.avatar_url, u.id AS commenter_user_id
       FROM comments c LEFT JOIN businesses b ON c.commenter_business_id = b.id LEFT JOIN users u ON c.commenter_user_id = u.id
       WHERE c.post_id = ? AND c.status = 'visible' ORDER BY c.created_at ASC`, [postId]
    );
    return res.json({ success: true, comments });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// COMMENTS CREATE
app.post("/api/posts/:id/comments", async (req, res) => {
  const session = await requireAuth(req, res);
  if (!session) return;
  const postId = Number(req.params.id);
  const { content } = req.body;
  if (!content || content.trim().length === 0) return res.status(400).json({ success: false, error: "Comment cannot be empty." });
  try {
    let result;
    if (session.user_type === "individual") {
      [result] = await pool.execute("INSERT INTO comments (post_id, commenter_type, commenter_user_id, content) VALUES (?, 'individual', ?, ?)", [postId, session.user_id, content.trim()]);
    } else {
      [result] = await pool.execute("INSERT INTO comments (post_id, commenter_type, commenter_business_id, content) VALUES (?, 'business', ?, ?)", [postId, session.business_id, content.trim()]);
    }
    const [comments] = await pool.execute(
      `SELECT c.id, c.commenter_type, c.content, c.created_at, b.business_name, b.slug AS business_slug, u.first_name, u.last_name, u.avatar_url, u.id AS commenter_user_id
       FROM comments c LEFT JOIN businesses b ON c.commenter_business_id = b.id LEFT JOIN users u ON c.commenter_user_id = u.id WHERE c.id = ?`, [result.insertId]
    );
    return res.json({ success: true, comment: comments[0] });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// NOTIFICATIONS
app.get("/api/notifications", async (req, res) => {
  const session = await requireAuth(req, res);
  if (!session) return;
  try {
    let where, params;
    if (session.user_type === "individual") { where = "recipient_user_id = ?"; params = [session.user_id]; }
    else { where = "recipient_business_id = ?"; params = [session.business_id]; }
    const [notifications] = await pool.execute(
      `SELECT n.*, ab.business_name AS actor_business_name, ab.slug AS actor_business_slug, au.first_name AS actor_first_name, au.last_name AS actor_last_name
       FROM notifications n LEFT JOIN businesses ab ON n.actor_business_id = ab.id LEFT JOIN users au ON n.actor_user_id = au.id
       WHERE ${where} ORDER BY n.created_at DESC LIMIT 30`, params
    );
    await pool.execute(`UPDATE notifications SET is_read = 1 WHERE ${where}`, params);
    const [[{ unread }]] = await pool.execute(`SELECT COUNT(*) AS unread FROM notifications WHERE ${where} AND is_read = 0`, params);
    return res.json({ success: true, notifications, unread_count: Number(unread) });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// USER PROFILE
app.get("/api/profile/:userId", async (req, res) => {
  try {
    const userId = Number(req.params.userId);
    const [users] = await pool.execute("SELECT id, first_name, last_name, avatar_url, bio, role, created_at FROM users WHERE id = ? LIMIT 1", [userId]);
    if (!users.length) return res.status(404).json({ success: false, error: "User not found." });
    const [shares] = await pool.execute(
      `SELECT p.id, p.content, p.created_at, p.shared_post_id, op.content AS original_content, ob.business_name AS original_business_name, ob.slug AS original_business_slug
       FROM posts p LEFT JOIN posts op ON p.shared_post_id = op.id LEFT JOIN businesses ob ON op.author_business_id = ob.id
       WHERE p.author_user_id = ? AND p.post_type = 'share' AND p.status = 'published' ORDER BY p.created_at DESC LIMIT 20`, [userId]
    );
    const [comments] = await pool.execute(
      `SELECT c.id, c.content, c.created_at, b.business_name, b.slug AS business_slug
       FROM comments c JOIN posts p ON c.post_id = p.id JOIN businesses b ON p.author_business_id = b.id
       WHERE c.commenter_user_id = ? AND c.status = 'visible' ORDER BY c.created_at DESC LIMIT 20`, [userId]
    );
    const [following] = await pool.execute(
      `SELECT b.id, b.business_name, b.slug, c.name AS category_name FROM follows f JOIN businesses b ON f.following_business_id = b.id LEFT JOIN categories c ON b.category_id = c.id WHERE f.follower_user_id = ? ORDER BY f.created_at DESC`, [userId]
    );
    return res.json({ success: true, user: users[0], shares, comments, following });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

// SEARCH
app.get("/api/search", async (req, res) => {
  try {
    const q = (req.query.q || "").trim();
    const category = req.query.category || "";
    const city = req.query.city || "";
    let query = `SELECT b.id, b.business_name, b.slug, b.business_type, b.short_description, b.city, b.country, c.name AS category_name,
      (SELECT COUNT(*) FROM follows WHERE following_business_id = b.id) AS follower_count
      FROM businesses b LEFT JOIN categories c ON b.category_id = c.id WHERE b.status = 'published'`;
    const params = [];
    if (q && q.length >= 2) { query += " AND (b.business_name LIKE ? OR b.short_description LIKE ?)"; params.push(`%${q}%`, `%${q}%`); }
    if (category) { query += " AND c.slug = ?"; params.push(category); }
    if (city) { query += " AND b.city LIKE ?"; params.push(`%${city}%`); }
    query += " ORDER BY follower_count DESC LIMIT 30";
    const [businesses] = await pool.execute(query, params);
    return res.json({ success: true, businesses });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});

app.get("/", (req, res) => { res.send("Datominds backend is running."); });
app.listen(PORT, () => { console.log(`Server is running on port ${PORT}`); });

// UPDATE BUSINESS PROFILE
app.put("/api/business/:slug", async (req, res) => {
  const session = await requireAuth(req, res);
  if (!session) return;
  if (session.user_type !== "business") return res.status(403).json({ success: false, error: "Only business accounts can edit profiles." });

  const { slug } = req.params;
  const { business_name, short_description, business_email, business_phone, city, country, logo_url, cover_url, website } = req.body;

  try {
    const [businesses] = await pool.execute("SELECT id, owner_user_id FROM businesses WHERE slug = ? LIMIT 1", [slug]);
    if (!businesses.length) return res.status(404).json({ success: false, error: "Business not found." });
    const biz = businesses[0];
    if (biz.owner_user_id !== session.user_id) return res.status(403).json({ success: false, error: "Not authorized." });

    const updates = [];
    const params = [];
    if (business_name) { updates.push("business_name = ?"); params.push(business_name); }
    if (short_description !== undefined) { updates.push("short_description = ?"); params.push(short_description); }
    if (business_email !== undefined) { updates.push("business_email = ?"); params.push(business_email || null); }
    if (business_phone !== undefined) { updates.push("business_phone = ?"); params.push(business_phone || null); }
    if (city !== undefined) { updates.push("city = ?"); params.push(city); }
    if (country !== undefined) { updates.push("country = ?"); params.push(country); }
    if (logo_url !== undefined) { updates.push("logo_url = ?"); params.push(logo_url || null); }
    if (cover_url !== undefined) { updates.push("cover_url = ?"); params.push(cover_url || null); }
    if (website !== undefined) { updates.push("website = ?"); params.push(website || null); }
    if (updates.length === 0) return res.status(400).json({ success: false, error: "Nothing to update." });

    params.push(biz.id);
    await pool.execute(`UPDATE businesses SET ${updates.join(", ")} WHERE id = ?`, params);
    const [updated] = await pool.execute(
      "SELECT b.*, c.name AS category_name FROM businesses b LEFT JOIN categories c ON b.category_id = c.id WHERE b.id = ?", [biz.id]
    );
    return res.json({ success: true, business: updated[0] });
  } catch (error) { return res.status(500).json({ success: false, error: error.message }); }
});