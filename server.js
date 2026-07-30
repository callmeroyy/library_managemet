const express = require("express");
const bodyParser = require("body-parser");
const DB = require("./koneksiDB.js");
const dayjs = require("dayjs");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const app = express();
const port = 3000;

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
require("dotenv").config();
app.use(cookieParser());

// Expose req.path to all EJS views
app.use((req, res, next) => {
  res.locals.path = req.path;
  next();
});

const jwtSecret = process.env.JWT_SECRET;

app.get("/", optionalAuth, (req, res) => {
  try {
    DB.query(`
      SELECT books.*, categories.name AS category_name
      FROM books
      LEFT JOIN categories ON books.category_id = categories.id
      ORDER BY books.id DESC LIMIT 8
    `, (err, featuredBooks) => {
      if (err) throw err;
      res.render("user_layout", {
        content: "public/beranda",
        featuredBooks
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

app.get("/beranda", (req, res) => {
  res.redirect("/");
});

// ==================== LOGIN ROUTES ====================
// LOGIN
app.get("/login", (req, res) => {
  try {
    res.render("auth/login", {
      pesan: null,
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

app.post("/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.render("auth/login", {
        pesan: "Jangan Biarkan kolom inputan kosong!",
      });
    }
    DB.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "DB error" });
      }
      if (result.length > 0) {
        if (result[0].is_active !== 1) {
          return res.render("auth/login", {
            pesan: "Akun anda dinonaktifkan!",
          });
        }
        const cocok = bcrypt.compareSync(password, result[0].password) || (password === result[0].password);
        if (!cocok) {
          return res.render("auth/login", {
            pesan: "Password salah!",
          });
        }

        const token = jwt.sign({ id: result[0].id, role: result[0].role, email: result[0].email }, process.env.JWT_SECRET);
        res.cookie("authToken", token, {
          httpOnly: true,
          secure: false,
          maxAge: 24 * 60 * 60 * 1000,
        });
        
        if (result[0].role === 'admin') {
          return res.redirect("/dashboard");
        } else {
          return res.redirect("/katalog");
        }
      } else {
        return res.render("auth/login", {
          pesan: "Akun tidak terdaftar!",
        });
      }
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== MIDLEWARE AUTH ====================
function authMiddleware(req, res, next) {
  const authToken = req.cookies.authToken;
  if (!authToken) return res.redirect("/login");

  jwt.verify(authToken, jwtSecret, (err, result) => {
    if (err) return res.redirect("/login");
    req.user = result;
    res.locals.user = result;
    next();
  });
}

// ==================== MIDLEWARE AUTH ADMIN ====================
function adminAuth(req, res, next) {
  if (req.user.role != "admin") {
    return res.status(403).send("Admin only");
  }
  next();
}

// ==================== MIDLEWARE AUTH USER ====================
function userAuth(req, res, next) {
  if (req.user.role != "user") {
    return res.status(403).send("Member only");
  }
  next();
}

// ==================== MIDLEWARE OPTIONAL AUTH ====================
function optionalAuth(req, res, next) {
  const authToken = req.cookies.authToken;
  if (!authToken) {
    req.user = null;
    res.locals.user = null;
    return next();
  }

  jwt.verify(authToken, jwtSecret, (err, result) => {
    if (!err) {
      req.user = result;
      res.locals.user = result;
    } else {
      req.user = null;
      res.locals.user = null;
    }
    next();
  });
}
// ==================== LOGOUT ROUTES ====================
app.post("/logout", (req, res) => {
  res.clearCookie("authToken", {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
  });
  res.redirect("/login");
});

// ==================== DASHBOARD ROUTE ====================
app.get("/dashboard", authMiddleware, adminAuth, (req, res) => {
  try {
    const totalBooksQuery = "SELECT COUNT(*) AS total FROM books";
    const totalUsersQuery = "SELECT COUNT(*) AS total FROM users WHERE role = 'user'";
    const totalCategoriesQuery = "SELECT COUNT(*) AS total FROM categories";
    const activeBookingsQuery = "SELECT COUNT(*) AS total FROM bookings WHERE actual_return_date IS NULL";

    DB.query(totalBooksQuery, (err, booksResult) => {
      if (err) throw err;
      DB.query(totalUsersQuery, (err, usersResult) => {
        if (err) throw err;
        DB.query(totalCategoriesQuery, (err, categoriesResult) => {
          if (err) throw err;
          DB.query(activeBookingsQuery, (err, bookingsResult) => {
            if (err) throw err;

            res.render("layout", {
              content: "dashboard",
              stats: {
                books: booksResult[0].total,
                users: usersResult[0].total,
                categories: categoriesResult[0].total,
                bookings: bookingsResult[0].total,
              },
            });
          });
        });
      });
    });
  } catch (err) {
    console.error("Error Dashboard:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== CATEGORIES ROUTES ====================
// CREATE PAGE
app.get("/categories/create", authMiddleware, adminAuth, (req, res) => {
  try {
    res.render("layout", { content: "categories/createCategories", pesan: null });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// CREATE POST
app.post("/categories/create", authMiddleware, adminAuth, (req, res) => {
  try {
    const newKategori = req.body.newKategori.trim();

    if (!newKategori) {
      return res.render("layout", {
        content: "categories/createCategories",
        pesan: "Jangan biarkan kolom inputan kosong!",
      });
    }

    DB.query("SELECT * FROM categories WHERE name = ?", [newKategori], (err, result) => {
      if (err) {
        console.error("Error check category:", err);
        return res.status(500).send("Terjadi kesalahan pada server.");
      }

      if (result.length > 0) {
        return res.render("layout", {
          content: "categories/createCategories",
          pesan: "Kategori sudah terdaftar. Silakan pilih yang lain.",
        });
      }

      DB.query("INSERT INTO categories (name) VALUES (?)", [newKategori], (err) => {
        if (err) {
          console.error("Error insert category:", err);
          return res.status(500).send("Terjadi kesalahan saat menyimpan data.");
        }
        res.redirect("/categories");
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// UPDATE PAGE
app.get("/categories/update", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = req.query.id;

    if (!id || isNaN(id)) {
      return res.status(400).send("ID tidak valid");
    }

    DB.query("SELECT * FROM categories WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("Error get category:", err);
        return res.status(500).send("Terjadi kesalahan pada database.");
      }

      if (result.length === 0) return res.status(404).send("Kategori tidak ditemukan.");

      res.render("layout", {
        content: "categories/updateCategories",
        id: result[0].id,
        name: result[0].name,
        pesan: null,
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// UPDATE POST
app.post("/categories/update", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.query.id);
    const name = req.body.name.trim();

    if (!name) {
      return res.render("layout", {
        content: "categories/updateCategories",
        pesan: "Inputan tidak boleh kosong!!",
        id,
        name,
      });
    }

    DB.query("SELECT * FROM categories WHERE name = ? AND id != ?", [name, id], (err, result) => {
      if (err) {
        console.error("Error check category:", err);
        return res.status(500).send("Error saat pengecekan data.");
      }

      if (result[0]) {
        return res.render("layout", {
          content: "categories/updateCategories",
          pesan: "Inputan tidak boleh sama!!",
          id,
          name,
        });
      }

      DB.query("UPDATE categories SET name = ? WHERE id = ?", [name, id], (err) => {
        if (err) {
          console.error("Error update category:", err);
          return res.status(500).send("Ada kesalahan saat update!");
        }
        res.redirect("/categories");
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// LIST / PAGINATION
app.get("/categories", authMiddleware, adminAuth, (req, res) => {
  try {
    const keyword = req.query.keyword || "";
    const page = parseInt(req.query.page) || 1;
    const limit = 6;
    const offset = (page - 1) * limit;

    DB.query(
      "SELECT * FROM categories WHERE name LIKE ? ORDER BY id ASC LIMIT ? OFFSET ?",
      [`%${keyword}%`, limit, offset],
      (err, keywordResult) => {
        if (err) {
          console.error("Error get categories:", err);
          return res.send("Ada error!");
        }
        DB.query(
          "SELECT COUNT(*) AS total FROM categories WHERE name LIKE ?",
          [`%${keyword}%`],
          (err, countResult) => {
        if (err) {
          console.error("Error count categories:", err);
          return res.status(500).send("Terjadi kesalahan pada server.");
        }
        const totalData = countResult[0].total;

        const totalPage = Math.ceil(totalData / limit);
        DB.query(
          `
      SELECT 
      categories.id AS category_id,
      categories.name AS nameCategory,
      COUNT(books.id) AS totalBooks 
      FROM categories 
      LEFT JOIN books ON books.category_id = categories.id
      GROUP BY categories.id, categories.name
		`,
          (err, booksTotal) => {
            if (err) {
              console.error("Error di query join:", err);
              return res.status(500).send("Terjadi kesalahan pada server (join).");
            }

            res.render("layout", {
              content: "categories/categories",
              keywordResult,
              nameSearch: keyword,
              page,
              totalPage,
              booksTotal,
            });
          }
        );
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// DELETE
app.get("/categories/delete/:id", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id);

    if (!id) return res.status(400).send("ID tidak valid.");

    // Cek apakah ada buku dalam kategori ini
    DB.query("SELECT * FROM books WHERE category_id = ?", [id], (err, result) => {
      if (err) {
        console.error("Error check relation:", err);
        return res.status(500).send("Terjadi kesalahan pada database.");
      }

      if (result.length > 0) {
        return res.status(400).send("Gagal menghapus: Kategori ini tidak bisa dihapus karena masih berisi buku.");
      }

      DB.query("DELETE FROM categories WHERE id = ?", [id], (err) => {
        if (err) {
          console.error("Error delete category:", err);
          return res.status(500).send("Gagal menghapus data kategori.");
        }
        res.redirect("/categories");
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== USERS ROUTES ====================
// LIST
app.get("/users", authMiddleware, adminAuth, (req, res) => {
  try {
    const { search = "", status = "all" } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const offset = (page - 1) * limit;

    const params = [];
    let whereClause = "WHERE role = ?";
    params.push("user");

    if (search) {
      whereClause += " AND (name LIKE ? OR email LIKE ?)";
      params.push(`%${search}%`, `%${search}%`);
    }

    if (status !== "all") {
      whereClause += " AND is_active = ?";
      params.push(status === "active" ? 1 : 0);
    }

    let query = `SELECT * FROM users ${whereClause} ORDER BY id ASC LIMIT ? OFFSET ?`;
    let queryCount = `SELECT COUNT(*) AS total FROM users ${whereClause}`;
    params.push(limit, offset);

    DB.query(query, params, (err, result) => {
      if (err) {
        console.error("Error get users:", err);
        return res.status(500).send("Terjadi kesalahan pada server.");
      }

      // Build params for count query (without limit/offset)
      const countParams = [];
      countParams.push("user");
      if (search) {
        countParams.push(`%${search}%`, `%${search}%`);
      }
      if (status !== "all") {
        countParams.push(status === "active" ? 1 : 0);
      }

      DB.query(queryCount, countParams, (err, countResult) => {
        if (err) {
          console.error("Error count users:", err);
          return res.status(500).send("Terjadi kesalahan pada server.");
        }
        const totalData = countResult[0].total;

        const totalPage = Math.ceil(totalData / limit);
        res.render("layout", {
          content: "user/index",
          result,
          totalPage,
          status,
          search,
          page,
          limit,
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// CREATE PAGE
app.get("/users/create", authMiddleware, adminAuth, (req, res) => {
  try {
    res.render("layout", {
      content: "user/createUsers",
      pesan: null,
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// CREATE POST
app.post("/users/create", authMiddleware, adminAuth, (req, res) => {
  try {
    const newName = req.body.newName.trim();
    const newEmail = req.body.newEmail.trim();
    const newPassword = req.body.newPassword.trim();
    const roleDefault = "user";
    const hashPassword = bcrypt.hashSync(newPassword);

    if (!newName || !newEmail || !newPassword) {
      return res.render("layout", {
        content: "user/createUsers",
        pesan: "Jangan biarkan kolom inputan kosong!!",
      });
    } else {
      DB.query("SELECT * FROM users WHERE name = ? OR email = ?", [newName, newEmail], (err, result) => {
        if (err) {
          console.error("Error check user:", err);
          return res.status(500).send("Terjadi kesalahan pada server.");
        }

        if (result.length > 0) {
          return res.render("layout", {
            content: "user/createUsers",
            pesan: "Nama atau Email sudah terdaftar!",
          });
        }

        DB.query("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", [newName, newEmail, hashPassword, roleDefault], (err) => {
          if (err) {
            console.error("Error insert user:", err);
            return res.status(500).send("Terjadi kesalahan saat menyimpan data.");
          }
          res.redirect("/users");
        });
      });
    }
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// UPDATE PAGE
app.get("/users/update", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = req.query.id;

    DB.query("SELECT * FROM users WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("Error get user:", err);
        return res.status(500).send("Terjadi kesalahan pada server.");
      }

      if (result.length === 0) return res.status(404).send("User tidak ditemukan.");

      res.render("layout", {
        content: "user/updateUsers",
        id: result[0].id,
        name: result[0].name,
        email: result[0].email,
        pesan: null,
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// UPDATE POST
app.post("/users/update", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.query.id);
    const updateName = req.body.newName.trim();
    const updateEmail = req.body.newEmail.trim();
    let updatePassword = req.body.newPassword.trim();

    if (!updateName || !updateEmail) {
      DB.query("SELECT * FROM users WHERE id = ?", [id], (err, userData) => {
        if (err) {
          console.error("Error get user:", err);
          return res.status(500).send("Terjadi kesalahan pada server.");
        }

        return res.render("layout", {
          content: "user/updateUsers",
          pesan: "Jangan biarkan kolom inputan kosong",
          id: id,
          name: updateName || userData[0].name,
          email: updateEmail || userData[0].email,
        });
      });
      return;
    }

    DB.query("SELECT password FROM users WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("Error get password:", err);
        return res.status(500).send("Terjadi kesalahan pada server.");
      }

      if (!updatePassword) {
        updatePassword = result[0].password;
      }

      DB.query("SELECT name, email, id FROM users WHERE (name = ? OR email = ?) AND id != ?", [updateName, updateEmail, id], (err, result) => {
        if (err) {
          console.error("Error check duplicate:", err);
          return res.status(500).send("Terjadi kesalahan pada server.");
        }

        if (result.length > 0) {
          let pesanError = "";

          const nameDuplicate = result.find((row) => row.name === updateName);
          const emailDuplicate = result.find((row) => row.email === updateEmail);

          if (nameDuplicate && emailDuplicate) {
            pesanError = "Nama dan Email sudah terdaftar. Silakan pilih yang lain.";
          } else if (nameDuplicate) {
            pesanError = "Nama sudah terdaftar. Silakan pilih yang lain.";
          } else if (emailDuplicate) {
            pesanError = "Email sudah terdaftar. Silakan pilih yang lain.";
          }

          return res.render("layout", {
            content: "user/updateUsers",
            pesan: pesanError,
            id: id,
            name: updateName,
            email: updateEmail,
          });
        }
        DB.query("UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?", [updateName, updateEmail, updatePassword, id], (err) => {
          if (err) {
            console.error("Error saat update:", err);
            return res.status(500).send("Terjadi kesalahan saat update!");
          }
          res.redirect("/users");
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// STATUS TOGGLE
app.get("/users/status", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.query.id);
    const page = parseInt(req.query.page) || 1;
    const search = req.query.search || "";
    const status = req.query.status || "all";

    if (isNaN(id)) return res.status(400).send("ID tidak valid.");

    DB.query("SELECT is_active FROM users WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("Error get status:", err);
        return res.status(500).send("Terjadi kesalahan pada cek status.");
      }
      if (result.length === 0) return res.status(404).send("User tidak ditemukan.");

      const newStatus = result[0].is_active === 1 ? 0 : 1;
      DB.query("UPDATE users SET is_active = ? WHERE id = ?", [newStatus, id], (err) => {
        if (err) {
          console.error("Error update status:", err);
          return res.status(500).send("Terjadi kesalahan pada update.");
        }

        res.redirect(`/users?page=${page}&search=${search}&status=${status}`);
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== BOOKS ROUTES ====================
// LIST
app.get("/books", authMiddleware, adminAuth, (req, res) => {
  try {
    const { search = "", categoryId } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;

    const params = [];
    const whereClauses = [];

    if (search) {
      whereClauses.push("(title LIKE ? OR isbn LIKE ?)");
      params.push(`%${search}%`, `%${search}%`);
    }

    if (categoryId) {
      whereClauses.push("category_id = ?");
      params.push(categoryId);
    }

    const whereStr = whereClauses.length > 0 ? "WHERE " + whereClauses.join(" AND ") : "";

    let query = `
      SELECT 
        books.*,
        categories.name AS category_name,
        MAX(bookings.id) AS booking_id
      FROM books
    LEFT JOIN categories 
        ON books.category_id = categories.id
    LEFT JOIN detail_bookings 
        ON detail_bookings.book_id = books.id
    LEFT JOIN bookings 
        ON bookings.id = detail_bookings.booking_id
        AND bookings.actual_return_date IS NULL
    ${whereStr}
    GROUP BY books.id ORDER BY id ASC LIMIT ? OFFSET ?
`;

    const countParams = [...params];
    let queryCount = `SELECT COUNT(*) AS total FROM books ${whereStr}`;

    const queryParams = [...params, limit, offset];

    DB.query(query, queryParams, (err, searchResult) => {
      if (err) {
        console.error("Error mengambil data buku search:", err);
        return res.status(500).send("Terjadi kesalahan saat mengambil data");
      }
      DB.query("SELECT * FROM categories", (err, categoryResult) => {
        if (err) {
          console.error("Error mengambil data buku:", err);
          return res.status(500).send("Terjadi kesalahan saat mengambil data");
        }
        DB.query(queryCount, countParams, (err, countResult) => {
          if (err) {
            console.error("Error count books:", err);
            return res.status(500).send("Terjadi kesalahan pada server.");
          }
          const totalData = countResult[0].total;
          const totalPage = Math.ceil(totalData / limit);

          searchResult.forEach((r) => {
            if (r.booking_id == null) {
              r.statusBook = 1;
            } else {
              r.statusBook = 2;
            }
          });

          res.render("layout", {
            content: "books/index",
            categoryResult,
            searchResult,
            categoryId,
            search,
            totalPage,
            page,
          });
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// CREATE PAGE
app.get("/books/create", authMiddleware, adminAuth, (req, res) => {
  try {
    DB.query("SELECT * FROM categories", (err, result) => {
      if (err) {
        console.error("Error get categories:", err);
        return res.status(500).send("Terjadi kesalahan pada pengambuilan categories");
      }
      return res.render("layout", { content: "books/createBook", category: result, pesan: null });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// CREATE POST
app.post("/books/create", authMiddleware, adminAuth, (req, res) => {
  try {
    const titleBook = req.body.title;
    const isbnBook = req.body.isbn;
    const patchImage = req.body.image_path;
    const category_id = req.body.category_id;

    if (!titleBook.trim() || !isbnBook.trim() || !category_id.trim()) {
      DB.query("SELECT * FROM categories", (err, result) => {
        if (err) {
          console.error("Error get categories:", err);
          return res.status(500).send("Terjadi kesalahan pada pengambuilan categories");
        }
        res.render("layout", { content: "books/createBook", category: result, pesan: "Jangan biarkan kolom inputan kosong" });
      });
      return;
    }

    DB.query("SELECT title, isbn FROM books WHERE title = ? or isbn = ?", [titleBook, isbnBook], (err, result) => {
      if (err) {
        console.error("Error check book:", err);
        return res.status(500).send("Terjadi kesalahan pada cek data books");
      }

      if (result.length > 0) {
        let pesanError = "";
        const titleDuplicate = result.find((row) => row.title === titleBook);
        const isbnDuplicate = result.find((row) => row.isbn === isbnBook);

        if (titleDuplicate && isbnDuplicate) {
          pesanError = "title dan isbn sudah terdaftar. Silakan pilih yang lain.";
        } else if (titleDuplicate) {
          pesanError = "title sudah terdaftar. Silakan pilih yang lain.";
        } else if (isbnDuplicate) {
          pesanError = "isbn sudah terdaftar. Silakan pilih yang lain.";
        }
        return DB.query("SELECT * FROM categories", (err, categories) => {
          if (err) {
            console.error("Error get categories:", err);
            return res.status(500).send("Error mengambil kategori");
          }

          res.render("layout", {
            content: "books/createBook",
            pesan: pesanError,
            category: categories,
          });
        });
      }

      DB.query("INSERT INTO books (title, image_path, isbn, category_id) VALUES (?,?,?,?)", [titleBook, patchImage, isbnBook, category_id], (err, result) => {
        if (err) {
          console.error("Error insert book:", err);
          return res.status(500).send("Terjadi kesalahan pada input data");
        }
        res.redirect("/books");
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// UPDATE PAGE
app.get("/books/update", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.query.id);
    if (!id) {
      return res.status(400).send("ID tidak valid");
    }

    DB.query(
      `SELECT 
    books.id,
    books.title,
    books.isbn,
    books.image_path,
    books.category_id,
    categories.name AS category_name
    FROM books 
    INNER JOIN categories ON books.category_id = categories.id 
    WHERE books.id = ?`,
      [id],
      (err, bookResult) => {
        if (err) {
          console.error("Error mengambil data buku:", err);
          return res.status(500).send("Terjadi kesalahan saat mengambil data buku");
        }

        if (bookResult.length === 0) {
          return res.status(404).send("Buku tidak ditemukan");
        }

        DB.query("SELECT id, name FROM categories", (err, categoryResult) => {
          if (err) {
            console.error("Error mengambil categories:", err);
            return res.status(500).send("Terjadi kesalahan saat mengambil kategori");
          }

          res.render("layout", {
            content: "books/updateBook",
            id: bookResult[0].id,
            title: bookResult[0].title,
            isbn: bookResult[0].isbn,
            image_path: bookResult[0].image_path,
            category_id: bookResult[0].category_id,
            category: categoryResult,
            pesan: null,
          });
        });
      }
    );
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// UPDATE POST
app.post("/books/update", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.query.id);
    const title = req.body.title;
    const isbn = req.body.isbn;
    const imagePath = req.body.image_path;
    const categoryId = req.body.category_id;

    if (!title || !isbn || !categoryId) {
      DB.query(
        `SELECT 
		books.*,
		  categories.name AS category_name
	  FROM books 
	    INNER JOIN categories ON books.category_id = categories.id 
	  WHERE books.id = ?`,
        [id],
        (err, bookResult) => {
          if (err) {
            console.error("Error get book:", err);
            return res.status(500).send("Error mengambil data buku");
          }

          DB.query("SELECT id, name FROM categories", (err, categoryResult) => {
            if (err) {
              console.error("Error get categories:", err);
              return res.status(500).send("Error mengambil categories");
            }

            return res.render("books/updateBook", {
              book: bookResult[0],
              category: categoryResult,
              pesan: "Terdapat kolom inputan yang kosong!",
            });
          });
        }
      );
      return;
    }

    DB.query("SELECT title, isbn FROM books WHERE (title = ? OR isbn = ?) AND id != ?", [title, isbn, id], (err, duplicateResult) => {
      if (err) {
        console.error("Error check duplicate:", err);
        return res.status(500).send("Terjadi kesalahan pada saat memeriksa duplikasi data.");
      }

      if (duplicateResult.length > 0) {
        let pesanError = "";
        const titleDuplicate = duplicateResult.find((row) => row.title === title);
        const isbnDuplicate = duplicateResult.find((row) => row.isbn === isbn);

        if (titleDuplicate && isbnDuplicate) {
          pesanError = "Judul dan ISBN sudah terdaftar. Silakan pilih yang lain.";
        } else if (titleDuplicate) {
          pesanError = "Judul sudah terdaftar. Silakan pilih yang lain.";
        } else {
          pesanError = "ISBN sudah terdaftar. Silakan pilih yang lain.";
        }

        return DB.query("SELECT * FROM categories", (err, categoryResult) => {
          if (err) {
            console.error("Error get categories:", err);
            return res.status(500).send("Terjadi kesalahan pada saat mengambil data kategori.");
          }
          res.render("books/updateBook", {
            id: id,
            title: title,
            isbn: isbn,
            image_path: imagePath,
            category_id: categoryId,
            category: categoryResult,
            pesan: pesanError,
          });
        });
      }

      DB.query("UPDATE books SET title = ?, isbn = ?, image_path = ?, category_id = ? WHERE id = ?", [title, isbn, imagePath, categoryId, id], (updateErr, updateResult) => {
        if (updateErr) {
          console.error("Error update book:", updateErr);
          return res.status(500).send("Terjadi kesalahan pada saat memperbarui data buku.");
        }
        res.redirect("/books");
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// DELETE
app.get("/books/delete/:id", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).send("ID tidak valid.");

    // Cek apakah buku sedang dipinjam
    DB.query(`
      SELECT * FROM detail_bookings 
      JOIN bookings ON detail_bookings.booking_id = bookings.id 
      WHERE detail_bookings.book_id = ? AND bookings.actual_return_date IS NULL
    `, [id], (err, result) => {
      if (err) {
        console.error("Error check relation:", err);
        return res.status(500).send("Terjadi kesalahan pada database.");
      }

      if (result.length > 0) {
        // Jika ada relasi yang masih aktif (belum dikembalikan)
        return res.status(400).send("Gagal menghapus: Buku ini tidak bisa dihapus karena sedang dipinjam.");
      }

      // Jika tidak ada relasi, lanjutkan penghapusan
      DB.query("DELETE FROM books WHERE id = ? ", [id], (err) => {
        if (err) {
          console.error("Error delete book:", err);
          return res.status(500).send("Gagal menghapus data buku.");
        }
        res.redirect("/books");
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== BOOKINGS ROUTES ====================
// LIST
app.get("/bookings", authMiddleware, adminAuth, (req, res) => {
  try {
    const keyword = req.query.keyword || "";
    const status = req.query.status || "";
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const offset = (page - 1) * limit;

    const keywordLike = keyword ? `%${keyword}%` : "";

    let query;
    let queryCount;
    let queryParams;
    let countParams;

    if (status == "") {
      query = `
      SELECT 
      bookings.id AS bookings_id,
      users.name AS user_name,
      bookings.start_date,
      bookings.end_date,
      bookings.actual_return_date,
      bookings.penalty_fee,
      COALESCE(bookings.penalty_paid, 0) AS penalty_paid,
      GROUP_CONCAT(books.title SEPARATOR ', ') AS books
      FROM bookings
      JOIN users ON users.id = bookings.user_id
      JOIN detail_bookings ON detail_bookings.booking_id = bookings.id
      JOIN books ON books.id = detail_bookings.book_id
      WHERE 1=1
      ${keyword ? "AND (users.name LIKE ? OR books.title LIKE ?)" : ""}
      GROUP BY bookings.id
      ORDER BY bookings.id DESC
      LIMIT ? OFFSET ?
`;
      queryCount = `
      SELECT 
      COUNT(DISTINCT bookings.id) AS totalBookings
      FROM bookings
      JOIN users ON users.id = bookings.user_id
      JOIN detail_bookings ON detail_bookings.booking_id = bookings.id
      JOIN books ON books.id = detail_bookings.book_id
      WHERE 1=1
      ${keyword ? "AND (users.name LIKE ? OR books.title LIKE ?)" : ""}
`;
      queryParams = keyword ? [keywordLike, keywordLike, limit, offset] : [limit, offset];
      countParams = keyword ? [keywordLike, keywordLike] : [];
    } else {
      if (status == "users") {
        query = ` 
        SELECT DISTINCT 
        users.name AS user_name,
        users.id
        FROM users
        JOIN bookings ON users.id = bookings.user_id
        WHERE (users.name LIKE ? OR users.email LIKE ?)
        ORDER BY users.id ASC
        LIMIT ? OFFSET ?
`;
        queryCount = `
        SELECT 
        COUNT(DISTINCT users.id) AS totalBookings
        FROM users
        JOIN bookings ON users.id = bookings.user_id
        WHERE (users.name LIKE ? OR users.email LIKE ?)
`;
        queryParams = [keywordLike, keywordLike, limit, offset];
        countParams = [keywordLike, keywordLike];
      } else {
        query = `
        SELECT DISTINCT
        books.id,
        books.title,
        books.isbn
        FROM books
        JOIN detail_bookings
        ON detail_bookings.book_id = books.id
        WHERE (books.title LIKE ? OR books.isbn LIKE ?)
        ORDER BY books.id ASC
        LIMIT ? OFFSET ?
`;
        queryCount = `
        SELECT 
        COUNT(DISTINCT books.id) AS totalBookings
        FROM books
        JOIN detail_bookings
        ON detail_bookings.book_id = books.id
        WHERE (books.title LIKE ? OR books.isbn LIKE ?)
`;
        queryParams = [keywordLike, keywordLike, limit, offset];
        countParams = [keywordLike, keywordLike];
      }
    }

    DB.query(queryCount, countParams, (err, totalBookings) => {
      if (err) {
        console.error("Error get total bookings:", err);
        return res.status(500).send("Gagal ambil data");
      }
      DB.query(query, queryParams, (err, resultSearch) => {
        if (err) {
          console.error("Error get bookings:", err);
          return res.status(500).send("Gagal ambil data");
        }
        DB.query(
          ` 
          SELECT 
          COUNT(detail_bookings.id) AS totalBooks
      FROM detail_bookings
      LEFT JOIN bookings 
          ON bookings.id = detail_bookings.booking_id
      WHERE bookings.actual_return_date IS NULL
        `,
          (err, result) => {
            if (err) {
              console.error("Error get bookings:", err);
              return res.status(500).send("Gagal ambil data");
            }

            const totalData = totalBookings[0].totalBookings;
            const totalPage = Math.ceil(totalData / limit);

            resultSearch.forEach((r) => {
              r.startDate = dayjs(r.start_date).format("D MMMM YYYY");
              r.endDate = dayjs(r.end_date).format("D MMMM YYYY");
              r.actualReturnDate = r.actual_return_date ? dayjs(r.actual_return_date).format("D MMMM YYYY") : "-";

              // Denda info
              r.penaltyPaid = r.penalty_paid == 1;
              r.denda = r.penalty_fee || 0;

              const end = dayjs(r.end_date);
              const actual = r.actual_return_date ? dayjs(r.actual_return_date) : null;

              if (!actual) {
                r.status = "Dipinjam";
                // Booking aktif: estimasi denda dari keterlambatan skrg (tapi jangan ditimpa kalo udah ada penalty_fee dari return)
                if (!r.denda && end.isBefore(dayjs())) {
                  r.daysLate = dayjs().diff(end, "day");
                  r.estimatedPenalty = true;
                  // Jangan set r.denda karena belum final — kita tampilkan info "Terlambat X hari"
                }
              } else if (actual.isAfter(end)) {
                r.status = "Terlambat";
              } else {
                r.status = "Dikembalikan";
              }
            });

            res.render("layout", {
              resultSearch,
              page,
              result: result[0].totalBooks,
              status,
              keyword,
              content: "bookings/index",
              totalPage: totalPage || 0,
              limit,
            });
          }
        );
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// CREATE PAGE
app.get("/bookings/create", authMiddleware, adminAuth, (req, res) => {
  try {
    DB.query("SELECT id, name FROM users WHERE role = 'user' AND is_active = 1 ", (err, users) => {
      if (err) {
        console.error("Error get users:", err);
        return res.status(500).send("Gagal ambil data user");
      }
      DB.query(
        `
        SELECT
        books.id,
        books.title
    FROM books
    WHERE books.id NOT IN (
        SELECT detail_bookings.book_id
        FROM detail_bookings
        JOIN bookings ON bookings.id = detail_bookings.booking_id
        WHERE bookings.actual_return_date IS NULL
    )
      `,
        (err, books) => {
          if (err) {
            console.error("Error get books:", err);
            return res.status(500).send("Gagal ambil data buku");
          }

          res.render("layout", {
            content: "bookings/createBookings",
            books,
            users,
            pesan: null,
          });
        }
      );
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// CREATE POST
app.post("/bookings/create", authMiddleware, adminAuth, (req, res) => {
  try {
    const { user_id, end_date, book_ids } = req.body;
    const penalty_fee = 0;

    if (!user_id || !end_date || !book_ids) {
      DB.query("SELECT id, name FROM users WHERE is_active = 1", (err, users) => {
        if (err) {
          console.error("Error get users:", err);
          return res.status(500).send("Gagal ambil data users");
        }

        DB.query("SELECT id, title FROM books", (err, books) => {
          if (err) {
            console.error("Error get books:", err);
            return res.status(500).send("Gagal ambil data books");
          }

          res.render("layout", {
            content: "bookings/createBookings",
            pesan: "Jangan ada inputan yang kosong!",
            users,
            books,
          });
        });
      });
      return;
    }

    const books_id = Array.isArray(book_ids) ? book_ids : [book_ids];

    // Use transaction to ensure atomicity
    DB.beginTransaction((err) => {
      if (err) {
        console.error("Error begin transaction:", err);
        return res.status(500).send("Gagal memulai transaksi.");
      }

      DB.query("INSERT INTO bookings (user_id, end_date, penalty_fee) VALUES (?,?,?)", [user_id, end_date, penalty_fee], (err, result) => {
        if (err) {
          return DB.rollback(() => {
            console.error("Error insert booking:", err);
            res.status(500).send("Gagal membuat booking");
          });
        }

        const booking_id = result.insertId;
        let inserted = 0;

        books_id.forEach((book) => {
          DB.query("INSERT INTO detail_bookings (book_id, booking_id) VALUES (?,?)", [book, booking_id], (err) => {
            if (err) {
              return DB.rollback(() => {
                console.error("Gagal tambah detail:", err);
                res.status(500).send("Gagal menambahkan detail buku: " + (book.title || book));
              });
            }

            inserted++;
            if (inserted === books_id.length) {
              DB.commit((err) => {
                if (err) {
                  return DB.rollback(() => {
                    console.error("Error commit:", err);
                    res.status(500).send("Gagal menyelesaikan transaksi.");
                  });
                }
                res.redirect("/bookings");
              });
            }
          });
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

//return book
app.get("/bookings/returnBook", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = req.query.id;
    DB.query(
      `
    SELECT 
    users.name,
    books.title,
    bookings.user_id,
    bookings.penalty_fee,
    bookings.start_date,  
    bookings.end_date,
    COUNT(*) OVER() AS totalBooks
    FROM bookings
    JOIN users ON users.id = bookings.user_id
    JOIN detail_bookings ON bookings.id = detail_bookings.booking_id
    JOIN books ON detail_bookings.book_id = books.id
    WHERE bookings.id = ?; 
     `,
      [id],
      (err, result) => {
        if (err) {
          console.error("Error get booking:", err);
          return res.status(500).send("Gagal ambil bookings");
        }

        const start = dayjs(result[0].start_date);
        const end = dayjs(result[0].end_date);
        const actual = dayjs(Date.now());

        const startDate = start.format("D MMMM YYYY");
        const endDate = end.format("D MMMM YYYY");
        const actualDate = actual.format("D MMMM YYYY");

        // Ambil penalty rate sebagai number
        DB.query("SELECT COALESCE(penalty_fee, 0) AS penalty_rate FROM settings LIMIT 1", (err, settingResult) => {
          if (err) {
            console.error("Error get penalty fee:", err);
            return res.status(500).send("Gagal ambil fee");
          }

          const penaltyRate = Number(settingResult[0].penalty_rate);
          const dayPenalty = actual.isAfter(end) ? actual.diff(end, `day`) : 0;
          const totalDenda = dayPenalty * Number(result[0].totalBooks) * penaltyRate;

          res.render("layout", {
            content: "bookings/returnBookings",
            id,
            name: result[0].name,
            totalBooks: result[0].totalBooks,
            books: result,
            endDate,
            startDate,
            actualDate,
            dayPenalty,
            fee: totalDenda.toLocaleString("id-ID"),
            penalty_fee: penaltyRate.toLocaleString("id-ID"),
            actual,
            end,
          });
        });
      }
    );
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// status pengembalian
app.post("/bookings/returnBook", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = req.body.id;
    const format = req.body.fee;
    const safeFormat = format ? String(format) : "0";
    const fee = safeFormat.replace(/[.,-]/g, "");

    DB.beginTransaction((err) => {
      if (err) {
        console.error("Error begin transaction:", err);
        return res.status(500).send("Gagal memulai transaksi.");
      }

      DB.query("UPDATE bookings SET actual_return_date = NOW() WHERE id = ?", [id], (err) => {
        if (err) {
          return DB.rollback(() => {
            console.error("Error return book:", err);
            res.status(500).send("Gagal mengembalikan buku.");
          });
        }
        DB.query("UPDATE bookings SET penalty_fee = ? WHERE id = ?", [fee, id], (err) => {
          if (err) {
            return DB.rollback(() => {
              console.error("Gagal dalam insert penalty_fee", err);
              res.status(500).send("Gagal insert fee");
            });
          }
          DB.commit((err) => {
            if (err) {
              return DB.rollback(() => {
                console.error("Error commit:", err);
                res.status(500).send("Gagal menyelesaikan transaksi.");
              });
            }
            res.redirect("/bookings");
          });
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

app.get("/bookings/user/:id", authMiddleware, adminAuth, (req, res) => {
  const id = req.params.id;
  DB.query(
    `
    SELECT
    users.*,
    GROUP_CONCAT(books.title SEPARATOR ', ') AS books,
    GROUP_CONCAT(books.isbn SEPARATOR ', ') AS isbns,
    bookings.start_date,
    bookings.end_date
    FROM users
    LEFT JOIN bookings ON users.id = bookings.user_id 
      AND bookings.actual_return_date IS NULL
    LEFT JOIN detail_bookings ON detail_bookings.booking_id = bookings.id
    LEFT JOIN books ON books.id = detail_bookings.book_id
    WHERE users.id = ?
    GROUP BY bookings.id
    `,
    [id],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Terjadi kesalahan pada server.");
      }

      if (!result || result.length === 0 || !result[0].start_date) {
        return res.render("layout", {
          content: "bookings/detailUser",
          bookReturn: [],
          result: [],
          totalDipinjam: 0,
        });
      }

      let totalDipinjam = result.length;

      result.forEach((r) => {
        if (!r.start_date) return;
        const dayStart = dayjs(r.start_date);
        const dayEnd = dayjs(r.end_date);
        const dayActual = r.actual_return_date ? dayjs(r.actual_return_date) : dayjs();

        r.startDate = dayjs(r.start_date).format("D MMMM YYYY");
        r.endDate = dayjs(r.end_date).format("D MMMM YYYY");
        r.actualReturnDate = r.actual_return_date ? dayjs(r.actual_return_date).format("D MMMM YYYY") : "-";

        r.remainingTime = dayEnd.diff(dayStart, `day`);
        r.dayPenalty = dayActual.diff(dayEnd, `day`);
      });
      DB.query(
        `
      SELECT 
      bookings.id,
      GROUP_CONCAT(books.title SEPARATOR ', ') AS books,
      bookings.start_date,
      bookings.end_date,
      bookings.actual_return_date
    FROM users
    LEFT JOIN bookings 
      ON users.id = bookings.user_id
    LEFT JOIN detail_bookings 
      ON detail_bookings.booking_id = bookings.id
    LEFT JOIN books 
      ON books.id = detail_bookings.book_id
    WHERE users.id = ?
      AND bookings.actual_return_date IS NOT NULL
      GROUP BY bookings.id
    `,
        [id],
        (err, bookReturn) => {
          if (err) {
            console.error(err);
            return;
          }

          bookReturn.forEach((r) => {
            if (!r.actual_return_date) {
              r.status = "Sedang Dipinjam";
              r.dayPenalty = 0;
            }
            const dayStart = dayjs(r.start_date);
            const dayEnd = dayjs(r.end_date);
            const dayActual = dayjs(r.actual_return_date).startOf("day");

            r.startDate = dayjs(r.start_date).format("D MMMM YYYY");
            r.endDate = dayjs(r.end_date).format("D MMMM YYYY");
            r.actualReturnDate = r.actual_return_date ? dayjs(r.actual_return_date).format("D MMMM YYYY") : "-";

            r.remainingTime = dayEnd.diff(dayStart, `day`);
            r.dayPenalty = dayActual.diff(dayEnd, `day`);

            if (dayActual.isAfter(dayEnd)) {
              r.status = "Terlambat";
            } else {
              r.status = "Tepat Waktu";
            }
          });

          res.render("layout", {
            content: "bookings/detailUser",
            bookReturn,
            result,
            totalDipinjam,
          });
        }
      );
    }
  );
});

app.get("/bookings/book/:id", authMiddleware, adminAuth, (req, res) => {
  const id = req.params.id;

  DB.query(
    `
    SELECT
      books.*,
      categories.name
      FROM books
    LEFT JOIN categories ON books.category_id = categories.id
    WHERE books.id = ?
    `,
    [id],
    (err, result) => {
      if (err) {
        console.error(err);
        return;
      }
      DB.query(
        `
        SELECT 
          users.name,
          users.email,
          bookings.start_date,
          bookings.end_date,
          bookings.actual_return_date,
          bookings.id AS bookings_id
        FROM users
        JOIN bookings ON users.id = bookings.user_id
        JOIN detail_bookings ON bookings.id = detail_bookings.booking_id
        WHERE detail_bookings.book_id = ?
        AND bookings.actual_return_date IS NULL
        `,
        [id],
        (err, results) => {
          if (err) {
            console.error(err);
            return;
          }
          DB.query(
            `
            SELECT 
              users.name, 
              users.email, 
              bookings.start_date, 
              bookings.end_date, 
              detail_bookings.book_id 
            FROM users 
            JOIN bookings ON bookings.user_id = users.id 
            JOIN detail_bookings ON detail_bookings.booking_id = bookings.id 
            WHERE bookings.actual_return_date IS NOT NULL 
              AND detail_bookings.book_id = ?;
            `,
            [id],
            (err, borrowerHistory) => {
              if (err) {
                console.error(err);
                return;
              }

              const yangPinjam = results.length > 0 ? results : null;
              const riwayatPeminjaman = borrowerHistory.length > 0 ? borrowerHistory : null;
              const statusBook = yangPinjam ? 1 : 0;

              let startDateForamat = "-";
              let endDateFormat = "-"; 
              let timeLeft = 0;
              let actual = dayjs();
              let dayEnd = null;
              let colorWarning = "orange";
              let dataPeminjam

              // 3. Hanya isi jika ada data peminjaman aktif
              if (yangPinjam) {
                const ds = dayjs(results[0].start_date);
                const de = dayjs(results[0].end_date);

                dayEnd = de;
                startDateForamat = ds.format("D MMMM YYYY");
                endDateFormat = de.format("D MMMM YYYY");

                const diff = de.diff(actual, "day");

                if (diff < 0) {
                  timeLeft = Math.abs(diff);
                  colorWarning = "red";
                } else {
                  timeLeft = diff;
                  colorWarning = timeLeft < 4 ? "red" : "orange";
                }
              }

              if (riwayatPeminjaman) {
                borrowerHistory.forEach((item) => {
                  item.startDate = dayjs(item.start_date).format("D MMMM YYYY");
                  item.endDate = dayjs(item.end_date).format("D MMMM YYYY");
                  
                });
              }

                res.render("layout", {
                  content: "bookings/detailBook",
                  book: result[0],
                  yangPinjam,
                  startDateForamat,
                  endDateFormat,
                  statusBook,
                  timeLeft,
                  actual,
                  dayEnd,
                  colorWarning,
                  dataPeminjam,
                  riwayatPeminjaman,
                  borrowerHistory,
                });
            }
          );
        }
      );
    }
  );
});

// ==================== SETTINGS ROUTES ====================
app.get("/settings", authMiddleware, adminAuth, (req, res) => {
  try {
    DB.query("SELECT FORMAT(penalty_fee, 0, 'id_ID') AS penalty_fee FROM settings LIMIT 1", (err, result) => {
      if (err) {
        console.error("Error get settings:", err);
        throw err;
      }

      res.render("layout", {
        content: "settings/index",
        pesan: null,
        setting: result[0],
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

app.post("/settings/updatePenalty", authMiddleware, adminAuth, (req, res) => {
  try {
    const penalty_fee = req.body.penalty_fee;
    DB.query("UPDATE settings SET penalty_fee = ? LIMIT 1", [penalty_fee], (err) => {
      if (err) {
        console.error("Error update penalty:", err);
        throw err;
      }

      DB.query("SELECT FORMAT(penalty_fee, 0, 'id_ID') AS penalty_fee FROM settings LIMIT 1", (err, result) => {
        if (err) {
          console.error("Error get settings:", err);
          throw err;
        }
        res.render("layout", {
          content: "settings/index",
          pesan: "Berhasil diubah!",
          setting: result[0],
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== USER PORTAL ROUTES ====================

app.get("/katalog", optionalAuth, (req, res) => {
  try {
    const search = req.query.search || "";
    const page = parseInt(req.query.page) || 1;
    const limit = 8;
    const offset = (page - 1) * limit;

    const searchLike = search ? `%${search}%` : "";

    let query = `
      SELECT books.*, categories.name AS category_name
      FROM books
      LEFT JOIN categories ON books.category_id = categories.id
      WHERE title LIKE ? OR isbn LIKE ?
      ORDER BY books.id DESC
      LIMIT ? OFFSET ?
    `;

    let queryCount = "SELECT COUNT(*) AS total FROM books WHERE title LIKE ? OR isbn LIKE ?";
    const queryParams = [searchLike, searchLike, limit, offset];
    const countParams = [searchLike, searchLike];

    DB.query(query, queryParams, (err, books) => {
      if (err) throw err;
      DB.query(queryCount, countParams, (err, countResult) => {
        if (err) throw err;
        const totalPage = Math.ceil(countResult[0].total / limit);
        res.render("user_layout", {
          content: "public/katalog",
          books,
          search,
          page,
          totalPage
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

app.get("/katalog/:id", optionalAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).send("ID tidak valid");

    DB.query(
      `SELECT books.*, categories.name AS category_name 
       FROM books 
       LEFT JOIN categories ON books.category_id = categories.id 
       WHERE books.id = ?`,
      [id],
      (err, result) => {
        if (err) throw err;
        if (result.length === 0) return res.status(404).send("Buku tidak ditemukan");

        // Record history if logged in as user
        if (req.user && req.user.role === 'user') {
          DB.query("INSERT INTO user_viewed_books (user_id, book_id) VALUES (?, ?)", [req.user.id, id], (err) => {
            if (err) console.error("Gagal mencatat riwayat buku:", err);
          });
        }

        res.render("user_layout", {
          content: "public/detailBuku",
          book: result[0]
        });
      }
    );
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

app.get("/user/pinjaman", authMiddleware, userAuth, (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get active loans (sedang dipinjam)
    const activeQuery = `
      SELECT bookings.id, bookings.start_date, bookings.end_date,
             COALESCE(bookings.penalty_paid, 0) AS penalty_paid,
             GROUP_CONCAT(books.title SEPARATOR ', ') AS books
      FROM bookings
      JOIN detail_bookings ON detail_bookings.booking_id = bookings.id
      JOIN books ON books.id = detail_bookings.book_id
      WHERE bookings.user_id = ? AND bookings.actual_return_date IS NULL
      GROUP BY bookings.id
    `;

    // Get stats
    const statsQuery = `
      SELECT 
        (SELECT COUNT(DISTINCT detail_bookings.book_id) FROM bookings JOIN detail_bookings ON detail_bookings.booking_id = bookings.id WHERE bookings.user_id = ? AND bookings.actual_return_date IS NULL) as totalDipinjam,
        (SELECT COUNT(DISTINCT detail_bookings.book_id) FROM bookings JOIN detail_bookings ON detail_bookings.booking_id = bookings.id WHERE bookings.user_id = ? AND bookings.actual_return_date IS NOT NULL) as totalDikembalikan
    `;

    DB.query(activeQuery, [userId], (err, activeLoans) => {
      if (err) throw err;
      
      DB.query(statsQuery, [userId, userId], (err, statsResult) => {
        if (err) throw err;
        
        DB.query("SELECT COALESCE(penalty_fee, 0) AS penalty_fee FROM settings LIMIT 1", (err, settingResult) => {
          if (err) throw err;
          
          let penaltyRate = 0;
          if (settingResult.length > 0 && settingResult[0].penalty_fee) {
            penaltyRate = Number(settingResult[0].penalty_fee);
          }
          
          let totalDenda = 0;
          let actual = dayjs();

          activeLoans.forEach(loan => {
            let start = dayjs(loan.start_date);
            let end = dayjs(loan.end_date);
            
            loan.startDate = start.format("D MMMM YYYY");
            loan.endDate = end.format("D MMMM YYYY");
            loan.penaltyPaid = loan.penalty_paid == 1;
            
            let diff = actual.diff(end, 'day');
            
            if (diff > 0) {
              loan.isLate = true;
              loan.daysLate = diff;
              // estimate penalty based on total books in this booking
              const numBooks = loan.books.split(',').length;
              // Hanya hitung denda yg belum dibayar
              if (!loan.penaltyPaid) {
                totalDenda += diff * numBooks * penaltyRate;
              }
            } else {
              loan.isLate = false;
              loan.daysLate = 0;
            }
          });

          // Add past unpaid penalties from returned bookings
          DB.query("SELECT SUM(penalty_fee) as accumulatedPenalty FROM bookings WHERE user_id = ? AND actual_return_date IS NOT NULL AND (penalty_paid IS NULL OR penalty_paid = 0)", [userId], (err, pastPenaltyRes) => {
            if (!err && pastPenaltyRes[0].accumulatedPenalty) {
              totalDenda += Number(pastPenaltyRes[0].accumulatedPenalty);
            }
            
            res.render("user_layout", {
              content: "user_portal/pinjaman",
              activeLoans,
              totalDipinjam: statsResult[0].totalDipinjam || 0,
              totalDikembalikan: statsResult[0].totalDikembalikan || 0,
              totalDenda
            });
          });
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

app.get("/user/riwayat", authMiddleware, userAuth, (req, res) => {
  try {
    const userId = req.user.id;
    const query = `
      SELECT books.*, categories.name AS category_name, MAX(user_viewed_books.viewed_at) as last_viewed
      FROM user_viewed_books
      JOIN books ON user_viewed_books.book_id = books.id
      LEFT JOIN categories ON books.category_id = categories.id
      WHERE user_viewed_books.user_id = ?
      GROUP BY books.id
      ORDER BY last_viewed DESC
      LIMIT 50
    `;

    DB.query(query, [userId], (err, books) => {
      if (err) throw err;
      
      const now = dayjs();
      books.forEach(b => {
        const viewed = dayjs(b.last_viewed);
        const diffHours = now.diff(viewed, 'hour');
        if (diffHours < 24) {
          b.timeAgo = diffHours === 0 ? 'Baru saja' : diffHours + ' jam yang lalu';
        } else {
          b.timeAgo = now.diff(viewed, 'day') + ' hari yang lalu';
        }
      });

      res.render("user_layout", {
        content: "user_portal/riwayat",
        books
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== RIWAYAT PINJAMAN USER ====================
app.get("/user/riwayat-pinjaman", authMiddleware, userAuth, (req, res) => {
  try {
    const userId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;

    const query = `
      SELECT bookings.id, bookings.start_date, bookings.end_date,
             bookings.actual_return_date, bookings.penalty_fee,
             COALESCE(bookings.penalty_paid, 0) AS penalty_paid,
             GROUP_CONCAT(books.title SEPARATOR ', ') AS books,
             GROUP_CONCAT(books.isbn SEPARATOR ', ') AS isbns
      FROM bookings
      JOIN detail_bookings ON detail_bookings.booking_id = bookings.id
      JOIN books ON books.id = detail_bookings.book_id
      WHERE bookings.user_id = ? AND bookings.actual_return_date IS NOT NULL
      GROUP BY bookings.id
      ORDER BY bookings.actual_return_date DESC
      LIMIT ? OFFSET ?
    `;

    const countQuery = `
      SELECT COUNT(DISTINCT bookings.id) AS total
      FROM bookings
      WHERE bookings.user_id = ? AND bookings.actual_return_date IS NOT NULL
    `;

    DB.query(query, [userId, limit, offset], (err, history) => {
      if (err) throw err;

      DB.query(countQuery, [userId], (err, countResult) => {
        if (err) throw err;

        const totalData = countResult[0].total;
        const totalPage = Math.ceil(totalData / limit);

        history.forEach((r) => {
          const end = dayjs(r.end_date);
          const actual = dayjs(r.actual_return_date);
          r.startDate = r.start_date ? dayjs(r.start_date).format("D MMMM YYYY") : "-";
          r.endDate = end.format("D MMMM YYYY");
          r.actualReturnDate = actual.format("D MMMM YYYY");
          r.penaltyPaid = r.penalty_paid == 1;

          if (actual.isAfter(end)) {
            r.status = "Terlambat";
            r.daysLate = actual.diff(end, "day");
          } else {
            r.status = "Tepat Waktu";
            r.daysLate = 0;
          }
        });

        res.render("user_layout", {
          content: "user_portal/riwayatPinjaman",
          history,
          page,
          totalPage,
          limit,
        });
      });
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== PAY PENALTY (ADMIN) ====================
app.post("/bookings/pay-penalty", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = req.body.id;
    if (!id) return res.status(400).send("ID booking diperlukan.");
    DB.query("UPDATE bookings SET penalty_paid = 1 WHERE id = ?", [id], (err) => {
      if (err) {
        console.error("Error pay penalty:", err);
        return res.status(500).send("Gagal menandai pembayaran.");
      }
      // Redirect back
      const referer = req.get("Referer") || "/bookings";
      res.redirect(referer);
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== UNPAY PENALTY (ADMIN) ====================
app.post("/bookings/unpay-penalty", authMiddleware, adminAuth, (req, res) => {
  try {
    const id = req.body.id;
    if (!id) return res.status(400).send("ID booking diperlukan.");
    DB.query("UPDATE bookings SET penalty_paid = 0 WHERE id = ?", [id], (err) => {
      if (err) {
        console.error("Error unpay penalty:", err);
        return res.status(500).send("Gagal membatalkan pembayaran.");
      }
      const referer = req.get("Referer") || "/bookings";
      res.redirect(referer);
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});

// ==================== SERVER START ====================
app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
