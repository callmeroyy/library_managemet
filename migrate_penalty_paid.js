const mysql = require("mysql2");
require("dotenv").config();

const connection = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "root",
  database: process.env.DB_NAME || "library_management",
});

connection.connect((err) => {
  if (err) {
    console.error("Gagal terhubung ke database:", err.stack);
    process.exit(1);
  }
  console.log("Terhubung ke database.");

  connection.query(
    "ALTER TABLE bookings ADD COLUMN penalty_paid TINYINT(1) NOT NULL DEFAULT 0 AFTER penalty_fee",
    (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_FIELDNAME" || err.message.includes("Duplicate column")) {
          console.log("Kolom penalty_paid sudah ada.");
        } else {
          console.error("Error:", err.message);
        }
      } else {
        console.log("Kolom penalty_paid berhasil ditambahkan!");
      }
      connection.end();
    }
  );
});
