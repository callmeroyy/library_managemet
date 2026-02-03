const mysql = require("mysql2");

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "library_management"
});

connection.connect((err) => {
  if (err) {
    console.error("Gagal terhubung ke database:", err.stack);
    process.exit(1);
  }
  console.log("Terhubung ke database.");

  function runQuery(sql) {
    return new Promise((resolve, reject) => {
      console.log(`Menjalankan: ${sql}`);
      connection.query(sql, (error, results) => {
        if (error) {
          console.log(`  (Hasil: Terjadi error - ${error.message})`);
          resolve(false); // Lanjut saja
        } else {
          console.log(`  (Hasil: Sukses)`);
          resolve(true);
        }
      });
    });
  }

  async function migrate() {
    // Coba hapus semua kemungkinan nama constraint
    await runQuery("ALTER TABLE detail_bookings DROP FOREIGN KEY detail_bookings_ibfk_1");
    await runQuery("ALTER TABLE detail_bookings DROP FOREIGN KEY detail_bookings_ibfk_2");
    await runQuery("ALTER TABLE detail_bookings DROP FOREIGN KEY fk_book_id");

    // Tambahkan kembali dengan CASCADE
    const success = await runQuery("ALTER TABLE detail_bookings ADD CONSTRAINT fk_book_id FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE");

    if (success) {
      console.log("\n>>> MIGRASI BERHASIL! Aturan CASCADE telah diterapkan. <<<");
    } else {
      console.log("\n>>> MIGRASI GAGAL! Silakan hubungi admin. <<<");
    }
    
    connection.end();
  }

  migrate();
});
