const mysql = require("mysql2");

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "library_management"
});

connection.connect((err) => {
  if (err) {
    console.error("koneksi database gagal:", err.stack);
    return;
  }  
});
console.log("Berhasil terhubung ke database.");

module.exports = connection;
