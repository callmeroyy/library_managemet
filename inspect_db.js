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
  
  connection.query("SHOW CREATE TABLE detail_bookings", (err, result) => {
    if (err) {
      console.error("Error:", err);
    } else {
      console.log("Table structure for detail_bookings:");
      console.log(result[0]['Create Table']);
    }
    connection.end();
  });
});
