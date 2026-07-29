const mysql = require('mysql2');
const c = mysql.createConnection({host:'localhost',user:'root',password:'root',database:'library_management'});
const sql = `
CREATE TABLE IF NOT EXISTS user_viewed_books (
  id int unsigned NOT NULL AUTO_INCREMENT,
  user_id int unsigned NOT NULL,
  book_id int unsigned NOT NULL,
  viewed_at datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  FOREIGN KEY (book_id) REFERENCES books (id) ON DELETE CASCADE
);
`;
c.query(sql, (e) => {
  if (e) console.error(e);
  else console.log('Table user_viewed_books created!');
  c.end();
});
