const { v4: uuidv4 } = require('uuid');
const { db } = require('../db/database');

class MediaFolder {
  static create({ name, user_id }) {
    return new Promise((resolve, reject) => {
      const id = uuidv4();
      const now = new Date().toISOString();
      db.run(
        `INSERT INTO media_folders (id, name, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
        [id, name, user_id, now, now],
        function (err) {
          if (err) {
            console.error('Error creating media folder:', err.message);
            return reject(err);
          }
          resolve({ id, name, user_id, created_at: now, updated_at: now });
        }
      );
    });
  }

  static findAll(userId) {
    return new Promise((resolve, reject) => {
      db.all(
        'SELECT * FROM media_folders WHERE user_id = ? ORDER BY created_at DESC',
        [userId],
        (err, rows) => {
          if (err) {
            console.error('Error finding media folders:', err.message);
            return reject(err);
          }
          resolve(rows || []);
        }
      );
    });
  }

  static findById(id) {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM media_folders WHERE id = ?', [id], (err, row) => {
        if (err) {
          console.error('Error finding media folder:', err.message);
          return reject(err);
        }
        resolve(row);
      });
    });
  }
}

module.exports = MediaFolder;
