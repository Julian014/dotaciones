const mysql = require('mysql2');

// Crear la conexión a la base de datos
const pool = mysql.createPool({
    host: '31.97.134.190',
    user: 'root',
    password: 'fPnlBb8jZA586oWWa6i8S2hRuSgN5bN6mY8ELfniRmzwn0c9ZCHKVEF5N69I4sXT',
    database: 'dotaciones',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    timezone: '-05:00', // ✅ Correcto para hora de Colombia

}).promise();  // Esto convierte el pool en una versión que utiliza promesas

// Exportar la conexión para usarla en otros módulos
module.exports = pool;
