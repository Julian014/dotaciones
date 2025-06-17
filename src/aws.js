require('dotenv').config();
const AWS = require('aws-sdk');

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION
});

const s3 = new AWS.S3();

// Verificación: listar los buckets
s3.listBuckets((err, data) => {
  if (err) {
    console.error('❌ Error al conectar con AWS S3:', err.message);
  } else {
    console.log('✅ Conexión con S3 exitosa. Buckets disponibles:');
    console.log(data.Buckets.map(bucket => bucket.Name));
  }
});

module.exports = s3;
