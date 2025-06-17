// Importar cualquier módulo que necesites
const { validationResult } = require('express-validator');

// Definir la función para manejar el webhook
function handleWebhook(req, res) {
  // Validar la solicitud del webhook (si es necesario)
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  // Procesar la solicitud del webhook
  const webhookData = req.body;
  // Aquí puedes escribir la lógica para manejar los datos del webhook
  console.log('Solicitud de webhook recibida:', webhookData);

  // Enviar una respuesta al servicio que envió el webhook
  res.status(200).send('Webhook recibido correctamente');
}

// Exportar la función de manejo de webhook para que esté disponible en otros archivos
module.exports = {
  handleWebhook
};
