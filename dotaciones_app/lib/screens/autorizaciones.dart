import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:http/http.dart' as http;

class AutorizacionesScreen extends StatefulWidget {
  final String userId;

  const AutorizacionesScreen({
    Key? key,
    required this.userId,
  }) : super(key: key);

  @override
  State<AutorizacionesScreen> createState() => _AutorizacionesScreenState();
}

class _AutorizacionesScreenState extends State<AutorizacionesScreen> {
  final _formKey = GlobalKey<FormState>();

  final TextEditingController nombreResidenteController = TextEditingController();
  final TextEditingController nombreVisitanteController = TextEditingController();
  final TextEditingController tipoIdentificacionController = TextEditingController();
  final TextEditingController documentoController = TextEditingController();
  final TextEditingController relacionController = TextEditingController();
  final TextEditingController observacionesController = TextEditingController();
  final TextEditingController edificioController = TextEditingController();
  final TextEditingController apartamentoController = TextEditingController();

  DateTime? fechaDesde;
  DateTime? fechaHasta;
  TimeOfDay? horaSeleccionada;
  bool _enviando = false;

  String userName = '';

  @override
  void initState() {
    super.initState();
    fetchUserInfo();
  }

  Future<void> fetchUserInfo() async {
    try {
      final url = 'https://sistemacerceta.com/user_infoo/${widget.userId}';
      print('🔍 Solicitando info de usuario desde: $url');

      final response = await http.get(Uri.parse(url));

      print('📦 Código de respuesta: ${response.statusCode}');
      print('📦 Cuerpo de la respuesta: ${response.body}');

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        print('✅ Datos decodificados: $data');

        setState(() {
          userName = data['nombre'] ?? 'Usuario';
          nombreResidenteController.text = userName;
          edificioController.text = data['edificio_nombre'] ?? '';
          apartamentoController.text = data['apartamento'] ?? '';
        });
      } else {
        print('⚠️ Error al obtener datos del usuario: ${response.reasonPhrase}');
        setState(() {
          userName = 'Usuario';
          nombreResidenteController.text = userName;
        });
      }
    } catch (e) {
      print('❌ Excepción al obtener datos del usuario: $e');
      setState(() {
        userName = 'Usuario';
        nombreResidenteController.text = userName;
      });
    }
  }
Future<void> _enviarAutorizacion() async {
  // Validación de campos obligatorios
  if (!_formKey.currentState!.validate() ||
      fechaDesde == null ||
      fechaHasta == null ||
      horaSeleccionada == null ||
      tipoIdentificacionController.text.isEmpty) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('Por favor completa todos los campos'),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
        backgroundColor: Colors.red[400],
      ),
    );
    return;
  }

  // Validación de rango de fechas
  if (fechaHasta!.isBefore(fechaDesde!)) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('La fecha final no puede ser anterior a la fecha de inicio'),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
        backgroundColor: Colors.red[400],
      ),
    );
    return;
  }

  // Formateo de fechas y hora
  final fechaInicio = DateFormat('yyyy-MM-dd').format(fechaDesde!);
  final fechaFin = DateFormat('yyyy-MM-dd').format(fechaHasta!);
  final hora = horaSeleccionada!.format(context);

  setState(() => _enviando = true);

  // Envío de datos
  final response = await http.post(
    Uri.parse('https://sistemacerceta.com/autorizar_ingreso'),
    body: {
      'userId': widget.userId,
      'residente': nombreResidenteController.text,
      'edificio': edificioController.text,
      'apartamento': apartamentoController.text,
      'nombre_visitante': nombreVisitanteController.text,
      'tipo_documento': tipoIdentificacionController.text,
      'documento': documentoController.text,
      'fecha_desde': fechaInicio,
      'fecha_hasta': fechaFin,
      'hora': hora,
      'relacion': relacionController.text,
      'observaciones': observacionesController.text,
    },
  );

  setState(() => _enviando = false);

  // Respuesta del servidor
  if (response.statusCode == 200) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('Autorización enviada con éxito'),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
        backgroundColor: Colors.green[400],
      ),
    );

    _formKey.currentState!.reset();
    nombreVisitanteController.clear();
    tipoIdentificacionController.clear();
    documentoController.clear();
    relacionController.clear();
    observacionesController.clear();

    setState(() {
      fechaDesde = null;
      fechaHasta = null;
      horaSeleccionada = null;
      nombreResidenteController.text = userName;
      fetchUserInfo();
    });
  } else {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('Error al enviar la autorización'),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
        backgroundColor: Colors.red[400],
      ),
    );
  }
}


  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[50],
      appBar: AppBar(
        title: const Text('Autorizar Ingreso de Visitantes'),
        centerTitle: true,
        elevation: 0,
        flexibleSpace: Container(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [Colors.blue[800]!, Colors.blue[600]!],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
          ),
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Card(
          elevation: 5,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(15),
          ),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Form(
              key: _formKey,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text(
                    'Datos del Residente',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: Colors.blue,
                    ),
                  ),
                  const SizedBox(height: 15),
                  _buildReadOnlyField(
                    controller: nombreResidenteController,
                    label: 'Nombre del residente',
                    icon: Icons.person,
                  ),
                  const SizedBox(height: 15),
                  Row(
                    children: [
                      Expanded(
                        child: _buildReadOnlyField(
                          controller: edificioController,
                          label: 'Edificio',
                          icon: Icons.apartment,
                        ),
                      ),
                      const SizedBox(width: 15),
                      Expanded(
                        child: _buildReadOnlyField(
                          controller: apartamentoController,
                          label: 'Apartamento',
                          icon: Icons.home,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 25),
                  const Text(
                    'Datos del Visitante',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: Colors.blue,
                    ),
                  ),
                  const SizedBox(height: 15),
                  _buildTextField(
                    controller: nombreVisitanteController,
                    label: 'Nombre completo del visitante',
                    icon: Icons.person_outline,
                    validator: (value) => value!.isEmpty ? 'Campo obligatorio' : null,
                  ),
                  const SizedBox(height: 15),
                  DropdownButtonFormField<String>(
                    value: tipoIdentificacionController.text.isNotEmpty ? tipoIdentificacionController.text : null,
                    decoration: InputDecoration(
                      labelText: 'Tipo de identificación',
                      prefixIcon: const Icon(Icons.credit_card),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                      filled: true,
                      fillColor: Colors.grey[100],
                    ),
                    items: ['Cédula', 'Pasaporte', 'C.E.', 'T.I.']
                        .map((tipo) => DropdownMenuItem(
                              value: tipo,
                              child: Text(tipo),
                            ))
                        .toList(),
                    onChanged: (value) {
                      setState(() => tipoIdentificacionController.text = value!);
                    },
                    validator: (value) => value == null || value.isEmpty ? 'Campo obligatorio' : null,
                  ),
                  const SizedBox(height: 15),
                  _buildTextField(
                    controller: documentoController,
                    label: 'Número de documento',
                    icon: Icons.numbers,
                    validator: (value) => value!.isEmpty ? 'Campo obligatorio' : null,
                  ),
                  const SizedBox(height: 25),
                  const Text(
                    'Detalles de la Visita',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: Colors.blue,
                    ),
                  ),
                  const SizedBox(height: 15),
                  _buildDatePickerTile(
                    context: context,
                    value: fechaDesde,
                    label: 'Fecha de inicio',
                    onTap: () async {
                      final picked = await showDatePicker(
                        context: context,
                        initialDate: DateTime.now(),
                        firstDate: DateTime.now(),
                        lastDate: DateTime.now().add(const Duration(days: 365)),
                      );
                      if (picked != null) setState(() => fechaDesde = picked);
                    },
                  ),
                  const SizedBox(height: 10),
                  _buildDatePickerTile(
                    context: context,
                    value: fechaHasta,
                    label: 'Fecha de fin',
                    onTap: () async {
                      final picked = await showDatePicker(
                        context: context,
                        initialDate: fechaDesde ?? DateTime.now(),
                        firstDate: fechaDesde ?? DateTime.now(),
                        lastDate: DateTime.now().add(const Duration(days: 365)),
                      );
                      if (picked != null) setState(() => fechaHasta = picked);
                    },
                  ),
                  const SizedBox(height: 10),
                  _buildTimePickerTile(
                    context: context,
                    value: horaSeleccionada,
                    label: 'Hora de visita',
                    onTap: () async {
                      final pickedTime = await showTimePicker(
                        context: context,
                        initialTime: TimeOfDay.now(),
                      );
                      if (pickedTime != null) {
                        setState(() => horaSeleccionada = pickedTime);
                      }
                    },
                  ),
                  const SizedBox(height: 15),
                  _buildTextField(
                    controller: relacionController,
                    label: 'Relación con el residente',
                    icon: Icons.group,
                    validator: (value) => value!.isEmpty ? 'Campo obligatorio' : null,
                  ),
                  const SizedBox(height: 15),
                  TextFormField(
                    controller: observacionesController,
                    decoration: InputDecoration(
                      labelText: 'Observaciones (opcional)',
                      prefixIcon: const Icon(Icons.note),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                      filled: true,
                      fillColor: Colors.grey[100],
                    ),
                    maxLines: 3,
                  ),
                  const SizedBox(height: 30),
                  ElevatedButton(
                    onPressed: _enviando ? null : _enviarAutorizacion,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blue[800],
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 15),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                      elevation: 5,
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.send),
                        const SizedBox(width: 10),
                        Text(
                          _enviando ? 'Enviando...' : 'Enviar Autorización',
                          style: const TextStyle(fontSize: 16),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildReadOnlyField({
    required TextEditingController controller,
    required String label,
    required IconData icon,
  }) {
    return TextFormField(
      controller: controller,
      readOnly: true,
      decoration: InputDecoration(
        labelText: label,
        prefixIcon: Icon(icon),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
        ),
        filled: true,
        fillColor: Colors.grey[200],
      ),
    );
  }

  Widget _buildTextField({
    required TextEditingController controller,
    required String label,
    required IconData icon,
    required String? Function(String?)? validator,
  }) {
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        labelText: label,
        prefixIcon: Icon(icon),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
        ),
        filled: true,
        fillColor: Colors.grey[100],
      ),
      validator: validator,
    );
  }

  Widget _buildDatePickerTile({
    required BuildContext context,
    required DateTime? value,
    required String label,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(10),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 15),
        decoration: BoxDecoration(
          border: Border.all(color: Colors.grey[300]!),
          borderRadius: BorderRadius.circular(10),
          color: Colors.grey[100],
        ),
        child: Row(
          children: [
            Icon(Icons.calendar_today, color: Colors.blue[800]),
            const SizedBox(width: 15),
            Text(
              value == null ? label : DateFormat('dd/MM/yyyy').format(value),
              style: TextStyle(
                color: value == null ? Colors.grey : Colors.black,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTimePickerTile({
    required BuildContext context,
    required TimeOfDay? value,
    required String label,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(10),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 15),
        decoration: BoxDecoration(
          border: Border.all(color: Colors.grey[300]!),
          borderRadius: BorderRadius.circular(10),
          color: Colors.grey[100],
        ),
        child: Row(
          children: [
            Icon(Icons.access_time, color: Colors.blue[800]),
            const SizedBox(width: 15),
            Text(
              value == null ? label : value.format(context),
              style: TextStyle(
                color: value == null ? Colors.grey : Colors.black,
              ),
            ),
          ],
        ),
      ),
    );
  }
}