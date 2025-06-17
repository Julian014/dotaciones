import 'dart:io';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as path;
import 'package:intl/intl.dart';

class NuevoPagoScreen extends StatefulWidget {
  final String userId;
  const NuevoPagoScreen({Key? key, required this.userId}) : super(key: key);

  @override
  _NuevoPagoScreenState createState() => _NuevoPagoScreenState();
}

class _NuevoPagoScreenState extends State<NuevoPagoScreen> {
  // ========== MANTENGO TODOS LOS MISMOS CONTROLADORES Y VARIABLES ==========
  final _formKey = GlobalKey<FormState>();
  DateTime? _fechaPago;
  final TextEditingController _valorPagoController = TextEditingController();
  final TextEditingController _nombreEdificioController = TextEditingController();
  final TextEditingController _numeroApartamentoController = TextEditingController();
  String _estado = 'Pagado';
  File? _documentoPago;
  final picker = ImagePicker();
  int? _apartamentoId;
  int? _edificioId;
  bool _isLoading = false;

  // ========== SOLO CAMBIO LOS ESTILOS ==========
  final Color _primaryColor = Color(0xFF1E99D3); // Mantengo tu color principal
  final Color _accentColor = Color(0xFF4CAF50);
  final Color _cardColor = Colors.white;
  final Color _textColor = Color(0xFF333333);
  final Color _hintColor = Color(0xFF9E9E9E);

  @override
  void initState() {
    super.initState();
    _fechaPago = DateTime.now();
    cargarInfoUsuario(); // MISMA FUNCIONALIDAD
  }

  // ========== MANTENGO EXACTAMENTE LOS MISMOS MÉTODOS DE FUNCIONALIDAD ==========
  Future<void> _pickFile() async {
    final pickedFile = await picker.pickImage(source: ImageSource.gallery);
    if (pickedFile != null) {
      setState(() {
        _documentoPago = File(pickedFile.path);
      });
    }
  }

  Future<void> cargarInfoUsuario() async {
    print("Llamando a /info_ususuario/${widget.userId}");

    try {
      final userResponse = await http.get(Uri.parse('https://sistemacerceta.com/info_ususuario/${widget.userId}'));

      if (userResponse.statusCode == 200) {
        final userData = jsonDecode(userResponse.body);
        final edificioId = int.tryParse(userData['edificio'].toString());
        final apartamentoId = int.tryParse(userData['apartamento'].toString());

        final edificioResponse = await http.get(Uri.parse('https://sistemacerceta.com/edificios/$edificioId'));
        final apartamentoResponse = await http.get(Uri.parse('https://sistemacerceta.com/apartamentos/$apartamentoId'));

        if (edificioResponse.statusCode == 200 && apartamentoResponse.statusCode == 200) {
          final nombreEdificio = jsonDecode(edificioResponse.body)['nombre'];
          final numeroApartamento = jsonDecode(apartamentoResponse.body)['numero'];

          setState(() {
            _edificioId = edificioId;
            _apartamentoId = apartamentoId;
            _nombreEdificioController.text = nombreEdificio ?? '';
            _numeroApartamentoController.text = numeroApartamento.toString();
          });
        }
      }
    } catch (e) {
      print('Error en cargarInfoUsuario: $e');
    }
  }

  Future<void> _submitPago() async {
    if (_apartamentoId == null || _edificioId == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('No se ha cargado la información del apartamento o edificio')),
      );
      return;
    }

    setState(() => _isLoading = true);

    try {
      var uri = Uri.parse("https://sistemacerceta.com/api/pagos");
      var request = http.MultipartRequest('POST', uri);
      request.fields['apartamento_id'] = (_apartamentoId ?? 0).toString();
      request.fields['fecha_pago'] = _fechaPago!.toIso8601String();
      request.fields['valor_pago'] = _valorPagoController.text;
      request.fields['estado'] = _estado;
      request.fields['edificio_id'] = (_edificioId ?? 0).toString();

      if (_documentoPago != null) {
        var stream = http.ByteStream(_documentoPago!.openRead());
        var length = await _documentoPago!.length();
        var multipartFile = http.MultipartFile('documento_pago', stream, length,
            filename: path.basename(_documentoPago!.path));
        request.files.add(multipartFile);
      }

      var response = await request.send();
      final responseBody = await http.Response.fromStream(response);

      if (response.statusCode == 200) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Pago registrado exitosamente')),
        );
        Navigator.pop(context);
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error al registrar el pago')),
        );
      }
    } finally {
      setState(() => _isLoading = false);
    }
  }

  // ========== DISEÑO MEJORADO PERO CON LA MISMA FUNCIONALIDAD ==========
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[50],
      appBar: AppBar(
        title: Text("Nuevo Pago", 
            style: TextStyle(color: Colors.white, fontWeight: FontWeight.w600)),
        backgroundColor: _primaryColor,
        elevation: 0,
        iconTheme: IconThemeData(color: Colors.white),
      ),
      body: _isLoading
          ? Center(child: CircularProgressIndicator(color: _primaryColor))
          : SingleChildScrollView(
              padding: EdgeInsets.all(20),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // ID de Usuario
                    Container(
                      padding: EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: _primaryColor.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        'ID de usuario: ${widget.userId}',
                        style: TextStyle(color: _primaryColor),
                      ),
                    ),
                    SizedBox(height: 20),
                    
                    // Fecha de Pago
                    Text("Fecha de Pago", style: TextStyle(fontWeight: FontWeight.bold)),
                    SizedBox(height: 8),
                    InkWell(
                      onTap: () async {
                        DateTime? pickedDate = await showDatePicker(
                          context: context,
                          initialDate: _fechaPago ?? DateTime.now(),
                          firstDate: DateTime(2020),
                          lastDate: DateTime(2100),
                          builder: (context, child) {
                            return Theme(
                              data: Theme.of(context).copyWith(
                                colorScheme: ColorScheme.light(
                                  primary: _primaryColor,
                                ),
                              ),
                              child: child!,
                            );
                          },
                        );
                        if (pickedDate != null) {
                          setState(() {
                            _fechaPago = pickedDate;
                          });
                        }
                      },
                      child: Container(
                        padding: EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                        decoration: BoxDecoration(
                          color: _cardColor,
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: Colors.grey[300]!),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text(
                              _fechaPago == null
                                  ? "Seleccionar fecha"
                                  : DateFormat('dd/MM/yyyy').format(_fechaPago!),
                              style: TextStyle(color: _textColor),
                            ),
                            Icon(Icons.calendar_today, size: 20, color: _primaryColor),
                          ],
                        ),
                      ),
                    ),
                    SizedBox(height: 20),
                    
                    // Valor del Pago
                    TextFormField(
                      controller: _valorPagoController,
                      keyboardType: TextInputType.number,
                      decoration: InputDecoration(
                        labelText: "Valor del Pago",
                        labelStyle: TextStyle(color: _primaryColor),
                        prefixIcon: Icon(Icons.attach_money, color: _primaryColor),
                        border: OutlineInputBorder(),
                        focusedBorder: OutlineInputBorder(
                          borderSide: BorderSide(color: _primaryColor),
                        ),
                      ),
                      validator: (value) => value == null || value.isEmpty ? "Este campo es obligatorio" : null,
                    ),
                    SizedBox(height: 20),
                    
                    // Nombre del Edificio
                    TextFormField(
                      controller: _nombreEdificioController,
                      readOnly: true,
                      decoration: InputDecoration(
                        labelText: "Nombre del Edificio",
                        labelStyle: TextStyle(color: _primaryColor),
                        prefixIcon: Icon(Icons.apartment, color: _primaryColor),
                        border: OutlineInputBorder(),
                      ),
                    ),
                    SizedBox(height: 20),
                    
                    // Número de Apartamento
                    TextFormField(
                      controller: _numeroApartamentoController,
                      readOnly: true,
                      keyboardType: TextInputType.number,
                      decoration: InputDecoration(
                        labelText: "Número de Apartamento",
                        labelStyle: TextStyle(color: _primaryColor),
                        prefixIcon: Icon(Icons.home, color: _primaryColor),
                        border: OutlineInputBorder(),
                      ),
                    ),
                    SizedBox(height: 20),
                    
                    // Documento de Pago
                    Text("Documento de Pago", style: TextStyle(fontWeight: FontWeight.bold)),
                    SizedBox(height: 8),
                    Container(
                      padding: EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                      decoration: BoxDecoration(
                        color: _cardColor,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.grey[300]!),
                      ),
                      child: Column(
                        children: [
                          Row(
                            children: [
                              Icon(Icons.insert_drive_file, color: _primaryColor),
                              SizedBox(width: 10),
                              Expanded(
                                child: Text(
                                  _documentoPago == null
                                      ? "Ningún archivo seleccionado"
                                      : path.basename(_documentoPago!.path),
                                  style: TextStyle(color: _textColor),
                                ),
                              ),
                            ],
                          ),
                          SizedBox(height: 10),
                          ElevatedButton.icon(
                            onPressed: _pickFile,
                            icon: Icon(Icons.upload_file),
                            label: Text("Seleccionar Archivo"),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: _primaryColor,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(8)),
                            ),
                          ),
                        ],
                      ),
                    ),
                    SizedBox(height: 30),
                    
                    // Botón de Registrar
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton(
                        onPressed: _submitPago,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: _primaryColor,
                          padding: EdgeInsets.symmetric(vertical: 16),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(8)),
                        ),
                        child: Text(
                          "REGISTRAR PAGO",
                          style: TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 16,
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
    );
  }
}