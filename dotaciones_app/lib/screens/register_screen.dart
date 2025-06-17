import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:aplicacion_conductores/screens/login_screen.dart';

class Edificio {
  final int id;
  final String nombre;

  Edificio({required this.id, required this.nombre});

  factory Edificio.fromJson(Map<String, dynamic> json) {
    return Edificio(
      id: json['id'],
      nombre: json['nombre'],
    );
  }
}

class Apartamento {
  final int id;
  final String numero;

  Apartamento({required this.id, required this.numero});

  factory Apartamento.fromJson(Map<String, dynamic> json) {
    return Apartamento(
      id: json['id'],
      numero: json['numero'],
    );
  }
}

class RegisterScreen extends StatefulWidget {
  @override
  _RegisterScreenState createState() => _RegisterScreenState();
}

class _RegisterScreenState extends State<RegisterScreen> {
  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _birthDateController = TextEditingController();
  final TextEditingController _buildingController = TextEditingController();
  final TextEditingController _apartmentController = TextEditingController();

  DateTime? selectedDate;

  List<Edificio> _edificios = [];
  Edificio? _edificioSeleccionado;

  List<Apartamento> _apartamentos = [];
  Apartamento? _apartamentoSeleccionado;

  @override
  void initState() {
    super.initState();
    _fetchEdificios();
  }

  Future<void> _fetchEdificios() async {
    final url = Uri.parse('https://sistemacerceta.com/api/edificios_app');
    try {
      final response = await http.get(url);
      if (response.statusCode == 200) {
        final List<dynamic> data = json.decode(response.body);
        setState(() {
          _edificios = data.map((json) => Edificio.fromJson(json)).toList();
        });
      } else {
        print("❌ Error al cargar edificios");
      }
    } catch (e) {
      print("❌ Excepción al cargar edificios: $e");
    }
  }

  Future<void> _fetchApartamentos(int edificioId) async {
    final url = Uri.parse(
        'https://sistemacerceta.com/api/apartamentos_app?edificio_id=$edificioId');
    try {
      final response = await http.get(url);
      if (response.statusCode == 200) {
        final List<dynamic> data = json.decode(response.body);
        setState(() {
          _apartamentos =
              data.map((json) => Apartamento.fromJson(json)).toList();
          _apartamentoSeleccionado = null;
        });
      } else {
        print("❌ Error al cargar apartamentos");
      }
    } catch (e) {
      print("❌ Excepción al cargar apartamentos: $e");
    }
  }

  Future<void> _selectDate(BuildContext context) async {
    final DateTime? picked = await showDatePicker(
      context: context,
      initialDate: DateTime(2000),
      firstDate: DateTime(1900),
      lastDate: DateTime.now(),
    );
    if (picked != null) {
      setState(() {
        selectedDate = picked;
        _birthDateController.text = "${picked.toLocal()}".split(' ')[0];
      });
    }
  }

  Future<void> _register() async {
    print("📩 Registrando usuario...");
    final url = Uri.parse('https://sistemacerceta.com/api/register');
    final response = await http.post(
      url,
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({
        "nombre": _nameController.text,
        "email": _emailController.text,
        "password": _passwordController.text,
        "role": "residentes",
        "cargo": null,
        "fecha_cumpleaños": _birthDateController.text,
        "edificio": _buildingController.text,
        "apartamento": _apartmentController.text,
      }),
    );

    if (response.statusCode == 201) {
      print("✅ Usuario registrado correctamente");
      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (context) {
          return AlertDialog(
            title: Text("Registro exitoso"),
            content: Text(
              "Su usuario se ha registrado con éxito. Ahora debe esperar a que el equipo de revisión verifique que usted es residente de este apartamento. En breve, su cuenta quedará activa y recibirá un correo electrónico confirmando la activación, lo que le permitirá ingresar.",
            ),
            actions: [
              TextButton(
                onPressed: () {
                  Navigator.of(context).pop();
                  Navigator.pushReplacement(
                    context,
                    MaterialPageRoute(
                      builder: (context) => LoginScreen(),
                    ),
                  );
                },
                child: Text("Aceptar"),
              )
            ],
          );
        },
      );
    } else {
      print("❌ Error al registrar usuario: ${response.statusCode}");
      print("Respuesta: ${response.body}");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
appBar: AppBar(
  backgroundColor: Colors.transparent,
  elevation: 0,
  automaticallyImplyLeading: false,
  leading: IconButton(
    icon: Icon(Icons.arrow_back, color: Colors.black), // CAMBIADO A NEGRO
    onPressed: () => Navigator.pop(context),
  ),
),

      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: [Colors.indigo.shade400, Colors.blue.shade200],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: Center(
          child: SingleChildScrollView(
            padding: EdgeInsets.all(20),
            child: Card(
              elevation: 10,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(20),
              ),
              margin: EdgeInsets.symmetric(horizontal: 10),
              child: Padding(
                padding: const EdgeInsets.all(25.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      "Crear cuenta",
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 26,
                        fontWeight: FontWeight.bold,
                        color: Colors.indigo.shade800,
                      ),
                    ),
                    SizedBox(height: 25),
                    _buildInput(_nameController, 'Nombre completo', Icons.person),
                    SizedBox(height: 15),
                    _buildInput(_emailController, 'Correo electrónico', Icons.email),
                    SizedBox(height: 15),
                    _buildInput(_passwordController, 'Contraseña', Icons.lock, obscure: true),
                    SizedBox(height: 15),
                    GestureDetector(
                      onTap: () => _selectDate(context),
                      child: AbsorbPointer(
                        child: _buildInput(_birthDateController, 'Fecha de nacimiento', Icons.calendar_today),
                      ),
                    ),
                    SizedBox(height: 15),
                    DropdownButtonFormField<Edificio>(
                      value: _edificioSeleccionado,
                      items: _edificios.map((edificio) {
                        return DropdownMenuItem(
                          value: edificio,
                          child: Text(edificio.nombre),
                        );
                      }).toList(),
                      onChanged: (value) {
                        setState(() {
                          _edificioSeleccionado = value;
                          _buildingController.text = value?.id.toString() ?? '';
                        });
                        if (value != null) {
                          _fetchApartamentos(value.id);
                        }
                      },
                      decoration: InputDecoration(
                        prefixIcon: Icon(Icons.location_city),
                        labelText: 'Edificio',
                        border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(12)),
                      ),
                    ),
                    SizedBox(height: 15),
                    DropdownButtonFormField<Apartamento>(
                      value: _apartamentoSeleccionado,
                      items: _apartamentos.map((apt) {
                        return DropdownMenuItem(
                          value: apt,
                          child: Text(apt.numero),
                        );
                      }).toList(),
                      onChanged: (value) {
                        setState(() {
                          _apartamentoSeleccionado = value;
                          _apartmentController.text = value?.id.toString() ?? '';
                        });
                      },
                      decoration: InputDecoration(
                        prefixIcon: Icon(Icons.apartment),
                        labelText: 'Apartamento',
                        border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(12)),
                      ),
                    ),
                    SizedBox(height: 30),
                    ElevatedButton(
                      onPressed: _register,
                      style: ElevatedButton.styleFrom(
                        padding: EdgeInsets.symmetric(vertical: 15),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12)),
                        backgroundColor: Colors.indigo.shade600,
                        textStyle: TextStyle(fontSize: 18),
                      ),
                      child: Text("Crear cuenta"),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  // ✅ Aquí está el método correctamente ubicado
  Widget _buildInput(TextEditingController controller, String label,
      IconData icon,
      {bool obscure = false}) {
    return TextField(
      controller: controller,
      obscureText: obscure,
      decoration: InputDecoration(
        prefixIcon: Icon(icon),
        labelText: label,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
        ),
      ),
    );
  }
}
