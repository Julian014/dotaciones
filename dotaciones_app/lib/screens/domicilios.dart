import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:intl/intl.dart';
import 'dart:async';

// ---------------------- PedidosScreen -------------------------
class PedidosScreen extends StatefulWidget {
  final String userId;
  PedidosScreen({required this.userId});
  @override
  _PedidosScreenState createState() => _PedidosScreenState();
}

class _PedidosScreenState extends State<PedidosScreen> {
  List<dynamic> domicilios = [];
  DateTimeRange? selectedRange;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    fetchDomicilios();
    _timer = Timer.periodic(Duration(seconds: 5), (Timer t) => fetchDomicilios());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> fetchDomicilios() async {
    final url = Uri.parse('https://sistemacerceta.com/domicilios/${widget.userId}');
    try {
      final response = await http.get(url);
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        setState(() {
          domicilios = data;
        });
      } else {
        print("Error al obtener los domicilios: ${response.statusCode}");
      }
    } catch (e) {
      print("Excepción al obtener domicilios: $e");
    }
  }

  List<dynamic> getFilteredDomicilios(int estadoFiltro) {
    List<dynamic> filtrados = domicilios.where((domicilio) {
      return domicilio['estado'] == estadoFiltro;
    }).toList();

    if (selectedRange != null) {
      filtrados = filtrados.where((domicilio) {
        final fecha = DateTime.parse(domicilio['created_at']);
        return fecha.isAfter(selectedRange!.start) &&
            fecha.isBefore(selectedRange!.end.add(Duration(days: 1)));
      }).toList();
    }
    filtrados.sort((a, b) =>
        DateTime.parse(b['created_at']).compareTo(DateTime.parse(a['created_at'])));
    return filtrados;
  }

  Future<void> _selectDateRange() async {
    DateTimeRange? picked = await showDateRangePicker(
      context: context,
      firstDate: DateTime(2020),
      lastDate: DateTime.now().add(Duration(days: 1)),
      initialDateRange: selectedRange,
    );
    if (picked != null && picked != selectedRange) {
      setState(() {
        selectedRange = picked;
      });
    }
  }

  String formatDate(String date) {
    final parsedDate = DateTime.parse(date);
    final formatter = DateFormat('d MMMM yyyy, HH:mm');
    return formatter.format(parsedDate);
  }

  String getEstado(int estado) {
    return estado == 1 ? 'Pendiente' : 'Completado';
  }

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          title: Text("Mis Pedidos"),
          backgroundColor: Colors.lightBlueAccent,
          elevation: 0,






         bottom: TabBar(
  indicatorColor: Colors.white,
  tabs: [
    Tab(
      child: Stack(
        children: [
          Align(
            alignment: Alignment.center,
            child: Text("Pendientes"),
          ),
          if (getFilteredDomicilios(1).length > 0)
            Positioned(
              right: 0,
              top: 0,
              child: Container(
                padding: EdgeInsets.all(6),
                decoration: BoxDecoration(
                  color: Colors.red,
                  shape: BoxShape.circle,
                ),
                child: Text(
                  '${getFilteredDomicilios(1).length}',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 12,
                  ),
                ),
              ),
            ),
        ],
      ),
    ),
    Tab(text: "Completados"),
  ],
),



          actions: [
            IconButton(
              icon: Icon(Icons.filter_alt_outlined),
              onPressed: _selectDateRange,
              tooltip: "Filtrar por fecha",
            )
          ],
        ),
        body: TabBarView(
          children: [
            _buildPedidosList(getFilteredDomicilios(1)),
            _buildPedidosList(getFilteredDomicilios(2)),
          ],
        ),
      ),
    );
  }

  Widget _buildPedidosList(List<dynamic> pedidos) {
    if (pedidos.isEmpty) {
      return Center(
        child: Text(
          selectedRange == null
              ? "No hay pedidos para mostrar."
              : "No se encontraron pedidos en el rango seleccionado.",
          style: TextStyle(fontSize: 16),
        ),
      );
    }
    return ListView.builder(
      padding: EdgeInsets.only(top: 16, bottom: 16),
      itemCount: pedidos.length,
      itemBuilder: (context, index) {
        final domicilio = pedidos[index];
        final estado = domicilio['estado'];
        return TweenAnimationBuilder(
          tween: Tween<Offset>(
            begin: Offset(1.0, 0.0),
            end: Offset.zero,
          ),
          duration: Duration(milliseconds: 300),
          builder: (context, Offset offset, child) {
            return Card(
              margin: EdgeInsets.symmetric(vertical: 10, horizontal: 16),
              color: estado == 1 ? Colors.amber[100] : Colors.green[100],
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(25),
              ),
              elevation: 5,
              child: Transform.translate(
                offset: offset,
                child: ListTile(
                  contentPadding: EdgeInsets.symmetric(vertical: 16, horizontal: 20),
                  leading: Icon(Icons.delivery_dining, color: Colors.black, size: 30),
                  title: Text(
                    "Fecha: ${formatDate(domicilio['created_at'])}",
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 18,
                      color: Colors.black,
                    ),
                  ),
                  subtitle: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      SizedBox(height: 8),
                      Text(
                        "Observaciones: ${domicilio['observaciones']}",
                        style: TextStyle(
                          color: Colors.grey[800],
                          fontSize: 14,
                        ),
                      ),
                      SizedBox(height: 8),
                      Text(
                        "Estado: ${getEstado(estado)}",
                        style: TextStyle(
                          color: estado == 1 ? Colors.black : Colors.white,
                          fontWeight: FontWeight.w500,
                          fontSize: 16,
                        ),
                      ),
                    ],
                  ),
                  onTap: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (context) => DetalleDomicilioScreen(domicilio: domicilio, onDomicilioUpdated: fetchDomicilios),
                      ),
                    );
                  },
                ),
              ),
            );
          },
        );
      },
    );
  }
}

// ---------------------- DetalleDomicilioScreen -------------------------
class DetalleDomicilioScreen extends StatelessWidget {
  final Map<String, dynamic> domicilio;
  final Future<void> Function() onDomicilioUpdated;

  DetalleDomicilioScreen({required this.domicilio, required this.onDomicilioUpdated});

  String formatDate(String date) {
    final parsedDate = DateTime.parse(date);
    final formatter = DateFormat('d MMMM yyyy, HH:mm');
    return formatter.format(parsedDate);
  }

  @override
  Widget build(BuildContext context) {
    final estado = domicilio['estado'];
    final fotoBase64 = domicilio['foto'];

    return Scaffold(
      appBar: AppBar(
        title: Text('Detalles del Domicilio'),
        backgroundColor: Colors.lightBlueAccent,
        elevation: 0,
      ),
      body: SingleChildScrollView(
        padding: EdgeInsets.all(20),
        child: Card(
          color: Colors.white,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(25)),
          elevation: 8,
          child: Padding(
            padding: EdgeInsets.all(24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (fotoBase64 != null && fotoBase64.isNotEmpty)
                  GestureDetector(
                    onTap: () {
                      Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (context) => FullScreenImageScreen(fotoBase64: fotoBase64),
                        ),
                      );
                    },
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(15),
                      child: Image.memory(
                        Base64Decoder().convert(fotoBase64),
                        height: 200,
                        width: double.infinity,
                        fit: BoxFit.cover,
                      ),
                    ),
                  ),
                SizedBox(height: 20),
                Text(
                  'Detalles del Domicilio',
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                    color: Colors.black,
                  ),
                ),
                SizedBox(height: 20),
                Text(
                  'Fecha de Creación:',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.w500,
                    color: Colors.grey[800],
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  formatDate(domicilio['created_at']),
                  style: TextStyle(fontSize: 18, color: Colors.black),
                ),
                SizedBox(height: 20),
                Text(
                  'Observaciones:',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.w500,
                    color: Colors.grey[800],
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  domicilio['observaciones'] ?? 'No hay observaciones.',
                  style: TextStyle(fontSize: 16, color: Colors.black),
                ),
                SizedBox(height: 20),
                Text(
                  'Estado:',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.w500,
                    color: Colors.grey[800],
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  domicilio['estado'] == 1 ? 'Pendiente' : 'Completado',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: domicilio['estado'] == 1 ? Colors.orange : Colors.green,
                  ),
                ),
                SizedBox(height: 30),


         Column(
  children: [
    if (domicilio['estado'] == 1)
      ElevatedButton(
        onPressed: () {
          _recibirDomicilio(context, domicilio, onDomicilioUpdated);
        },
        child: Text('Recibir Domicilio'),
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.green,
          foregroundColor: Colors.white,
          padding: EdgeInsets.symmetric(vertical: 15, horizontal: 50),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(30)),
        ),
      ),
    SizedBox(height: 15),
    ElevatedButton(
      onPressed: () {
        // Aquí implementa la acción para reportar novedades
      },
      child: Text('Reportar Novedad'),
      style: ElevatedButton.styleFrom(
        backgroundColor: Colors.red,
        foregroundColor: Colors.white,
        padding: EdgeInsets.symmetric(vertical: 15, horizontal: 50),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(30)),
      ),
    ),
  ],
)





              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ---------------------- FullScreenImageScreen -------------------------
class FullScreenImageScreen extends StatelessWidget {
  final String fotoBase64;
  FullScreenImageScreen({required this.fotoBase64});
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        actions: [
          IconButton(
            icon: Icon(Icons.close, color: Colors.white),
            onPressed: () {
              Navigator.pop(context);
            },
          ),
        ],
      ),
      body: Center(
        child: GestureDetector(
          onTap: () {
            Navigator.pop(context);
          },
          child: Image.memory(
            Base64Decoder().convert(fotoBase64),
            fit: BoxFit.contain,
          ),
        ),
      ),
    );
  }
}

// ---------------------- Función para actualizar el pedido -------------------------
Future<void> _recibirDomicilio(BuildContext context, Map<String, dynamic> domicilio, Future<void> Function() onDomicilioUpdated) async {
  final id = domicilio['id'];
  if (id == null) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text('ID inválido.')));
    print("Error: ID inválido");
    return;
  }
  final url = Uri.parse('https://sistemacerceta.com/domicilio/$id');
  final data = {'estado': 2};
  try {
    final response = await http.put(
      url,
      headers: {'Content-Type': 'application/json'},
      body: json.encode(data),
    );
    if (response.statusCode == 200) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Domicilio recibido con éxito.')));
      print("Domicilio actualizado exitosamente.");
      await onDomicilioUpdated();
      Navigator.pop(context); // Navegar de regreso a la lista de domicilios
    } else {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Error al recibir el domicilio.')));
      print("Error al actualizar domicilio: ${response.statusCode}");
    }
  } catch (e) {
    print("Error al realizar la solicitud: $e");
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text('Hubo un error al realizar la solicitud.')));
  }
}