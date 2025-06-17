import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'login_screen.dart';
import 'package:url_launcher/url_launcher.dart';

import 'dart:convert';
import 'package:http/http.dart' as http;
import 'home_screen.dart'; // o como se llame tu archivo
import 'dart:typed_data';
import 'dart:io';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';

Image _getImageFromBase64(String base64String) {
  Uint8List bytes = base64Decode(base64String);
  return Image.memory(bytes);
}

Future<void> _downloadFileFromBase64(String base64String, String fileName) async {
  // Verifica los permisos para escribir en almacenamiento
  await Permission.storage.request();

  if (await Permission.storage.isGranted) {
    final bytes = base64Decode(base64String);
    final directory = await getExternalStorageDirectory();
    final file = File('${directory!.path}/$fileName');
    await file.writeAsBytes(bytes);

    // Abre el archivo (usando el paquete url_launcher o cualquier otro paquete adecuado)
    launchUrl(Uri.file(file.path), mode: LaunchMode.externalApplication);
  }
}

Future<List<BlogEntry>> fetchBlogEntries(String userId) async {
  print('📨 Solicitando entradas de blog para userId: $userId');

  final response = await http.get(Uri.parse('http://localhost:3000/api/blog?userId=$userId'));

  if (response.statusCode == 200) {
    final List<dynamic> data = jsonDecode(response.body);
    return data.map((json) => BlogEntry.fromJson(json)).toList();
  } else {
    throw Exception('Error al cargar entradas del blog');
  }
}

class BlogScreen extends StatefulWidget {
  final String userId;

  BlogScreen({Key? key, required this.userId}) : super(key: key);

  @override
  _BlogScreenState createState() => _BlogScreenState();
}

class _BlogScreenState extends State<BlogScreen> {
  late Future<List<BlogEntry>> _futureBlogEntries;

  @override
  void initState() {
    super.initState();
    _futureBlogEntries = fetchBlogEntries(widget.userId);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Blog'),
        backgroundColor: Colors.deepPurple,
      ),
      body: FutureBuilder<List<BlogEntry>>(
        future: _futureBlogEntries,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          } else if (snapshot.hasError) {
            return Center(child: Text('Error: ${snapshot.error}'));
          } else if (!snapshot.hasData || snapshot.data!.isEmpty) {
            return const Center(child: Text('No hay publicaciones disponibles.'));
          }

          final entries = snapshot.data!;
          return ListView.builder(
            itemCount: entries.length,
            itemBuilder: (context, index) {
              final entry = entries[index];

              return Card(
                margin: const EdgeInsets.all(10),
                child: Padding(
                  padding: const EdgeInsets.all(12.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(entry.titulo, style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                      Text(entry.fecha, style: TextStyle(color: Colors.grey)),
                      const SizedBox(height: 10),
                      Text(entry.descripcion),
                      if (entry.imagenBase64 != null)
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 10),
                          child: _getImageFromBase64(entry.imagenBase64!),
                        ),
                      if (entry.pdfBase64 != null)
                        ElevatedButton.icon(
                          onPressed: () => _downloadFileFromBase64(entry.pdfBase64!, 'documento.pdf'),
                          icon: Icon(Icons.picture_as_pdf),
                          label: Text('Descargar PDF'),
                        ),
                      if (entry.wordBase64 != null)
                        ElevatedButton.icon(
                          onPressed: () => _downloadFileFromBase64(entry.wordBase64!, 'documento.docx'),
                          icon: Icon(Icons.description),
                          label: Text('Descargar Word'),
                        ),
                      if (entry.excelBase64 != null)
                        ElevatedButton.icon(
                          onPressed: () => _downloadFileFromBase64(entry.excelBase64!, 'documento.xlsx'),
                          icon: Icon(Icons.grid_on),
                          label: Text('Descargar Excel'),
                        ),
                    ],
                  ),
                ),
              );
            },
          );
        },
      ),
      bottomNavigationBar: _buildBottomNavigationBar(context),
    );
  }

  Widget _buildBottomNavigationBar(BuildContext context) {
    return BottomNavigationBar(
      items: const [
        BottomNavigationBarItem(
          icon: Icon(Icons.home),
          label: 'Inicio',
        ),
        BottomNavigationBarItem(
          icon: Icon(Icons.article),
          label: 'Blog',
        ),
      ],
      currentIndex: 1,
      onTap: (index) {
        if (index == 0) {
          Navigator.pushReplacement(
            context,
            MaterialPageRoute(builder: (context) => HomeScreen(userId: widget.userId)),
          );
        }
      },
    );
  }
}

class BlogEntry {
  final String titulo;
  final String descripcion;
  final String fecha;
  final String? imagenBase64;  // Imagen en base64
  final String? pdfBase64;     // PDF en base64
  final String? wordBase64;    // Word en base64
  final String? excelBase64;   // Excel en base64

  BlogEntry({
    required this.titulo,
    required this.descripcion,
    required this.fecha,
    this.imagenBase64,
    this.pdfBase64,
    this.wordBase64,
    this.excelBase64,
  });

  factory BlogEntry.fromJson(Map<String, dynamic> json) {
    return BlogEntry(
      titulo: json['titulo'] ?? '',
      descripcion: json['descripcion'] ?? '',
      fecha: json['fecha'] ?? '',
      imagenBase64: json['imagen'],  // Recibir base64
      pdfBase64: json['pdf'],        // Recibir base64
      wordBase64: json['word'],      // Recibir base64
      excelBase64: json['excel'],    // Recibir base64
    );
  }
}
